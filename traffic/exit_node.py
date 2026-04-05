"""
SecureCrypt Exit Node — the remote endpoint that actually
connects to the internet on behalf of the proxied browser.

Runs on port 9090 (or configured port).
Accepts ONE tunnel connection from the local proxy,
performs ECDH handshake, then enters a command loop:

  1. Receives encrypted "proxy commands" (CONNECT, HTTP)
  2. Opens real TCP connections to destination websites
  3. Relays data bidirectionally: tunnel ↔ destination
  4. All tunnel traffic is AES-256-GCM encrypted

Run standalone:
    python run_exit_node.py
"""

import socket
import select
import json
import struct
import threading
import time
import logging
import os

from config.settings         import Settings
from traffic.handshake       import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from core.crypto_engine      import CipherFactory
from utils.framing           import Framing, MessageType
from utils.random_gen        import SecureRandom

logger = logging.getLogger("SecureCrypt.ExitNode")


# ── Internal protocol between proxy and exit node ────────────────
# All commands are JSON encoded, encrypted with session cipher,
# sent as MessageType.DATA frames.
#
# Command format:
#   {"cmd": "connect", "host": "...", "port": 443, "req_id": "..."}
#   {"cmd": "connect_ok", "req_id": "..."}
#   {"cmd": "connect_fail", "req_id": "...", "error": "..."}
#   {"cmd": "data", "req_id": "...", "payload": "<base64>"}
#   {"cmd": "http", "req_id": "...", "host": "...", "port": 80,
#    "request": "<base64 of raw HTTP request>"}
#   {"cmd": "close", "req_id": "..."}
#   {"cmd": "eof", "req_id": "..."}


class ExitNode:
    """
    Encrypted exit node — accepts tunnel peers and proxies
    their traffic to the real internet.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9090,
        server_id: str = "securecrypt-exit",
        allowed_ciphers: list[str] | None = None,
    ):
        self.host      = host
        self.port      = port
        self.server_id = server_id
        self.allowed_ciphers = (
            allowed_ciphers or CipherFactory.list_ciphers()
        )

        self._server_sock: socket.socket | None = None
        self._running    = False
        self._sessions: dict[str, Session] = {}
        # req_id → destination socket
        self._dest_socks: dict[str, socket.socket] = {}
        self._lock       = threading.Lock()

    def start(self):
        self._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(20)
        self._running = True

        threading.Thread(
            target=self._accept_loop, daemon=True,
            name="ExitAccept",
        ).start()

        logger.info(
            "Exit node on %s:%d — ciphers: %s",
            self.host, self.port,
            ", ".join(self.allowed_ciphers[:3]) + "…",
        )

    def stop(self):
        self._running = False
        with self._lock:
            for s in self._dest_socks.values():
                try:
                    s.close()
                except OSError:
                    pass
            self._dest_socks.clear()
            for s in self._sessions.values():
                s.close()
            self._sessions.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        logger.info("Exit node stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── accept loop ──────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            logger.info("Tunnel peer from %s:%d", *addr)
            threading.Thread(
                target=self._handle_peer,
                args=(sock, addr),
                daemon=True,
                name=f"Exit-{addr[0]}:{addr[1]}",
            ).start()

    # ── per-peer handler ─────────────────────────────────────────

    def _handle_peer(self, sock: socket.socket, addr: tuple):
        session: Session | None = None
        try:
            # Handshake
            hs = HandshakeProtocol()
            session_key, cipher = hs.server_hello(
                sock,
                server_id=self.server_id,
                allowed_ciphers=self.allowed_ciphers,
            )

            sid = SecureRandom.generate_session_id()
            session = Session(
                session_id=sid,
                session_key=session_key,
                cipher=cipher,
                sock=sock,
                peer_addr=addr,
            )
            with self._lock:
                self._sessions[sid] = session

            logger.info(
                "Exit session %s cipher=%s peer=%s:%d",
                sid[:12], cipher, *addr,
            )

            # Command loop
            self._command_loop(session)

        except Exception as exc:
            logger.error("Peer %s:%d error: %s", *addr, exc)
        finally:
            if session:
                session.close()
                with self._lock:
                    self._sessions.pop(session.session_id, None)

    # ── command loop ─────────────────────────────────────────────

    def _command_loop(self, session: Session):
        """
        Read encrypted commands from the tunnel peer and execute them.
        """
        while session.active and self._running:
            try:
                data = session.recv_encrypted()
                if data is None:
                    logger.info("Tunnel peer closed session")
                    break
                if data == b"":
                    continue

                # Parse JSON command
                try:
                    cmd = json.loads(data.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logger.warning("Non-JSON data received, ignoring")
                    continue

                cmd_type = cmd.get("cmd", "")

                if cmd_type == "connect":
                    self._handle_connect(session, cmd)

                elif cmd_type == "data":
                    self._handle_data(session, cmd)

                elif cmd_type == "http":
                    self._handle_http(session, cmd)

                elif cmd_type == "close":
                    self._handle_close(cmd)

                else:
                    logger.debug("Unknown command: %s", cmd_type)

            except ConnectionError:
                break
            except Exception as exc:
                logger.error("Command loop error: %s", exc)
                break

        # Cleanup all destination sockets for this session
        self._cleanup_session_dests()

    # ── CONNECT handler (HTTPS tunneling) ────────────────────────

    def _handle_connect(self, session: Session, cmd: dict):
        host   = cmd["host"]
        port   = cmd["port"]
        req_id = cmd["req_id"]

        try:
            dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest.settimeout(15)
            dest.connect((host, port))
            dest.settimeout(None)

            with self._lock:
                self._dest_socks[req_id] = dest

            # Tell proxy: connection established
            resp = {
                "cmd":    "connect_ok",
                "req_id": req_id,
            }
            session.send_encrypted(
                json.dumps(resp).encode("utf-8")
            )

            logger.info("CONNECT %s:%d [%s]", host, port, req_id[:8])

            # Start background reader: dest → tunnel
            threading.Thread(
                target=self._dest_reader,
                args=(session, dest, req_id),
                daemon=True,
                name=f"DestRead-{req_id[:8]}",
            ).start()

        except Exception as exc:
            resp = {
                "cmd":    "connect_fail",
                "req_id": req_id,
                "error":  str(exc),
            }
            try:
                session.send_encrypted(
                    json.dumps(resp).encode("utf-8")
                )
            except Exception:
                pass
            logger.warning("CONNECT %s:%d failed: %s", host, port, exc)

    # ── DATA handler (relay bytes to destination) ────────────────

    def _handle_data(self, session: Session, cmd: dict):
        req_id  = cmd["req_id"]
        import base64
        payload = base64.b64decode(cmd["payload"])

        with self._lock:
            dest = self._dest_socks.get(req_id)

        if dest:
            try:
                dest.sendall(payload)
            except (ConnectionError, OSError):
                self._close_dest(req_id)
                eof = {"cmd": "eof", "req_id": req_id}
                try:
                    session.send_encrypted(
                        json.dumps(eof).encode("utf-8")
                    )
                except Exception:
                    pass

    # ── HTTP handler (simple HTTP forward) ───────────────────────

    def _handle_http(self, session: Session, cmd: dict):
        host   = cmd["host"]
        port   = cmd["port"]
        req_id = cmd["req_id"]
        import base64
        request_data = base64.b64decode(cmd["request"])

        dest = None
        try:
            dest = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest.settimeout(15)
            dest.connect((host, port))
            dest.sendall(request_data)

            # Read full response
            response = b""
            dest.settimeout(10)
            while True:
                try:
                    chunk = dest.recv(65536)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            # Send response back through tunnel
            resp = {
                "cmd":     "http_response",
                "req_id":  req_id,
                "payload": base64.b64encode(response).decode("ascii"),
            }
            session.send_encrypted(
                json.dumps(resp).encode("utf-8")
            )
            logger.info(
                "HTTP %s:%d → %d bytes [%s]",
                host, port, len(response), req_id[:8],
            )

        except Exception as exc:
            resp = {
                "cmd":    "connect_fail",
                "req_id": req_id,
                "error":  str(exc),
            }
            try:
                session.send_encrypted(
                    json.dumps(resp).encode("utf-8")
                )
            except Exception:
                pass
        finally:
            if dest:
                try:
                    dest.close()
                except OSError:
                    pass

    # ── CLOSE handler ────────────────────────────────────────────

    def _handle_close(self, cmd: dict):
        req_id = cmd.get("req_id", "")
        self._close_dest(req_id)

    # ── destination → tunnel reader ──────────────────────────────

    def _dest_reader(self, session: Session,
                     dest: socket.socket, req_id: str):
        """
        Background thread: reads from destination website,
        encrypts and sends back through tunnel.
        """
        import base64
        try:
            while session.active and self._running:
                try:
                    ready, _, _ = select.select([dest], [], [], 1.0)
                except (ValueError, OSError):
                    break

                if not ready:
                    continue

                try:
                    data = dest.recv(65536)
                except (ConnectionError, OSError):
                    break

                if not data:
                    break

                resp = {
                    "cmd":     "data",
                    "req_id":  req_id,
                    "payload": base64.b64encode(data).decode("ascii"),
                }
                try:
                    session.send_encrypted(
                        json.dumps(resp).encode("utf-8")
                    )
                except Exception:
                    break

        except Exception as exc:
            logger.debug("dest_reader %s ended: %s", req_id[:8], exc)
        finally:
            # Send EOF to proxy
            try:
                eof = {"cmd": "eof", "req_id": req_id}
                session.send_encrypted(
                    json.dumps(eof).encode("utf-8")
                )
            except Exception:
                pass
            self._close_dest(req_id)

    # ── helpers ──────────────────────────────────────────────────

    def _close_dest(self, req_id: str):
        with self._lock:
            dest = self._dest_socks.pop(req_id, None)
        if dest:
            try:
                dest.close()
            except OSError:
                pass

    def _cleanup_session_dests(self):
        with self._lock:
            for req_id, dest in list(self._dest_socks.items()):
                try:
                    dest.close()
                except OSError:
                    pass
            self._dest_socks.clear()


# ── Standalone runner ────────────────────────────────────────────

def run_exit_node(host: str = "0.0.0.0", port: int = 9090):
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    node = ExitNode(host, port)
    node.start()
    print(f"\n🌐 SecureCrypt Exit Node on {host}:{port}")
    print("   Waiting for tunnel connections…\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.stop()
        print("\nExit node stopped.")


if __name__ == "__main__":
    run_exit_node()