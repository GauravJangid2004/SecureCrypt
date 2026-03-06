"""
SecureCrypt Exit Node — runs on the remote server.

Receives encrypted tunnel traffic, decrypts it, and forwards
to the real internet destination. Sends responses back through
the encrypted tunnel.

This is what makes the proxy work end-to-end:
  Browser → Local Proxy → Encrypt → Tunnel → EXIT NODE → Internet
                                               ↑ this file
"""

import socket
import select
import json
import threading
import logging

from config.settings         import Settings
from traffic.handshake       import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from utils.framing           import Framing, MessageType
from utils.random_gen        import SecureRandom

logger = logging.getLogger("SecureCrypt.ExitNode")


class ExitNode:
    """
    Listens for SecureCrypt tunnel connections and acts as an
    internet exit point — decrypting proxy commands and forwarding
    traffic to real destinations.
    """

    def __init__(
        self,
        host: str = Settings.TUNNEL_HOST,
        port: int = Settings.TUNNEL_PORT,
        server_id: str = "securecrypt-exit-node",
    ):
        self.host      = host
        self.port      = port
        self.server_id = server_id

        self.session_manager = SessionManager(
            timeout=Settings.SESSION_TIMEOUT
        )

        self._server_sock: socket.socket | None = None
        self._running = False

    def start(self):
        """Start the exit node server."""
        self._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(50)

        self._running = True
        self.session_manager.start()

        threading.Thread(
            target=self._accept_loop, daemon=True,
            name="ExitNodeAccept",
        ).start()

        logger.info(
            "Exit node listening on %s:%d", self.host, self.port
        )

    def stop(self):
        self._running = False
        self.session_manager.stop()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        logger.info("Exit node stopped")

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            logger.info("Tunnel peer connected from %s:%d", *addr)
            threading.Thread(
                target=self._handle_peer,
                args=(client_sock, addr),
                daemon=True,
            ).start()

    def _handle_peer(self, sock: socket.socket, addr: tuple):
        """Handle one tunnel peer — handshake then command loop."""
        session: Session | None = None
        try:
            # Perform handshake
            hs = HandshakeProtocol()
            session_key, cipher = hs.server_hello(
                sock, server_id=self.server_id
            )
            session_id = SecureRandom.generate_session_id()
            session = Session(
                session_id=session_id,
                session_key=session_key,
                cipher=cipher,
                sock=sock,
                peer_addr=addr,
            )
            self.session_manager.add(session)
            logger.info(
                "Exit node session %s established with %s:%d",
                session_id, *addr,
            )

            # Command loop — read commands from tunnel peer
            while session.active and self._running:
                data = session.recv_encrypted()
                if data is None:
                    break
                if data == b"":
                    continue

                # Try to parse as JSON command
                try:
                    cmd = json.loads(data.decode())
                    action = cmd.get("action")

                    if action == "connect":
                        self._handle_connect(
                            session, cmd["host"], cmd["port"]
                        )
                    elif action == "http_forward":
                        self._handle_http_forward(session, cmd)
                    else:
                        # Raw data — just log it
                        logger.debug(
                            "Raw data from %s: %d bytes",
                            session_id, len(data),
                        )
                except (json.JSONDecodeError, KeyError):
                    # Not a command — treat as raw tunnel data
                    logger.debug(
                        "Raw tunnel data: %d bytes", len(data)
                    )

        except Exception as exc:
            logger.error(
                "Exit node peer error (%s:%d): %s",
                *addr, exc,
            )
        finally:
            if session:
                self.session_manager.remove(session.session_id)

    def _handle_connect(self, session: Session,
                        host: str, port: int):
        """
        CONNECT command — open TCP connection to destination
        and relay bidirectionally through the encrypted session.
        """
        dest_sock: socket.socket | None = None
        try:
            dest_sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            dest_sock.settimeout(15)
            dest_sock.connect((host, port))
            dest_sock.settimeout(None)

            logger.info("Exit node connected to %s:%d", host, port)

            # Tell the proxy peer we're connected
            session.send_encrypted(json.dumps({
                "status": "connected",
                "host":   host,
                "port":   port,
            }).encode())

            # Bidirectional relay
            self._relay_tunnel_to_dest(session, dest_sock)

        except Exception as exc:
            logger.error(
                "Exit node connect to %s:%d failed: %s",
                host, port, exc,
            )
            try:
                session.send_encrypted(json.dumps({
                    "status": "error",
                    "error":  str(exc),
                }).encode())
            except Exception:
                pass
        finally:
            if dest_sock:
                try:
                    dest_sock.close()
                except OSError:
                    pass

    def _handle_http_forward(self, session: Session, cmd: dict):
        """
        Forward an HTTP request to the destination and return
        the response through the tunnel.
        """
        host = cmd["host"]
        port = cmd["port"]
        dest_sock = None

        try:
            # Read the actual HTTP request data
            request_data = session.recv_encrypted()
            if not request_data:
                return

            dest_sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            dest_sock.settimeout(15)
            dest_sock.connect((host, port))
            dest_sock.sendall(request_data)

            # Read response
            response = b""
            dest_sock.settimeout(10)
            while True:
                try:
                    chunk = dest_sock.recv(Settings.BUFFER_SIZE)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            if response:
                session.send_encrypted(response)

        except Exception as exc:
            logger.error(
                "HTTP forward to %s:%d failed: %s",
                host, port, exc,
            )
        finally:
            if dest_sock:
                try:
                    dest_sock.close()
                except OSError:
                    pass

    def _relay_tunnel_to_dest(self, session: Session,
                               dest_sock: socket.socket):
        """
        Bidirectional relay:
          tunnel session ↔ destination socket
        """
        stop = threading.Event()

        def _tunnel_to_dest():
            try:
                while session.active and not stop.is_set():
                    data = session.recv_encrypted()
                    if data is None:
                        break
                    if data == b"":
                        continue
                    # Check if it's a new command (stop relay)
                    try:
                        cmd = json.loads(data.decode())
                        if cmd.get("action") in (
                            "connect", "http_forward", "disconnect"
                        ):
                            break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
                    dest_sock.sendall(data)
            except Exception:
                pass
            finally:
                stop.set()

        def _dest_to_tunnel():
            try:
                while session.active and not stop.is_set():
                    ready, _, _ = select.select(
                        [dest_sock], [], [], 1.0
                    )
                    if not ready:
                        continue
                    data = dest_sock.recv(Settings.BUFFER_SIZE)
                    if not data:
                        break
                    session.send_encrypted(data)
            except Exception:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=_tunnel_to_dest, daemon=True)
        t2 = threading.Thread(target=_dest_to_tunnel, daemon=True)
        t1.start()
        t2.start()
        stop.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)