"""
SecureCrypt Relay Server — routes E2E encrypted messages.

The relay server:
  ✓ Registers users (stores public keys only)
  ✓ Routes encrypted messages between peers
  ✓ Forwards file transfer chunks
  ✗ CANNOT read any message content
  ✗ CANNOT forge signatures
  ✗ CANNOT perform MITM (ECDH keys are RSA-signed)

Run standalone:
    python -m traffic.relay_server
"""

import socket
import threading
import json
import time
import logging

from utils.framing    import Framing, MessageType
from config.settings  import Settings

logger = logging.getLogger("SecureCrypt.Relay")


class RelayUser:
    """A registered user on the relay server."""

    def __init__(self, username: str, sock: socket.socket,
                 addr: tuple, rsa_public_key: str):
        self.username       = username
        self.sock           = sock
        self.addr           = addr
        self.rsa_public_key = rsa_public_key
        self.registered_at  = time.time()
        self.last_seen      = time.time()
        self.online         = True
        self._lock          = threading.Lock()

    def send(self, msg_type: int, payload: bytes):
        with self._lock:
            try:
                Framing.send_frame(self.sock, msg_type, payload)
                self.last_seen = time.time()
            except Exception as exc:
                logger.warning(
                    "Send to %s failed: %s", self.username, exc
                )
                self.online = False


class RelayServer:
    """
    Central relay for SecureCrypt E2E messaging.

    Accepts TCP connections from peers, registers them,
    and routes encrypted messages between them.
    """

    def __init__(self, host: str = "0.0.0.0",
                 port: int = 9091):
        self.host = host
        self.port = port
        self.users: dict[str, RelayUser] = {}
        self._lock = threading.Lock()
        self._server_sock: socket.socket | None = None
        self._running = False

    def start(self):
        self._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(100)
        self._running = True

        threading.Thread(
            target=self._accept_loop, daemon=True,
            name="RelayAccept",
        ).start()

        logger.info(
            "Relay server listening on %s:%d", self.host, self.port
        )

    def stop(self):
        self._running = False
        with self._lock:
            for u in self.users.values():
                try:
                    u.sock.close()
                except OSError:
                    pass
            self.users.clear()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        logger.info("Relay server stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def online_users(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "username": u.username,
                    "online":   u.online,
                    "addr":     f"{u.addr[0]}:{u.addr[1]}",
                }
                for u in self.users.values() if u.online
            ]

    # ── accept loop ──────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            logger.info("Relay connection from %s:%d", *addr)
            threading.Thread(
                target=self._handle_client,
                args=(sock, addr),
                daemon=True,
            ).start()

    # ── per-client handler ───────────────────────────────────────

    def _handle_client(self, sock: socket.socket, addr: tuple):
        username = None
        try:
            while self._running:
                msg_type, payload = Framing.recv_frame(sock)

                if msg_type == MessageType.CLOSE:
                    break

                if msg_type == MessageType.KEEPALIVE:
                    if username:
                        with self._lock:
                            u = self.users.get(username)
                            if u:
                                u.last_seen = time.time()
                    continue

                if msg_type == MessageType.RELAY:
                    data = json.loads(payload.decode())
                    action = data.get("action", "")

                    if action == "register":
                        username = self._handle_register(
                            data, sock, addr
                        )

                    elif action == "list_peers":
                        self._handle_list_peers(username, sock)

                    elif action == "get_peer_keys":
                        self._handle_get_peer_keys(data, sock)

                    elif action in (
                        "key_exchange_init",
                        "key_exchange_response",
                        "send_message",
                        "file_meta",
                        "file_chunk",
                        "file_complete",
                    ):
                        self._route_to_peer(data, msg_type, payload)

                    else:
                        self._send_error(
                            sock, f"Unknown action: {action}"
                        )

                elif msg_type in (
                    MessageType.PEER_MESSAGE,
                    MessageType.FILE_META,
                    MessageType.FILE_CHUNK,
                    MessageType.FILE_COMPLETE,
                ):
                    # Binary messages with JSON routing header
                    try:
                        data = json.loads(payload.decode())
                        self._route_to_peer(data, msg_type, payload)
                    except json.JSONDecodeError:
                        logger.warning("Invalid binary relay message")

        except ConnectionError:
            logger.info("Client disconnected: %s", username or addr)
        except Exception as exc:
            logger.error(
                "Relay handler error: %s", exc, exc_info=True
            )
        finally:
            if username:
                with self._lock:
                    u = self.users.get(username)
                    if u:
                        u.online = False
                logger.info("User %s went offline", username)
            try:
                sock.close()
            except OSError:
                pass

    # ── handlers ─────────────────────────────────────────────────

    def _handle_register(self, data: dict,
                         sock: socket.socket,
                         addr: tuple) -> str:
        username = data["username"]
        rsa_pub  = data["rsa_public_key"]

        user = RelayUser(username, sock, addr, rsa_pub)
        with self._lock:
            self.users[username] = user

        response = {
            "action":  "registered",
            "status":  "ok",
            "user_id": username,
            "message": f"Welcome {username}!",
        }
        Framing.send_frame(
            sock, MessageType.RELAY,
            json.dumps(response).encode(),
        )
        logger.info("User registered: %s from %s:%d", username, *addr)
        return username

    def _handle_list_peers(self, requesting_user: str | None,
                           sock: socket.socket):
        peers = []
        with self._lock:
            for uname, u in self.users.items():
                if uname != requesting_user:
                    peers.append({
                        "username":       uname,
                        "online":         u.online,
                        "rsa_public_key": u.rsa_public_key,
                    })
        response = {
            "action": "peer_list",
            "peers":  peers,
        }
        Framing.send_frame(
            sock, MessageType.RELAY,
            json.dumps(response).encode(),
        )

    def _handle_get_peer_keys(self, data: dict,
                              sock: socket.socket):
        target = data.get("username", "")
        with self._lock:
            user = self.users.get(target)

        if user:
            response = {
                "action":         "peer_keys",
                "username":       target,
                "online":         user.online,
                "rsa_public_key": user.rsa_public_key,
            }
        else:
            response = {
                "action":  "error",
                "message": f"User '{target}' not found",
            }
        Framing.send_frame(
            sock, MessageType.RELAY,
            json.dumps(response).encode(),
        )

    def _route_to_peer(self, data: dict, msg_type: int,
                       raw_payload: bytes):
        target = data.get("to_user")
        if not target:
            logger.warning("No to_user in relay message")
            return

        with self._lock:
            peer = self.users.get(target)

        if peer and peer.online:
            peer.send(msg_type, raw_payload)
            logger.debug(
                "Routed %s → %s (%d bytes)",
                data.get("from_user", "?"), target, len(raw_payload),
            )
        else:
            logger.warning(
                "Cannot route to %s (offline or not found)", target
            )
            # Try to notify sender
            sender_name = data.get("from_user")
            if sender_name:
                with self._lock:
                    sender = self.users.get(sender_name)
                if sender and sender.online:
                    err = {
                        "action":  "error",
                        "message": f"{target} is offline",
                    }
                    sender.send(
                        MessageType.RELAY,
                        json.dumps(err).encode(),
                    )

    def _send_error(self, sock: socket.socket, message: str):
        err = {"action": "error", "message": message}
        Framing.send_frame(
            sock, MessageType.RELAY,
            json.dumps(err).encode(),
        )


# ── Standalone runner ────────────────────────────────────────────

def run_relay_server(host: str = "0.0.0.0", port: int = 9091):
    """Run relay server as a standalone process."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    server = RelayServer(host, port)
    server.start()
    print(f"\n🔁 SecureCrypt Relay Server running on {host}:{port}")
    print("   Press Ctrl+C to stop\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("\nRelay server stopped.")


if __name__ == "__main__":
    run_relay_server()