"""
SecureCrypt Peer Client — connects to Relay, handles E2E messaging
and file transfer.

Usage:
    client = PeerClient("alice", "relay.server.com", 9091)
    client.connect()

    # Establish E2E session with Bob
    client.initiate_e2e("bob", cipher_name="AES-256-GCM")
    # (wait for Bob to respond)

    # Send messages
    client.send_message("bob", "Hello Bob!")

    # Send files
    client.send_file("bob", "/path/to/document.pdf")
"""

import socket
import threading
import json
import time
import os
import logging
import base64

from utils.framing      import Framing, MessageType
from core.e2e_engine    import E2EEngine, E2ESession
from core.file_transfer import (
    FileChunker, FileAssembler, FileMetadata, CHUNK_SIZE,
)
from core.crypto_engine import CipherFactory
from config.settings    import Settings

logger = logging.getLogger("SecureCrypt.Peer")


class PeerClient:
    """
    E2E encrypted peer client connecting through a relay server.
    """

    def __init__(
        self,
        username: str,
        relay_host: str = "127.0.0.1",
        relay_port: int = 9091,
        download_dir: str | None = None,
        # GUI callbacks
        on_message_received=None,
        on_file_started=None,
        on_file_progress=None,
        on_file_complete=None,
        on_peer_list=None,
        on_e2e_established=None,
        on_status=None,
        on_error=None,
    ):
        self.username   = username
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.download_dir = download_dir or os.path.join(
            Settings.BASE_DIR, "downloads"
        )
        os.makedirs(self.download_dir, exist_ok=True)

        self.e2e = E2EEngine(username)

        # Callbacks
        self._on_message    = on_message_received
        self._on_file_start = on_file_started
        self._on_file_prog  = on_file_progress
        self._on_file_done  = on_file_complete
        self._on_peers      = on_peer_list
        self._on_e2e        = on_e2e_established
        self._on_status     = on_status
        self._on_error      = on_error

        self._sock: socket.socket | None = None
        self._running = False
        self._lock    = threading.Lock()

        # Active file assemblers
        self._assemblers: dict[str, FileAssembler] = {}

    # ── Connection ───────────────────────────────────────────────

    def connect(self) -> bool:
        """Connect to relay server and register."""
        try:
            # Generate identity if needed
            if self.e2e.identity is None:
                self.e2e.generate_identity()

            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            self._sock.settimeout(15)
            self._sock.connect((self.relay_host, self.relay_port))
            self._sock.settimeout(None)

            self._running = True

            # Register with relay
            reg = {
                "action":         "register",
                "username":       self.username,
                "rsa_public_key": self.e2e.identity.public_key_pem,
            }
            Framing.send_frame(
                self._sock, MessageType.RELAY,
                json.dumps(reg).encode(),
            )

            # Wait for registration confirmation
            msg_type, payload = Framing.recv_frame(self._sock)
            resp = json.loads(payload.decode())
            if resp.get("status") != "ok":
                raise RuntimeError(
                    f"Registration failed: {resp.get('message')}"
                )

            # Start listener thread
            threading.Thread(
                target=self._listen_loop, daemon=True,
                name=f"Peer-{self.username}-listener",
            ).start()

            # Start keepalive
            threading.Thread(
                target=self._keepalive_loop, daemon=True,
            ).start()

            self._fire_status(
                f"Connected as '{self.username}' to "
                f"{self.relay_host}:{self.relay_port}"
            )
            logger.info(
                "Peer %s connected to relay %s:%d",
                self.username, self.relay_host, self.relay_port,
            )
            return True

        except Exception as exc:
            self._fire_error(f"Connection failed: {exc}")
            logger.error("Connect failed: %s", exc, exc_info=True)
            return False

    def disconnect(self):
        self._running = False
        if self._sock:
            try:
                Framing.send_frame(
                    self._sock, MessageType.CLOSE, b""
                )
            except Exception:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._fire_status("Disconnected")

    @property
    def is_connected(self) -> bool:
        return self._running and self._sock is not None

    # ── Peer Discovery ───────────────────────────────────────────

    def request_peer_list(self):
        self._send_relay({"action": "list_peers"})

    def get_peer_keys(self, username: str):
        self._send_relay({
            "action":   "get_peer_keys",
            "username": username,
        })

    # ── E2E Session Establishment ────────────────────────────────

    def initiate_e2e(self, peer_username: str,
                     peer_rsa_pub_pem: str,
                     cipher_name: str = "AES-256-GCM"):
        """Start E2E key exchange with a peer."""
        init_data = self.e2e.create_key_exchange(
            peer_username, peer_rsa_pub_pem, cipher_name
        )
        self._send_relay(init_data)
        self._fire_status(
            f"Key exchange initiated with {peer_username} "
            f"(cipher: {cipher_name})"
        )

    # ── Messaging ────────────────────────────────────────────────

    def send_message(self, peer_username: str, text: str) -> bool:
        """Send an E2E encrypted + signed text message."""
        session = self.e2e.get_session(peer_username)
        if not session:
            self._fire_error(
                f"No E2E session with {peer_username}. "
                f"Initiate key exchange first."
            )
            return False

        encrypted = session.encrypt_and_sign(text.encode("utf-8"))
        msg = {
            "action":         "send_message",
            "from_user":      self.username,
            "to_user":        peer_username,
            "msg_id":         SecureRandom.generate_session_id(),
            "timestamp":      time.time(),
            "msg_type":       "text",
            **encrypted,
        }
        self._send_relay(msg)
        logger.debug("Sent message to %s (%d chars)", peer_username, len(text))
        return True

    # ── File Transfer ────────────────────────────────────────────

    def send_file(self, peer_username: str, filepath: str,
                  progress_callback=None) -> bool:
        """Send an E2E encrypted file with RSA-signed hash."""
        session = self.e2e.get_session(peer_username)
        if not session:
            self._fire_error(f"No E2E session with {peer_username}")
            return False

        try:
            chunker = FileChunker(filepath, session)

            # Send file metadata
            meta_msg = {
                "action":    "file_meta",
                "from_user": self.username,
                "to_user":   peer_username,
                **chunker.metadata.to_dict(),
            }
            self._send_relay(meta_msg)
            self._fire_status(
                f"Sending {chunker.filename} to {peer_username} "
                f"({FileMetadata.format_size(chunker.file_size)}, "
                f"{chunker.total_chunks} chunks)"
            )

            # Send chunks
            for idx, encrypted_chunk in chunker.chunks_with_progress(
                progress_callback
            ):
                chunk_msg = {
                    "action":       "file_chunk",
                    "from_user":    self.username,
                    "to_user":      peer_username,
                    "transfer_id":  chunker.transfer_id,
                    "chunk_index":  idx,
                    "chunk_data":   base64.b64encode(
                        encrypted_chunk
                    ).decode(),
                }
                self._send_relay(chunk_msg)

                # Small delay to avoid overwhelming the relay
                if idx % 10 == 9:
                    time.sleep(0.01)

            # Send completion
            complete_msg = {
                "action":      "file_complete",
                "from_user":   self.username,
                "to_user":     peer_username,
                "transfer_id": chunker.transfer_id,
            }
            self._send_relay(complete_msg)

            self._fire_status(
                f"File sent: {chunker.filename} → {peer_username}"
            )
            return True

        except Exception as exc:
            self._fire_error(f"File send failed: {exc}")
            logger.error("File send error: %s", exc, exc_info=True)
            return False

    # ── Listener Loop ────────────────────────────────────────────

    def _listen_loop(self):
        while self._running:
            try:
                msg_type, payload = Framing.recv_frame(self._sock)

                if msg_type == MessageType.CLOSE:
                    self._running = False
                    self._fire_status("Server closed connection")
                    break

                if msg_type == MessageType.KEEPALIVE:
                    continue

                if msg_type == MessageType.RELAY:
                    data = json.loads(payload.decode())
                    self._handle_relay_message(data)

            except ConnectionError:
                self._running = False
                self._fire_status("Connection lost")
                break
            except Exception as exc:
                logger.error("Listener error: %s", exc, exc_info=True)
                if not self._running:
                    break

    def _handle_relay_message(self, data: dict):
        action = data.get("action", "")

        if action == "peer_list":
            if self._on_peers:
                self._on_peers(data.get("peers", []))

        elif action == "peer_keys":
            logger.info(
                "Received keys for %s", data.get("username")
            )

        elif action == "key_exchange_init":
            self._handle_kex_init(data)

        elif action == "key_exchange_response":
            self._handle_kex_response(data)

        elif action == "send_message":
            self._handle_incoming_message(data)

        elif action == "file_meta":
            self._handle_file_meta(data)

        elif action == "file_chunk":
            self._handle_file_chunk(data)

        elif action == "file_complete":
            self._handle_file_complete(data)

        elif action == "error":
            self._fire_error(data.get("message", "Unknown error"))

        else:
            logger.debug("Unknown relay action: %s", action)

    # ── Key Exchange Handling ────────────────────────────────────

    def _handle_kex_init(self, data: dict):
        """Handle incoming key exchange initiation."""
        from_user = data["from_user"]
        cipher    = data.get("cipher_name", "AES-256-GCM")

        try:
            response, session = self.e2e.respond_key_exchange(data)
            self._send_relay(response)

            self._fire_status(
                f"E2E session established with {from_user} "
                f"(cipher: {cipher})"
            )
            if self._on_e2e:
                self._on_e2e(from_user, session.info())

        except Exception as exc:
            self._fire_error(
                f"Key exchange with {from_user} failed: {exc}"
            )

    def _handle_kex_response(self, data: dict):
        """Handle key exchange response (we initiated)."""
        from_user = data["from_user"]
        try:
            session = self.e2e.complete_key_exchange(data)

            self._fire_status(
                f"E2E session established with {from_user} "
                f"(cipher: {session.cipher_name})"
            )
            if self._on_e2e:
                self._on_e2e(from_user, session.info())

        except Exception as exc:
            self._fire_error(
                f"Key exchange completion with {from_user} "
                f"failed: {exc}"
            )

    # ── Message Handling ─────────────────────────────────────────

    def _handle_incoming_message(self, data: dict):
        from_user = data["from_user"]
        session = self.e2e.get_session(from_user)

        if not session:
            self._fire_error(
                f"Message from {from_user} but no E2E session"
            )
            return

        try:
            plaintext, sig_valid = session.decrypt_and_verify(
                data["encrypted_data"],
                data["signature"],
            )
            text = plaintext.decode("utf-8")

            if self._on_message:
                self._on_message(
                    from_user, text, sig_valid,
                    data.get("timestamp", time.time()),
                    session.cipher_name,
                )

            sig_icon = "✅" if sig_valid else "❌"
            logger.info(
                "Message from %s [%s sig] [%s]: %s",
                from_user, sig_icon, session.cipher_name,
                text[:50] + ("…" if len(text) > 50 else ""),
            )
        except Exception as exc:
            self._fire_error(
                f"Failed to decrypt message from {from_user}: {exc}"
            )

    # ── File Transfer Handling ───────────────────────────────────

    def _handle_file_meta(self, data: dict):
        from_user = data["from_user"]
        session = self.e2e.get_session(from_user)
        if not session:
            self._fire_error(f"File from {from_user} but no session")
            return

        try:
            meta = FileMetadata.from_dict(data)
            assembler = FileAssembler(
                meta, session, self.download_dir
            )
            self._assemblers[meta.transfer_id] = assembler

            self._fire_status(
                f"Receiving file from {from_user}: "
                f"{meta.filename} "
                f"({FileMetadata.format_size(meta.file_size)})"
            )
            if self._on_file_start:
                self._on_file_start(from_user, meta.to_dict())

        except Exception as exc:
            self._fire_error(f"File meta error: {exc}")

    def _handle_file_chunk(self, data: dict):
        tid = data["transfer_id"]
        assembler = self._assemblers.get(tid)
        if not assembler:
            return

        try:
            encrypted = base64.b64decode(data["chunk_data"])
            assembler.add_chunk(data["chunk_index"], encrypted)

            if self._on_file_prog:
                self._on_file_prog(tid, assembler.progress)

        except Exception as exc:
            logger.error("Chunk error: %s", exc)

    def _handle_file_complete(self, data: dict):
        tid = data["transfer_id"]
        assembler = self._assemblers.pop(tid, None)
        if not assembler:
            return

        try:
            result = assembler.finalize()

            if self._on_file_done:
                self._on_file_done(data["from_user"], result)

            if result["success"]:
                self._fire_status(
                    f"✅ File received: {result['filename']} "
                    f"(hash ✓, signature ✓)"
                )
            else:
                self._fire_error(
                    f"❌ File verification failed: "
                    f"hash={'✓' if result['hash_valid'] else '✗'} "
                    f"sig={'✓' if result['sig_valid'] else '✗'}"
                )
        except Exception as exc:
            self._fire_error(f"File finalize error: {exc}")

    # ── Helpers ──────────────────────────────────────────────────

    def _send_relay(self, data: dict):
        with self._lock:
            Framing.send_frame(
                self._sock, MessageType.RELAY,
                json.dumps(data).encode(),
            )

    def _keepalive_loop(self):
        while self._running:
            try:
                with self._lock:
                    if self._sock:
                        Framing.send_frame(
                            self._sock, MessageType.KEEPALIVE, b""
                        )
            except Exception:
                break
            time.sleep(15)

    def _fire_status(self, msg: str):
        if self._on_status:
            self._on_status(msg)

    def _fire_error(self, msg: str):
        logger.error(msg)
        if self._on_error:
            self._on_error(msg)

    # ── Info ─────────────────────────────────────────────────────

    @property
    def identity_info(self) -> dict | None:
        if self.e2e.identity:
            return self.e2e.identity.info()
        return None

    @property
    def sessions(self) -> list[dict]:
        return self.e2e.list_sessions()


# Need this import for send_message msg_id
from utils.random_gen import SecureRandom