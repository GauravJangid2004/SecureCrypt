# """
# Encrypted-session abstraction and lifecycle manager.
# """

# import time, threading, logging
# from core.crypto_engine import AESCrypto
# from utils.framing      import Framing, MessageType

# logger = logging.getLogger("SecureCrypt.Session")


# class Session:
#     """A single end-to-end encrypted connection."""

#     def __init__(self, session_id: str, session_key: bytes,
#                  cipher: str, sock, peer_addr: tuple):
#         self.session_id     = session_id
#         self.session_key    = session_key
#         self.cipher         = cipher
#         self.sock           = sock
#         self.peer_addr      = peer_addr
#         self.created_at     = time.time()
#         self.last_activity  = time.time()
#         self.bytes_sent     = 0
#         self.bytes_received = 0
#         self.active         = True
#         self._aes           = AESCrypto(key=session_key)
#         self._lock          = threading.Lock()

#     def send_encrypted(self, data: bytes):
#         with self._lock:
#             nonce, ct = self._aes.encrypt_gcm(data)
#             Framing.send_frame(self.sock, MessageType.DATA, nonce + ct)
#             self.bytes_sent   += len(data)
#             self.last_activity = time.time()

#     def recv_encrypted(self) -> bytes | None:
#         msg_type, payload = Framing.recv_frame(self.sock)
#         if msg_type == MessageType.CLOSE:
#             self.active = False
#             return None
#         if msg_type == MessageType.KEEPALIVE:
#             self.last_activity = time.time()
#             return b""
#         if msg_type != MessageType.DATA:
#             raise RuntimeError(f"Unexpected msg type 0x{msg_type:02x}")
#         nonce, ct = payload[:12], payload[12:]
#         data = self._aes.decrypt_gcm(nonce, ct)
#         self.bytes_received += len(data)
#         self.last_activity   = time.time()
#         return data

#     def close(self):
#         if not self.active:
#             return
#         self.active = False
#         try:
#             Framing.send_frame(self.sock, MessageType.CLOSE, b"")
#         except Exception:
#             pass
#         try:
#             self.sock.close()
#         except Exception:
#             pass

#     def info(self) -> dict:
#         return {
#             "session_id":     self.session_id,
#             "peer":           f"{self.peer_addr[0]}:{self.peer_addr[1]}",
#             "cipher":         self.cipher,
#             "created":        self.created_at,
#             "last_activity":  self.last_activity,
#             "bytes_sent":     self.bytes_sent,
#             "bytes_received": self.bytes_received,
#             "active":         self.active,
#         }


# class SessionManager:
#     """Track every active *Session* and expire stale ones."""

#     def __init__(self, timeout: int = 3600):
#         self.sessions: dict[str, Session] = {}
#         self.timeout  = timeout
#         self._lock    = threading.Lock()
#         self._running = False

#     def start(self):
#         self._running = True
#         threading.Thread(target=self._cleanup_loop, daemon=True).start()

#     def stop(self):
#         self._running = False
#         with self._lock:
#             for s in list(self.sessions.values()):
#                 s.close()
#             self.sessions.clear()

#     def add(self, session: Session):
#         with self._lock:
#             self.sessions[session.session_id] = session

#     def remove(self, sid: str):
#         with self._lock:
#             s = self.sessions.pop(sid, None)
#         if s:
#             s.close()

#     def get(self, sid: str) -> Session | None:
#         with self._lock:
#             return self.sessions.get(sid)

#     def all_info(self) -> list[dict]:
#         with self._lock:
#             return [s.info() for s in self.sessions.values()]

#     def active_count(self) -> int:
#         with self._lock:
#             return sum(1 for s in self.sessions.values() if s.active)

#     # ── internal ─────────────────────────────────────────────────
#     def _cleanup_loop(self):
#         while self._running:
#             time.sleep(30)
#             now     = time.time()
#             expired = []
#             with self._lock:
#                 for sid, s in self.sessions.items():
#                     if now - s.last_activity > self.timeout:
#                         expired.append(sid)
#             for sid in expired:
#                 logger.info("Expiring session %s", sid)
#                 self.remove(sid)





"""
Encrypted-session abstraction using the unified CipherFactory.
Now supports ALL registered ciphers — not just AES-256-GCM.
"""

import time
import threading
import logging

from core.crypto_engine import CipherFactory, SymmetricCipher
from utils.framing      import Framing, MessageType

logger = logging.getLogger("SecureCrypt.Session")


class Session:
    """A single end-to-end encrypted connection."""

    def __init__(self, session_id: str, session_key: bytes,
                 cipher: str, sock, peer_addr: tuple):
        self.session_id     = session_id
        self.session_key    = session_key
        self.cipher         = cipher
        self.sock           = sock
        self.peer_addr      = peer_addr
        self.created_at     = time.time()
        self.last_activity  = time.time()
        self.bytes_sent     = 0
        self.bytes_received = 0
        self.active         = True
        self._lock          = threading.Lock()

        # ── Create the negotiated cipher via factory ─────────────
        self._crypto: SymmetricCipher = CipherFactory.create(
            cipher, session_key
        )
        logger.info(
            "Session %s using cipher %s (AEAD=%s)",
            session_id, self._crypto.cipher_name,
            self._crypto.is_aead,
        )

    def send_encrypted(self, data: bytes):
        """Encrypt data with the negotiated cipher and send."""
        with self._lock:
            encrypted = self._crypto.encrypt(data)
            Framing.send_frame(
                self.sock, MessageType.DATA, encrypted
            )
            self.bytes_sent   += len(data)
            self.last_activity = time.time()

    def recv_encrypted(self) -> bytes | None:
        """Receive and decrypt a frame."""
        msg_type, payload = Framing.recv_frame(self.sock)

        if msg_type == MessageType.CLOSE:
            self.active = False
            return None

        if msg_type == MessageType.KEEPALIVE:
            self.last_activity = time.time()
            return b""

        if msg_type != MessageType.DATA:
            raise RuntimeError(
                f"Unexpected msg type 0x{msg_type:02x}"
            )

        data = self._crypto.decrypt(payload)
        self.bytes_received += len(data)
        self.last_activity   = time.time()
        return data

    def close(self):
        if not self.active:
            return
        self.active = False
        try:
            Framing.send_frame(
                self.sock, MessageType.CLOSE, b""
            )
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def info(self) -> dict:
        return {
            "session_id":     self.session_id,
            "peer":           f"{self.peer_addr[0]}:{self.peer_addr[1]}",
            "cipher":         self.cipher,
            "cipher_details": self._crypto.info(),
            "created":        self.created_at,
            "last_activity":  self.last_activity,
            "bytes_sent":     self.bytes_sent,
            "bytes_received": self.bytes_received,
            "active":         self.active,
        }


class SessionManager:
    """Track every active Session and expire stale ones."""

    def __init__(self, timeout: int = 3600):
        self.sessions: dict[str, Session] = {}
        self.timeout  = timeout
        self._lock    = threading.Lock()
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(
            target=self._cleanup_loop, daemon=True
        ).start()

    def stop(self):
        self._running = False
        with self._lock:
            for s in list(self.sessions.values()):
                s.close()
            self.sessions.clear()

    def add(self, session: Session):
        with self._lock:
            self.sessions[session.session_id] = session

    def remove(self, sid: str):
        with self._lock:
            s = self.sessions.pop(sid, None)
        if s:
            s.close()

    def get(self, sid: str) -> Session | None:
        with self._lock:
            return self.sessions.get(sid)

    def all_info(self) -> list[dict]:
        with self._lock:
            return [s.info() for s in self.sessions.values()]

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for s in self.sessions.values() if s.active)

    def _cleanup_loop(self):
        while self._running:
            time.sleep(30)
            now     = time.time()
            expired = []
            with self._lock:
                for sid, s in self.sessions.items():
                    if now - s.last_activity > self.timeout:
                        expired.append(sid)
            for sid in expired:
                logger.info("Expiring session %s", sid)
                self.remove(sid)