# """
# Custom ECDH handshake protocol (TLS-like, but over the SecureCrypt
# framing layer).

# Flow
# ----
# 1. Client  → HELLO   (supported ciphers, ephemeral EC pub-key, nonce)
# 2. Server  → RESPONSE(chosen cipher, ephemeral EC pub-key, nonce)
# 3. Client  → FINISH  (HMAC proof)
# 4. Server  → FINISH  (HMAC proof)

# Both sides derive the same 256-bit session key via ECDH + HKDF.
# """

# import json, os, time, logging
# from cryptography.hazmat.primitives import serialization

# from core.crypto_engine import ECCCrypto, HashCrypto
# from utils.framing      import Framing, MessageType

# logger = logging.getLogger("SecureCrypt.Handshake")


# class HandshakeProtocol:
#     SUPPORTED_CIPHERS      = ["AES-256-GCM"]
#     SUPPORTED_KEY_EXCHANGE = ["ECDH-SECP384R1"]

#     def __init__(self):
#         self.session_key: bytes | None = None
#         self.cipher:      str   | None = None
#         self.peer_id:     str   | None = None

#     # ── client side ──────────────────────────────────────────────
#     def client_hello(self, sock) -> tuple[bytes, str]:
#         """Run the client side of the handshake; return *(session_key, cipher)*."""
#         sock.settimeout(30)

#         # 1 — generate ephemeral EC key-pair
#         ecc = ECCCrypto("SECP384R1")
#         ecc.generate_keys()
#         client_nonce = os.urandom(32)

#         hello = {
#             "version":           "1.0",
#             "ciphers":           self.SUPPORTED_CIPHERS,
#             "key_exchange":      self.SUPPORTED_KEY_EXCHANGE,
#             "client_public_key": ecc.export_public_key().decode(),
#             "client_nonce":      client_nonce.hex(),
#             "timestamp":         int(time.time()),
#         }
#         Framing.send_frame(sock, MessageType.HANDSHAKE_HELLO,
#                            json.dumps(hello).encode())

#         # 2 — receive server response
#         msg_type, payload = Framing.recv_frame(sock)
#         if msg_type != MessageType.HANDSHAKE_RESPONSE:
#             raise RuntimeError("Expected HANDSHAKE_RESPONSE")
#         resp = json.loads(payload.decode())

#         server_pub = serialization.load_pem_public_key(
#             resp["server_public_key"].encode())
#         server_nonce  = bytes.fromhex(resp["server_nonce"])
#         combined      = client_nonce + server_nonce

#         self.session_key = ecc.derive_shared_key(
#             server_pub, key_length=32, salt=combined,
#             info=b"securecrypt-session-key")
#         self.cipher  = resp["selected_cipher"]
#         self.peer_id = resp.get("server_id", "unknown")

#         # 3 — send client FINISH
#         verify = HashCrypto.hmac_sha256(
#             self.session_key, b"client-finished" + combined)
#         Framing.send_frame(sock, MessageType.HANDSHAKE_FINISH,
#                            json.dumps({"verify": verify.hex()}).encode())

#         # 4 — receive server FINISH
#         msg_type, payload = Framing.recv_frame(sock)
#         if msg_type != MessageType.HANDSHAKE_FINISH:
#             raise RuntimeError("Expected server FINISH")
#         srv_fin  = json.loads(payload.decode())
#         expected = HashCrypto.hmac_sha256(
#             self.session_key, b"server-finished" + combined)
#         if bytes.fromhex(srv_fin["verify"]) != expected:
#             raise RuntimeError("Server FINISH verification failed")

#         sock.settimeout(None)
#         logger.info("Client handshake complete — cipher=%s", self.cipher)
#         return self.session_key, self.cipher

#     # ── server side ──────────────────────────────────────────────
#     def server_hello(self, sock,
#                      server_id: str = "securecrypt-server"
#                      ) -> tuple[bytes, str]:
#         """Run the server side of the handshake; return *(session_key, cipher)*."""
#         sock.settimeout(30)

#         # 1 — receive client HELLO
#         msg_type, payload = Framing.recv_frame(sock)
#         if msg_type != MessageType.HANDSHAKE_HELLO:
#             raise RuntimeError("Expected HANDSHAKE_HELLO")
#         hello = json.loads(payload.decode())

#         ts = hello.get("timestamp", 0)
#         if abs(time.time() - ts) > 300:
#             raise RuntimeError("Handshake timestamp too old")

#         # 2 — generate ephemeral key, choose cipher
#         ecc = ECCCrypto("SECP384R1")
#         ecc.generate_keys()

#         selected = None
#         for c in self.SUPPORTED_CIPHERS:
#             if c in hello["ciphers"]:
#                 selected = c; break
#         if selected is None:
#             raise RuntimeError("No common cipher")

#         server_nonce = os.urandom(32)
#         client_nonce = bytes.fromhex(hello["client_nonce"])
#         combined     = client_nonce + server_nonce

#         client_pub = serialization.load_pem_public_key(
#             hello["client_public_key"].encode())

#         self.session_key = ecc.derive_shared_key(
#             client_pub, key_length=32, salt=combined,
#             info=b"securecrypt-session-key")
#         self.cipher  = selected
#         self.peer_id = "client"

#         resp = {
#             "version":           "1.0",
#             "selected_cipher":   selected,
#             "server_public_key": ecc.export_public_key().decode(),
#             "server_nonce":      server_nonce.hex(),
#             "server_id":         server_id,
#             "timestamp":         int(time.time()),
#         }
#         Framing.send_frame(sock, MessageType.HANDSHAKE_RESPONSE,
#                            json.dumps(resp).encode())

#         # 3 — receive client FINISH
#         msg_type, payload = Framing.recv_frame(sock)
#         if msg_type != MessageType.HANDSHAKE_FINISH:
#             raise RuntimeError("Expected client FINISH")
#         cli_fin  = json.loads(payload.decode())
#         expected = HashCrypto.hmac_sha256(
#             self.session_key, b"client-finished" + combined)
#         if bytes.fromhex(cli_fin["verify"]) != expected:
#             raise RuntimeError("Client FINISH verification failed")

#         # 4 — send server FINISH
#         verify = HashCrypto.hmac_sha256(
#             self.session_key, b"server-finished" + combined)
#         Framing.send_frame(sock, MessageType.HANDSHAKE_FINISH,
#                            json.dumps({"verify": verify.hex()}).encode())

#         sock.settimeout(None)
#         logger.info("Server handshake complete — cipher=%s", self.cipher)
#         return self.session_key, self.cipher





"""
Custom ECDH handshake protocol with multi-cipher negotiation.

Flow
----
1. Client  → HELLO   (supported ciphers list, ephemeral EC pub, nonce)
2. Server  → RESPONSE(chosen cipher, ephemeral EC pub, nonce)
3. Client  → FINISH  (HMAC proof)
4. Server  → FINISH  (HMAC proof)

Both sides derive a 32-byte session key via ECDH + HKDF.
The CipherFactory then creates the negotiated cipher.
"""

import json
import os
import time
import logging
from cryptography.hazmat.primitives import serialization

from core.crypto_engine import ECCCrypto, HashCrypto, CipherFactory
from utils.framing      import Framing, MessageType

logger = logging.getLogger("SecureCrypt.Handshake")


class HandshakeProtocol:
    """
    ECDH key exchange with cipher negotiation.

    SUPPORTED_CIPHERS is ordered by preference (best first).
    During negotiation the server picks the first cipher that
    both sides support.
    """

    SUPPORTED_CIPHERS = CipherFactory.list_ciphers()
    # e.g. ["AES-256-GCM", "CHACHA20-POLY1305", "AES-192-GCM",
    #        "AES-128-GCM", "AES-256-CBC", ... ]

    SUPPORTED_KEY_EXCHANGE = ["ECDH-SECP384R1"]

    def __init__(self):
        self.session_key: bytes | None = None
        self.cipher:      str   | None = None
        self.peer_id:     str   | None = None

    # ── client side ──────────────────────────────────────────────

    def client_hello(self, sock,
                     preferred_ciphers: list[str] | None = None
                     ) -> tuple[bytes, str]:
        """
        Run the client side of the handshake.

        Parameters
        ----------
        sock : socket
            Connected TCP socket to the server.
        preferred_ciphers : list[str] | None
            Override the default cipher preference list.

        Returns
        -------
        (session_key, cipher_name)
        """
        sock.settimeout(30)
        ciphers = preferred_ciphers or self.SUPPORTED_CIPHERS

        # 1 — generate ephemeral EC key-pair
        ecc = ECCCrypto("SECP384R1")
        ecc.generate_keys()
        client_nonce = os.urandom(32)

        hello = {
            "version":           "2.0",
            "ciphers":           ciphers,
            "key_exchange":      self.SUPPORTED_KEY_EXCHANGE,
            "client_public_key": ecc.export_public_key().decode(),
            "client_nonce":      client_nonce.hex(),
            "timestamp":         int(time.time()),
        }
        Framing.send_frame(
            sock, MessageType.HANDSHAKE_HELLO,
            json.dumps(hello).encode(),
        )

        # 2 — receive server response
        msg_type, payload = Framing.recv_frame(sock)
        if msg_type != MessageType.HANDSHAKE_RESPONSE:
            raise RuntimeError("Expected HANDSHAKE_RESPONSE")
        resp = json.loads(payload.decode())

        server_pub = serialization.load_pem_public_key(
            resp["server_public_key"].encode()
        )
        server_nonce = bytes.fromhex(resp["server_nonce"])
        combined     = client_nonce + server_nonce

        self.session_key = ecc.derive_shared_key(
            server_pub, key_length=32, salt=combined,
            info=b"securecrypt-session-key",
        )
        self.cipher  = resp["selected_cipher"]
        self.peer_id = resp.get("server_id", "unknown")

        # Verify the selected cipher is in our list
        if self.cipher not in ciphers:
            raise RuntimeError(
                f"Server selected unsupported cipher: {self.cipher}"
            )

        # 3 — send client FINISH
        verify = HashCrypto.hmac_sha256(
            self.session_key, b"client-finished" + combined
        )
        Framing.send_frame(
            sock, MessageType.HANDSHAKE_FINISH,
            json.dumps({"verify": verify.hex()}).encode(),
        )

        # 4 — receive server FINISH
        msg_type, payload = Framing.recv_frame(sock)
        if msg_type != MessageType.HANDSHAKE_FINISH:
            raise RuntimeError("Expected server FINISH")
        srv_fin  = json.loads(payload.decode())
        expected = HashCrypto.hmac_sha256(
            self.session_key, b"server-finished" + combined
        )
        if bytes.fromhex(srv_fin["verify"]) != expected:
            raise RuntimeError("Server FINISH verification failed")

        sock.settimeout(None)
        logger.info(
            "Client handshake complete — cipher=%s",
            self.cipher,
        )
        return self.session_key, self.cipher

    # ── server side ──────────────────────────────────────────────

    def server_hello(self, sock,
                     server_id: str = "securecrypt-server",
                     allowed_ciphers: list[str] | None = None,
                     ) -> tuple[bytes, str]:
        """
        Run the server side of the handshake.

        Parameters
        ----------
        sock : socket
            Accepted TCP socket from client.
        server_id : str
            Identifier sent to client.
        allowed_ciphers : list[str] | None
            Override which ciphers the server will accept.

        Returns
        -------
        (session_key, cipher_name)
        """
        sock.settimeout(30)
        server_ciphers = allowed_ciphers or self.SUPPORTED_CIPHERS

        # 1 — receive client HELLO
        msg_type, payload = Framing.recv_frame(sock)
        if msg_type != MessageType.HANDSHAKE_HELLO:
            raise RuntimeError("Expected HANDSHAKE_HELLO")
        hello = json.loads(payload.decode())

        ts = hello.get("timestamp", 0)
        if abs(time.time() - ts) > 300:
            raise RuntimeError("Handshake timestamp too old")

        # 2 — negotiate cipher (server preference order)
        client_ciphers = hello.get("ciphers", ["AES-256-GCM"])
        selected = None
        for sc in server_ciphers:
            if sc in client_ciphers:
                selected = sc
                break
        if selected is None:
            raise RuntimeError(
                f"No common cipher. "
                f"Server supports: {server_ciphers}, "
                f"Client supports: {client_ciphers}"
            )

        # Generate ephemeral key
        ecc = ECCCrypto("SECP384R1")
        ecc.generate_keys()

        server_nonce = os.urandom(32)
        client_nonce = bytes.fromhex(hello["client_nonce"])
        combined     = client_nonce + server_nonce

        client_pub = serialization.load_pem_public_key(
            hello["client_public_key"].encode()
        )
        self.session_key = ecc.derive_shared_key(
            client_pub, key_length=32, salt=combined,
            info=b"securecrypt-session-key",
        )
        self.cipher  = selected
        self.peer_id = "client"

        resp = {
            "version":           "2.0",
            "selected_cipher":   selected,
            "server_public_key": ecc.export_public_key().decode(),
            "server_nonce":      server_nonce.hex(),
            "server_id":         server_id,
            "timestamp":         int(time.time()),
            "available_ciphers": server_ciphers,
        }
        Framing.send_frame(
            sock, MessageType.HANDSHAKE_RESPONSE,
            json.dumps(resp).encode(),
        )

        # 3 — receive client FINISH
        msg_type, payload = Framing.recv_frame(sock)
        if msg_type != MessageType.HANDSHAKE_FINISH:
            raise RuntimeError("Expected client FINISH")
        cli_fin  = json.loads(payload.decode())
        expected = HashCrypto.hmac_sha256(
            self.session_key, b"client-finished" + combined
        )
        if bytes.fromhex(cli_fin["verify"]) != expected:
            raise RuntimeError("Client FINISH verification failed")

        # 4 — send server FINISH
        verify = HashCrypto.hmac_sha256(
            self.session_key, b"server-finished" + combined
        )
        Framing.send_frame(
            sock, MessageType.HANDSHAKE_FINISH,
            json.dumps({"verify": verify.hex()}).encode(),
        )

        sock.settimeout(None)
        logger.info(
            "Server handshake complete — cipher=%s (from %d options)",
            self.cipher, len(client_ciphers),
        )
        return self.session_key, self.cipher