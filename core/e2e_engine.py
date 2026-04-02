"""
SecureCrypt End-to-End Encryption Engine.

Combines:
  • RSA-4096 identity keys (signing / verification)
  • ECDH ephemeral keys   (session key agreement)
  • CipherFactory         (symmetric encryption — any cipher)
  • HMAC-SHA256           (key derivation / integrity)

Security properties:
  • Forward secrecy       — ephemeral ECDH keys per session
  • Authentication        — RSA signatures on every message
  • MITM protection       — ECDH public keys signed with RSA identity
  • Cipher agility        — any CipherFactory cipher can be used
"""

import os
import json
import time
import logging
import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization

from core.crypto_engine import (
    RSACrypto, ECCCrypto, HashCrypto, CipherFactory, SymmetricCipher,
)
from utils.random_gen import SecureRandom

logger = logging.getLogger("SecureCrypt.E2E")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  E2E Identity — your RSA keypair
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class E2EIdentity:
    """
    Represents this device's cryptographic identity.

    Contains:
      - RSA-4096 keypair for signing and verification
      - Username / display name
      - Identity fingerprint (SHA-256 of public key)
    """

    def __init__(self, username: str, rsa: RSACrypto | None = None):
        self.username = username
        self.rsa = rsa or RSACrypto(key_size=4096)
        if self.rsa.private_key is None:
            self.rsa.generate_keys()

    @property
    def public_key_pem(self) -> str:
        return self.rsa.export_public_key().decode()

    @property
    def private_key_pem(self) -> str:
        return self.rsa.export_private_key().decode()

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the RSA public key (for out-of-band verification)."""
        pub_bytes = self.rsa.export_public_key()
        digest = hashlib.sha256(pub_bytes).hexdigest().upper()
        # Format as groups of 4 for readability
        return " ".join(
            digest[i:i + 4] for i in range(0, len(digest), 4)
        )

    def sign(self, data: bytes) -> bytes:
        return self.rsa.sign(data)

    def save(self, private_path: str, public_path: str,
             password: bytes | None = None):
        with open(private_path, "wb") as f:
            f.write(self.rsa.export_private_key(password))
        with open(public_path, "wb") as f:
            f.write(self.rsa.export_public_key())

    @classmethod
    def load(cls, username: str, private_path: str,
             password: bytes | None = None) -> "E2EIdentity":
        rsa = RSACrypto()
        with open(private_path, "rb") as f:
            rsa.load_private_key(f.read(), password)
        return cls(username=username, rsa=rsa)

    def info(self) -> dict:
        return {
            "username":    self.username,
            "fingerprint": self.fingerprint,
            "key_size":    self.rsa.key_size,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  E2E Peer — the remote user's public identity
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class E2EPeer:
    """Stores a remote peer's public identity."""

    def __init__(self, username: str, rsa_public_pem: str):
        self.username = username
        self.rsa = RSACrypto()
        self.rsa.load_public_key(rsa_public_pem.encode())

    @property
    def fingerprint(self) -> str:
        pub_bytes = self.rsa.export_public_key()
        digest = hashlib.sha256(pub_bytes).hexdigest().upper()
        return " ".join(
            digest[i:i + 4] for i in range(0, len(digest), 4)
        )

    def verify(self, data: bytes, signature: bytes) -> bool:
        return self.rsa.verify(data, signature)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  E2E Session — active encrypted session with a peer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class E2ESession:
    """
    An active end-to-end encrypted session between two peers.

    Created after ECDH key exchange + RSA verification.
    """

    def __init__(
        self,
        session_id: str,
        local_identity: E2EIdentity,
        peer: E2EPeer,
        session_key: bytes,
        cipher_name: str,
    ):
        self.session_id     = session_id
        self.local_identity = local_identity
        self.peer           = peer
        self.session_key    = session_key
        self.cipher_name    = cipher_name
        self.created_at     = time.time()
        self.message_count  = 0
        self.active         = True

        self._cipher: SymmetricCipher = CipherFactory.create(
            cipher_name, session_key
        )
        logger.info(
            "E2E session %s with %s — cipher: %s",
            session_id, peer.username, cipher_name,
        )

    def encrypt_and_sign(self, plaintext: bytes) -> dict:
        """
        Encrypt plaintext with session cipher, then sign with RSA.

        Returns dict with encrypted_data (hex) and signature (hex).
        """
        encrypted = self._cipher.encrypt(plaintext)
        signature = self.local_identity.sign(encrypted)
        self.message_count += 1
        return {
            "encrypted_data": encrypted.hex(),
            "signature":      signature.hex(),
            "cipher":         self.cipher_name,
            "msg_index":      self.message_count,
        }

    def decrypt_and_verify(self, encrypted_hex: str,
                           signature_hex: str) -> tuple[bytes, bool]:
        """
        Verify RSA signature, then decrypt.

        Returns (plaintext, signature_valid).
        """
        encrypted = bytes.fromhex(encrypted_hex)
        signature = bytes.fromhex(signature_hex)

        sig_valid = self.peer.verify(encrypted, signature)
        if not sig_valid:
            logger.warning(
                "SIGNATURE VERIFICATION FAILED from %s",
                self.peer.username,
            )

        plaintext = self._cipher.decrypt(encrypted)
        self.message_count += 1
        return plaintext, sig_valid

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Encrypt raw bytes (for file chunks)."""
        return self._cipher.encrypt(data)

    def decrypt_bytes(self, data: bytes) -> bytes:
        """Decrypt raw bytes (for file chunks)."""
        return self._cipher.decrypt(data)

    def sign_data(self, data: bytes) -> bytes:
        """RSA-sign arbitrary data (e.g., file hash)."""
        return self.local_identity.sign(data)

    def verify_signature(self, data: bytes,
                         signature: bytes) -> bool:
        """Verify peer's RSA signature."""
        return self.peer.verify(data, signature)

    def info(self) -> dict:
        return {
            "session_id":    self.session_id,
            "peer":          self.peer.username,
            "cipher":        self.cipher_name,
            "cipher_info":   self._cipher.info(),
            "created":       self.created_at,
            "messages":      self.message_count,
            "active":        self.active,
            "peer_fingerprint": self.peer.fingerprint,
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  E2E Engine — orchestrates identity, key exchange, sessions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class E2EEngine:
    """
    Main E2E engine — manages identity, peers, sessions.

    Usage:
        engine = E2EEngine("alice")
        engine.generate_identity()

        # Key exchange (Alice initiates)
        init_data = engine.create_key_exchange("bob", bob_rsa_pub_pem, "AES-256-GCM")
        # Send init_data to Bob through relay...

        # When Bob responds with his ECDH public key:
        session = engine.complete_key_exchange("bob", bob_response_data)

        # Now send encrypted + signed messages
        msg = session.encrypt_and_sign(b"Hello Bob!")
    """

    def __init__(self, username: str):
        self.identity: E2EIdentity | None = None
        self.username = username
        self.peers: dict[str, E2EPeer] = {}
        self.sessions: dict[str, E2ESession] = {}

        # Pending key exchanges
        self._pending_kex: dict[str, dict] = {}

    def generate_identity(self) -> E2EIdentity:
        """Generate a new RSA-4096 identity."""
        self.identity = E2EIdentity(self.username)
        logger.info(
            "Generated identity for %s — fingerprint: %s",
            self.username, self.identity.fingerprint[:20] + "…",
        )
        return self.identity

    def load_identity(self, private_key_path: str,
                      password: bytes | None = None) -> E2EIdentity:
        """Load identity from disk."""
        self.identity = E2EIdentity.load(
            self.username, private_key_path, password
        )
        return self.identity

    def save_identity(self, private_path: str, public_path: str,
                      password: bytes | None = None):
        if self.identity:
            self.identity.save(private_path, public_path, password)

    def add_peer(self, username: str, rsa_public_pem: str) -> E2EPeer:
        """Register a peer's public identity."""
        peer = E2EPeer(username, rsa_public_pem)
        self.peers[username] = peer
        logger.info(
            "Added peer %s — fingerprint: %s",
            username, peer.fingerprint[:20] + "…",
        )
        return peer

    # ── Key Exchange (Initiator Side) ────────────────────────────

    def create_key_exchange(
        self,
        peer_username: str,
        peer_rsa_pub_pem: str,
        cipher_name: str = "AES-256-GCM",
    ) -> dict:
        """
        Step 1: Create key exchange initiation data.

        Returns a dict to send to the peer through the relay.
        The ECDH public key is signed with our RSA identity
        to prevent MITM by the relay server.
        """
        if self.identity is None:
            raise RuntimeError("Generate identity first")

        # Add peer if not known
        if peer_username not in self.peers:
            self.add_peer(peer_username, peer_rsa_pub_pem)

        # Generate ephemeral ECDH keypair
        ecc = ECCCrypto("SECP384R1")
        ecc.generate_keys()
        nonce = os.urandom(32)

        ecc_pub_pem = ecc.export_public_key().decode()

        # Sign the ECDH public key + nonce with RSA identity
        sign_payload = (ecc_pub_pem + nonce.hex()).encode()
        signature = self.identity.sign(sign_payload)

        # Store pending exchange
        self._pending_kex[peer_username] = {
            "ecc":          ecc,
            "nonce":        nonce,
            "cipher_name":  cipher_name,
        }

        return {
            "action":          "key_exchange_init",
            "from_user":       self.username,
            "to_user":         peer_username,
            "ecc_public_key":  ecc_pub_pem,
            "nonce":           nonce.hex(),
            "signature":       signature.hex(),
            "rsa_public_key":  self.identity.public_key_pem,
            "cipher_name":     cipher_name,
            "timestamp":       int(time.time()),
        }

    # ── Key Exchange (Responder Side) ────────────────────────────

    def respond_key_exchange(self, init_data: dict) -> tuple[dict, E2ESession]:
        """
        Step 2: Respond to a key exchange initiation.

        Verifies the initiator's RSA signature on their ECDH key,
        generates our own ECDH keypair, derives the shared secret,
        and creates the E2E session.

        Returns (response_data_to_send, session).
        """
        if self.identity is None:
            raise RuntimeError("Generate identity first")

        peer_username    = init_data["from_user"]
        peer_rsa_pub_pem = init_data["rsa_public_key"]
        peer_ecc_pub_pem = init_data["ecc_public_key"]
        peer_nonce       = bytes.fromhex(init_data["nonce"])
        peer_signature   = bytes.fromhex(init_data["signature"])
        cipher_name      = init_data.get("cipher_name", "AES-256-GCM")

        # Add / update peer
        peer = self.add_peer(peer_username, peer_rsa_pub_pem)

        # Verify RSA signature on ECDH key (prevents relay MITM)
        sign_payload = (
            peer_ecc_pub_pem + init_data["nonce"]
        ).encode()
        if not peer.verify(sign_payload, peer_signature):
            raise RuntimeError(
                f"RSA signature verification FAILED for {peer_username}! "
                f"Possible MITM attack."
            )
        logger.info(
            "Verified RSA signature from %s ✓", peer_username
        )

        # Generate our ephemeral ECDH keypair
        ecc = ECCCrypto("SECP384R1")
        ecc.generate_keys()
        our_nonce = os.urandom(32)

        # Derive shared secret
        peer_ecc_pub = serialization.load_pem_public_key(
            peer_ecc_pub_pem.encode()
        )
        combined_nonce = peer_nonce + our_nonce
        session_key = ecc.derive_shared_key(
            peer_ecc_pub,
            key_length=32,
            salt=combined_nonce,
            info=b"securecrypt-e2e-session-key",
        )

        # Sign our ECDH key
        our_ecc_pub_pem = ecc.export_public_key().decode()
        our_sign_payload = (our_ecc_pub_pem + our_nonce.hex()).encode()
        our_signature = self.identity.sign(our_sign_payload)

        # Create session
        session_id = SecureRandom.generate_session_id()
        session = E2ESession(
            session_id=session_id,
            local_identity=self.identity,
            peer=peer,
            session_key=session_key,
            cipher_name=cipher_name,
        )
        self.sessions[peer_username] = session

        response = {
            "action":          "key_exchange_response",
            "from_user":       self.username,
            "to_user":         peer_username,
            "ecc_public_key":  our_ecc_pub_pem,
            "nonce":           our_nonce.hex(),
            "signature":       our_signature.hex(),
            "rsa_public_key":  self.identity.public_key_pem,
            "session_id":      session_id,
            "cipher_name":     cipher_name,
            "timestamp":       int(time.time()),
        }

        logger.info(
            "E2E session established with %s (responder)",
            peer_username,
        )
        return response, session

    # ── Key Exchange (Initiator Completion) ──────────────────────

    def complete_key_exchange(self, resp_data: dict) -> E2ESession:
        """
        Step 3: Complete key exchange using the responder's data.

        Called by the initiator after receiving the response.
        """
        peer_username    = resp_data["from_user"]
        peer_ecc_pub_pem = resp_data["ecc_public_key"]
        peer_nonce       = bytes.fromhex(resp_data["nonce"])
        peer_signature   = bytes.fromhex(resp_data["signature"])
        peer_rsa_pub_pem = resp_data["rsa_public_key"]
        cipher_name      = resp_data.get("cipher_name", "AES-256-GCM")

        if peer_username not in self._pending_kex:
            raise RuntimeError(
                f"No pending key exchange with {peer_username}"
            )

        pending = self._pending_kex.pop(peer_username)
        ecc         = pending["ecc"]
        our_nonce   = pending["nonce"]

        # Update peer
        peer = self.add_peer(peer_username, peer_rsa_pub_pem)

        # Verify RSA signature
        sign_payload = (
            peer_ecc_pub_pem + resp_data["nonce"]
        ).encode()
        if not peer.verify(sign_payload, peer_signature):
            raise RuntimeError(
                f"RSA signature verification FAILED for {peer_username}!"
            )
        logger.info(
            "Verified RSA signature from %s ✓", peer_username
        )

        # Derive shared secret (same as responder)
        peer_ecc_pub = serialization.load_pem_public_key(
            peer_ecc_pub_pem.encode()
        )
        combined_nonce = our_nonce + peer_nonce
        session_key = ecc.derive_shared_key(
            peer_ecc_pub,
            key_length=32,
            salt=combined_nonce,
            info=b"securecrypt-e2e-session-key",
        )

        session_id = resp_data.get(
            "session_id", SecureRandom.generate_session_id()
        )
        session = E2ESession(
            session_id=session_id,
            local_identity=self.identity,
            peer=peer,
            session_key=session_key,
            cipher_name=cipher_name,
        )
        self.sessions[peer_username] = session

        logger.info(
            "E2E session established with %s (initiator)",
            peer_username,
        )
        return session

    # ── Helpers ──────────────────────────────────────────────────

    def get_session(self, peer_username: str) -> E2ESession | None:
        return self.sessions.get(peer_username)

    def has_session(self, peer_username: str) -> bool:
        s = self.sessions.get(peer_username)
        return s is not None and s.active

    def close_session(self, peer_username: str):
        s = self.sessions.pop(peer_username, None)
        if s:
            s.active = False

    def list_sessions(self) -> list[dict]:
        return [s.info() for s in self.sessions.values()]