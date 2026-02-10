"""
Hashing, HMAC, and key-derivation utilities.
"""

import os
import hashlib
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class HashCrypto:
    """Static helpers for hashing, HMAC, PBKDF2 and Scrypt."""

    # ── hashes ───────────────────────────────────────────────────
    @staticmethod
    def sha256(data: bytes) -> bytes:
        d = hashes.Hash(hashes.SHA256())
        d.update(data)
        return d.finalize()

    @staticmethod
    def sha512(data: bytes) -> bytes:
        d = hashes.Hash(hashes.SHA512())
        d.update(data)
        return d.finalize()

    @staticmethod
    def blake2b(data: bytes, digest_size: int = 64) -> bytes:
        return hashlib.blake2b(data, digest_size=digest_size).digest()

    # ── HMAC ─────────────────────────────────────────────────────
    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected: bytes) -> bool:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(expected)
            return True
        except Exception:
            return False

    # ── KDFs ─────────────────────────────────────────────────────
    @staticmethod
    def pbkdf2(password: bytes, salt: bytes | None = None,
               iterations: int = 600_000,
               key_length: int = 32) -> tuple[bytes, bytes]:
        """Return *(salt, derived_key)*."""
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
        )
        return salt, kdf.derive(password)

    @staticmethod
    def scrypt_derive(password: bytes, salt: bytes | None = None,
                      key_length: int = 32) -> tuple[bytes, bytes]:
        if salt is None:
            salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=key_length, n=2**14, r=8, p=1)
        return salt, kdf.derive(password)