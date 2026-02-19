"""
Blowfish block cipher — CBC mode with HMAC-SHA256.

Designed by Bruce Schneier (1993). Included for educational
purposes and legacy compatibility.

Key:  4–56 bytes (we default to 16 = 128 bits)
Block: 64 bits (8 bytes)

⚠ Blowfish may be deprecated in newer cryptography versions.
   This module handles that gracefully.
"""

import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .symmetric_base import SymmetricCipher

logger = logging.getLogger("SecureCrypt.Blowfish")

# ── Graceful import ──────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
    BLOWFISH_AVAILABLE = True
except (ImportError, AttributeError):
    BLOWFISH_AVAILABLE = False
    logger.warning(
        "Blowfish not available in this cryptography version"
    )


class BlowfishCBCCipher(SymmetricCipher):
    """
    Blowfish-CBC with Encrypt-then-MAC (HMAC-SHA256).

    Output format:  [IV 8B][ciphertext padded][HMAC 32B]
    """
    IV_SIZE    = 8
    BLOCK_BITS = 64
    HMAC_SIZE  = 32

    def __init__(self, key: bytes, mac_key: bytes):
        if not BLOWFISH_AVAILABLE:
            raise RuntimeError(
                "Blowfish is not available in this version of the "
                "cryptography library. Use AES or ChaCha20 instead."
            )
        if not (4 <= len(key) <= 56):
            raise ValueError(
                f"Blowfish key must be 4–56 bytes, got {len(key)}"
            )
        self._key     = key
        self._mac_key = mac_key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv     = os.urandom(self.IV_SIZE)
        padder = sym_padding.PKCS7(self.BLOCK_BITS).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc    = Cipher(
            Blowfish(self._key), modes.CBC(iv)
        ).encryptor()
        ct  = enc.update(padded) + enc.finalize()
        mac = self._compute_hmac(iv + ct)
        return iv + ct + mac

    def decrypt(self, data: bytes) -> bytes:
        mac = data[-self.HMAC_SIZE:]
        iv  = data[:self.IV_SIZE]
        ct  = data[self.IV_SIZE:-self.HMAC_SIZE]
        self._verify_hmac(iv + ct, mac)
        dec    = Cipher(
            Blowfish(self._key), modes.CBC(iv)
        ).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpad  = sym_padding.PKCS7(self.BLOCK_BITS).unpadder()
        return unpad.update(padded) + unpad.finalize()

    def _compute_hmac(self, data: bytes) -> bytes:
        h = crypto_hmac.HMAC(self._mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def _verify_hmac(self, data: bytes, expected: bytes):
        h = crypto_hmac.HMAC(self._mac_key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(expected)
        except InvalidSignature:
            raise ValueError("Blowfish HMAC verification failed")

    @property
    def cipher_name(self) -> str:
        return f"BLOWFISH-{len(self._key) * 8}-CBC"

    @property
    def key_size(self) -> int:
        return len(self._key)

    @property
    def iv_size(self) -> int:
        return self.IV_SIZE

    @property
    def is_aead(self) -> bool:
        return False

    def info(self) -> dict:
        base = super().info()
        base["security_note"] = (
            "Blowfish has a 64-bit block size — vulnerable to "
            "birthday attacks on large data. Use AES for production."
        )
        return base