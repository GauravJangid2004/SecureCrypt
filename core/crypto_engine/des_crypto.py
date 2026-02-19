"""
Triple DES (3DES / DESede) — CBC mode with HMAC-SHA256.

3DES applies DES three times with a 168-bit key (24 bytes).
Included for legacy compatibility and educational comparison.
Block size: 64 bits (8 bytes).
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .symmetric_base import SymmetricCipher


class TripleDESCipher(SymmetricCipher):
    """
    3DES-CBC with Encrypt-then-MAC (HMAC-SHA256).

    Output format:  [IV 8B][ciphertext padded][HMAC 32B]

    Key: 24 bytes (three 8-byte DES keys)
    IV:  8 bytes  (DES block size)
    """
    IV_SIZE    = 8
    KEY_SIZE   = 24
    BLOCK_BITS = 64      # DES block = 64 bits
    HMAC_SIZE  = 32

    def __init__(self, key: bytes, mac_key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(
                f"3DES key must be exactly 24 bytes, got {len(key)}"
            )
        self._key     = key
        self._mac_key = mac_key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv     = os.urandom(self.IV_SIZE)
        padder = sym_padding.PKCS7(self.BLOCK_BITS).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc    = Cipher(
            algorithms.TripleDES(self._key), modes.CBC(iv)
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
            algorithms.TripleDES(self._key), modes.CBC(iv)
        ).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpad  = sym_padding.PKCS7(self.BLOCK_BITS).unpadder()
        return unpad.update(padded) + unpad.finalize()

    # ── HMAC helpers ─────────────────────────────────────────────
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
            raise ValueError("3DES HMAC verification failed")

    @property
    def cipher_name(self) -> str:
        return "3DES-CBC"

    @property
    def key_size(self) -> int:
        return self.KEY_SIZE

    @property
    def iv_size(self) -> int:
        return self.IV_SIZE

    @property
    def is_aead(self) -> bool:
        return False

    def info(self) -> dict:
        base = super().info()
        base["security_note"] = (
            "3DES is considered legacy. Effective security is ~112 bits. "
            "Use AES-256-GCM or ChaCha20 for new deployments."
        )
        return base