"""
ChaCha20-Poly1305 — modern AEAD stream cipher.

Designed by Daniel J. Bernstein. Excellent performance on devices
without hardware AES acceleration (ARM phones, older CPUs).

Key:   32 bytes (256 bits)
Nonce: 12 bytes (96 bits)
Tag:   16 bytes (128 bits) — included in ciphertext by library
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .symmetric_base import SymmetricCipher


class ChaCha20Cipher(SymmetricCipher):
    """
    ChaCha20-Poly1305 AEAD cipher.

    Output format:  [nonce 12B][ciphertext + Poly1305 tag 16B]
    """
    NONCE_SIZE = 12
    KEY_SIZE   = 32

    def __init__(self, key: bytes):
        if len(key) != self.KEY_SIZE:
            raise ValueError(
                f"ChaCha20 key must be 32 bytes, got {len(key)}"
            )
        self._key    = key
        self._chacha = ChaCha20Poly1305(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        ct    = self._chacha.encrypt(nonce, plaintext, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:self.NONCE_SIZE]
        ct    = data[self.NONCE_SIZE:]
        return self._chacha.decrypt(nonce, ct, None)

    @property
    def cipher_name(self) -> str:
        return "CHACHA20-POLY1305"

    @property
    def key_size(self) -> int:
        return self.KEY_SIZE

    @property
    def iv_size(self) -> int:
        return self.NONCE_SIZE

    @property
    def is_aead(self) -> bool:
        return True

    def info(self) -> dict:
        base = super().info()
        base["security_note"] = (
            "ChaCha20-Poly1305 is recommended for devices without "
            "AES-NI hardware support. Same security as AES-256-GCM."
        )
        return base