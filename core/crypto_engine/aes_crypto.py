"""
AES symmetric encryption — GCM (authenticated) and CBC modes.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


class AESCrypto:
    """AES-256 encryption helper (GCM & CBC)."""

    def __init__(self, key: bytes | None = None, key_size: int = 32):
        self.key = key if key else os.urandom(key_size)

    # ── AES-GCM (recommended) ───────────────────────────────────
    def encrypt_gcm(self, plaintext: bytes,
                    associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Return *(nonce, ciphertext+tag)*."""
        nonce  = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ct     = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ct

    def decrypt_gcm(self, nonce: bytes, ciphertext: bytes,
                    associated_data: bytes | None = None) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    # ── AES-CBC + PKCS-7 ────────────────────────────────────────
    def encrypt_cbc(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Return *(iv, ciphertext)*."""
        iv      = os.urandom(16)
        padder  = sym_padding.PKCS7(128).padder()
        padded  = padder.update(plaintext) + padder.finalize()
        cipher  = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        enc     = cipher.encryptor()
        ct      = enc.update(padded) + enc.finalize()
        return iv, ct

    def decrypt_cbc(self, iv: bytes, ciphertext: bytes) -> bytes:
        cipher   = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        dec      = cipher.decryptor()
        padded   = dec.update(ciphertext) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # ── helpers ──────────────────────────────────────────────────
    def get_key(self) -> bytes:
        return self.key