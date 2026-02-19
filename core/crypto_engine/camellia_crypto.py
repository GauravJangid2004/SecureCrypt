"""
Camellia block cipher — CBC mode with HMAC-SHA256.

Developed by Mitsubishi Electric and NTT (Japan).
Equivalent security to AES — approved by ISO/IEC, NESSIE, CRYPTREC.

Key sizes: 128, 192, 256 bits
Block size: 128 bits (same as AES)
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .symmetric_base import SymmetricCipher


class CamelliaCBCCipher(SymmetricCipher):
    """
    Camellia-CBC with Encrypt-then-MAC (HMAC-SHA256).

    Output format:  [IV 16B][ciphertext padded][HMAC 32B]
    """
    IV_SIZE    = 16
    BLOCK_BITS = 128
    HMAC_SIZE  = 32

    def __init__(self, key: bytes, mac_key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"Camellia key must be 16, 24, or 32 bytes, "
                f"got {len(key)}"
            )
        self._key     = key
        self._mac_key = mac_key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv     = os.urandom(self.IV_SIZE)
        padder = sym_padding.PKCS7(self.BLOCK_BITS).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc    = Cipher(
            algorithms.Camellia(self._key), modes.CBC(iv)
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
            algorithms.Camellia(self._key), modes.CBC(iv)
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
            raise ValueError("Camellia HMAC verification failed")

    @property
    def cipher_name(self) -> str:
        return f"CAMELLIA-{len(self._key) * 8}-CBC"

    @property
    def key_size(self) -> int:
        return len(self._key)

    @property
    def iv_size(self) -> int:
        return self.IV_SIZE

    @property
    def is_aead(self) -> bool:
        return False