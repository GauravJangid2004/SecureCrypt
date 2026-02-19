# """
# AES symmetric encryption — GCM (authenticated) and CBC modes.
# """

# import os
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding as sym_padding


# class AESCrypto:
#     """AES-256 encryption helper (GCM & CBC)."""

#     def __init__(self, key: bytes | None = None, key_size: int = 32):
#         self.key = key if key else os.urandom(key_size)

#     # ── AES-GCM (recommended) ───────────────────────────────────
#     def encrypt_gcm(self, plaintext: bytes,
#                     associated_data: bytes | None = None) -> tuple[bytes, bytes]:
#         """Return *(nonce, ciphertext+tag)*."""
#         nonce  = os.urandom(12)
#         aesgcm = AESGCM(self.key)
#         ct     = aesgcm.encrypt(nonce, plaintext, associated_data)
#         return nonce, ct

#     def decrypt_gcm(self, nonce: bytes, ciphertext: bytes,
#                     associated_data: bytes | None = None) -> bytes:
#         aesgcm = AESGCM(self.key)
#         return aesgcm.decrypt(nonce, ciphertext, associated_data)

#     # ── AES-CBC + PKCS-7 ────────────────────────────────────────
#     def encrypt_cbc(self, plaintext: bytes) -> tuple[bytes, bytes]:
#         """Return *(iv, ciphertext)*."""
#         iv      = os.urandom(16)
#         padder  = sym_padding.PKCS7(128).padder()
#         padded  = padder.update(plaintext) + padder.finalize()
#         cipher  = Cipher(algorithms.AES(self.key), modes.CBC(iv))
#         enc     = cipher.encryptor()
#         ct      = enc.update(padded) + enc.finalize()
#         return iv, ct

#     def decrypt_cbc(self, iv: bytes, ciphertext: bytes) -> bytes:
#         cipher   = Cipher(algorithms.AES(self.key), modes.CBC(iv))
#         dec      = cipher.decryptor()
#         padded   = dec.update(ciphertext) + dec.finalize()
#         unpadder = sym_padding.PKCS7(128).unpadder()
#         return unpadder.update(padded) + unpadder.finalize()

#     # ── helpers ──────────────────────────────────────────────────
#     def get_key(self) -> bytes:
#         return self.key



"""
AES symmetric encryption — GCM, CBC, CTR with multiple key sizes.

Backward-compatible: the original AESCrypto class is unchanged.
New unified classes (AESGCMCipher, AESCBCCipher, AESCTRCipher)
implement the SymmetricCipher interface.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .symmetric_base import SymmetricCipher


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Original AESCrypto — UNCHANGED (used by secure_storage, etc.)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AESCrypto:
    """AES-256 encryption helper (GCM & CBC) — original API."""

    def __init__(self, key: bytes | None = None, key_size: int = 32):
        self.key = key if key else os.urandom(key_size)

    # ── AES-GCM ──────────────────────────────────────────────────
    def encrypt_gcm(self, plaintext: bytes,
                    associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        nonce  = os.urandom(12)
        aesgcm = AESGCM(self.key)
        ct     = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ct

    def decrypt_gcm(self, nonce: bytes, ciphertext: bytes,
                    associated_data: bytes | None = None) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    # ── AES-CBC + PKCS7 ─────────────────────────────────────────
    def encrypt_cbc(self, plaintext: bytes) -> tuple[bytes, bytes]:
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

    def get_key(self) -> bytes:
        return self.key


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HMAC helper mixin for non-AEAD modes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class _HMACMixin:
    """Provides Encrypt-then-MAC for non-AEAD cipher modes."""
    HMAC_SIZE = 32

    def _compute_hmac(self, mac_key: bytes, data: bytes) -> bytes:
        h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def _verify_hmac(self, mac_key: bytes, data: bytes,
                     expected: bytes):
        h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(expected)
        except InvalidSignature:
            raise ValueError(
                "HMAC verification failed — data may be tampered"
            )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  AES-GCM (AEAD) — 128 / 192 / 256 bit keys
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AESGCMCipher(SymmetricCipher):
    """
    AES in Galois/Counter Mode (authenticated encryption).

    Output format:  [nonce 12B][ciphertext + GCM tag 16B]
    """
    NONCE_SIZE = 12

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes, got {len(key)}"
            )
        self._key    = key
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        ct    = self._aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ct                       # nonce ‖ ct+tag

    def decrypt(self, data: bytes) -> bytes:
        nonce = data[:self.NONCE_SIZE]
        ct    = data[self.NONCE_SIZE:]
        return self._aesgcm.decrypt(nonce, ct, None)

    @property
    def cipher_name(self) -> str:
        return f"AES-{len(self._key) * 8}-GCM"

    @property
    def key_size(self) -> int:
        return len(self._key)

    @property
    def iv_size(self) -> int:
        return self.NONCE_SIZE

    @property
    def is_aead(self) -> bool:
        return True


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  AES-CBC + HMAC-SHA256 — 128 / 192 / 256 bit keys
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AESCBCCipher(SymmetricCipher, _HMACMixin):
    """
    AES in CBC mode with Encrypt-then-MAC (HMAC-SHA256).

    Output format:  [IV 16B][ciphertext padded][HMAC 32B]
    """
    IV_SIZE    = 16
    BLOCK_BITS = 128

    def __init__(self, key: bytes, mac_key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes, got {len(key)}"
            )
        self._key     = key
        self._mac_key = mac_key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv     = os.urandom(self.IV_SIZE)
        padder = sym_padding.PKCS7(self.BLOCK_BITS).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(self._key), modes.CBC(iv))
        ct     = cipher.encryptor().update(padded) + \
                 cipher.encryptor().finalize()
        # Fix: use single encryptor
        enc = Cipher(algorithms.AES(self._key), modes.CBC(iv)).encryptor()
        ct  = enc.update(padded) + enc.finalize()
        mac = self._compute_hmac(self._mac_key, iv + ct)
        return iv + ct + mac

    def decrypt(self, data: bytes) -> bytes:
        mac = data[-self.HMAC_SIZE:]
        iv  = data[:self.IV_SIZE]
        ct  = data[self.IV_SIZE:-self.HMAC_SIZE]
        self._verify_hmac(self._mac_key, iv + ct, mac)
        dec    = Cipher(
            algorithms.AES(self._key), modes.CBC(iv)
        ).decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpad  = sym_padding.PKCS7(self.BLOCK_BITS).unpadder()
        return unpad.update(padded) + unpad.finalize()

    @property
    def cipher_name(self) -> str:
        return f"AES-{len(self._key) * 8}-CBC"

    @property
    def key_size(self) -> int:
        return len(self._key)

    @property
    def iv_size(self) -> int:
        return self.IV_SIZE

    @property
    def is_aead(self) -> bool:
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  AES-CTR + HMAC-SHA256
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AESCTRCipher(SymmetricCipher, _HMACMixin):
    """
    AES in Counter mode with Encrypt-then-MAC.
    No padding needed (stream-cipher behaviour).

    Output format:  [nonce 16B][ciphertext][HMAC 32B]
    """
    NONCE_SIZE = 16

    def __init__(self, key: bytes, mac_key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError(
                f"AES key must be 16, 24, or 32 bytes, got {len(key)}"
            )
        self._key     = key
        self._mac_key = mac_key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(self.NONCE_SIZE)
        enc   = Cipher(
            algorithms.AES(self._key), modes.CTR(nonce)
        ).encryptor()
        ct  = enc.update(plaintext) + enc.finalize()
        mac = self._compute_hmac(self._mac_key, nonce + ct)
        return nonce + ct + mac

    def decrypt(self, data: bytes) -> bytes:
        mac   = data[-self.HMAC_SIZE:]
        nonce = data[:self.NONCE_SIZE]
        ct    = data[self.NONCE_SIZE:-self.HMAC_SIZE]
        self._verify_hmac(self._mac_key, nonce + ct, mac)
        dec = Cipher(
            algorithms.AES(self._key), modes.CTR(nonce)
        ).decryptor()
        return dec.update(ct) + dec.finalize()

    @property
    def cipher_name(self) -> str:
        return f"AES-{len(self._key) * 8}-CTR"

    @property
    def key_size(self) -> int:
        return len(self._key)

    @property
    def iv_size(self) -> int:
        return self.NONCE_SIZE

    @property
    def is_aead(self) -> bool:
        return False