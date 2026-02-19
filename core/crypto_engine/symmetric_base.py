"""
Abstract base class for all symmetric ciphers in SecureCrypt.

Every cipher (AES-GCM, ChaCha20, 3DES, Camellia, Blowfish …)
implements this interface so the Session layer and GUI can treat
them uniformly.
"""

from abc import ABC, abstractmethod


class SymmetricCipher(ABC):
    """
    Unified interface for symmetric encryption.

    encrypt() returns a self-contained blob:
        AEAD ciphers  → nonce + ciphertext_with_tag
        CBC  ciphers  → iv + ciphertext + hmac_sha256
        CTR  ciphers  → nonce + ciphertext + hmac_sha256

    decrypt() accepts that blob and returns plaintext.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext → self-contained encrypted blob."""

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt blob produced by encrypt() → plaintext."""

    @property
    @abstractmethod
    def cipher_name(self) -> str:
        """Human-readable name, e.g. 'AES-256-GCM'."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Encryption key size in bytes."""

    @property
    @abstractmethod
    def iv_size(self) -> int:
        """IV / nonce size in bytes."""

    @property
    @abstractmethod
    def is_aead(self) -> bool:
        """True if cipher has built-in authentication (GCM, Poly1305)."""

    @property
    def key_size_bits(self) -> int:
        return self.key_size * 8

    def info(self) -> dict:
        """Return cipher metadata for GUI display."""
        return {
            "name":          self.cipher_name,
            "key_bits":      self.key_size_bits,
            "iv_bytes":      self.iv_size,
            "aead":          self.is_aead,
            "auth_method":   "Built-in" if self.is_aead else "HMAC-SHA256",
        }