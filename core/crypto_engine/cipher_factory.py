"""
CipherFactory — unified cipher creation and discovery.

Usage:
    cipher = CipherFactory.create("AES-256-GCM", session_key)
    encrypted = cipher.encrypt(b"hello")
    plaintext = cipher.decrypt(encrypted)

    # List all available ciphers
    for name in CipherFactory.list_ciphers():
        print(CipherFactory.get_info(name))
"""

import logging
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes

from .symmetric_base    import SymmetricCipher
from .aes_crypto        import AESGCMCipher, AESCBCCipher, AESCTRCipher
from .chacha_crypto     import ChaCha20Cipher
from .des_crypto        import TripleDESCipher
from .camellia_crypto   import CamelliaCBCCipher
from .blowfish_crypto   import BlowfishCBCCipher, BLOWFISH_AVAILABLE

logger = logging.getLogger("SecureCrypt.CipherFactory")


class CipherFactory:
    """
    Create any supported cipher by name.

    The factory handles:
    - Key truncation (session key is always 32 bytes from ECDH)
    - MAC key derivation for non-AEAD ciphers
    - Graceful fallback if a cipher is unavailable
    """

    # ── Registry ─────────────────────────────────────────────────
    # Each entry: (CipherClass, enc_key_size, is_aead)
    _REGISTRY: dict[str, dict] = {
        # AEAD ciphers (built-in authentication)
        "AES-128-GCM": {
            "class":    AESGCMCipher,
            "key_size": 16,
            "aead":     True,
            "category": "AEAD",
            "security": "High (128-bit)",
            "speed":    "Very Fast (AES-NI)",
        },
        "AES-192-GCM": {
            "class":    AESGCMCipher,
            "key_size": 24,
            "aead":     True,
            "category": "AEAD",
            "security": "High (192-bit)",
            "speed":    "Very Fast (AES-NI)",
        },
        "AES-256-GCM": {
            "class":    AESGCMCipher,
            "key_size": 32,
            "aead":     True,
            "category": "AEAD",
            "security": "Very High (256-bit)",
            "speed":    "Fast (AES-NI)",
        },
        "CHACHA20-POLY1305": {
            "class":    ChaCha20Cipher,
            "key_size": 32,
            "aead":     True,
            "category": "AEAD",
            "security": "Very High (256-bit)",
            "speed":    "Fast (no AES-NI needed)",
        },
        # CBC + HMAC ciphers
        "AES-128-CBC": {
            "class":    AESCBCCipher,
            "key_size": 16,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "High (128-bit)",
            "speed":    "Fast",
        },
        "AES-192-CBC": {
            "class":    AESCBCCipher,
            "key_size": 24,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "High (192-bit)",
            "speed":    "Fast",
        },
        "AES-256-CBC": {
            "class":    AESCBCCipher,
            "key_size": 32,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "Very High (256-bit)",
            "speed":    "Fast",
        },
        # CTR + HMAC
        "AES-256-CTR": {
            "class":    AESCTRCipher,
            "key_size": 32,
            "aead":     False,
            "category": "CTR + HMAC",
            "security": "Very High (256-bit)",
            "speed":    "Fast",
        },
        # Legacy / educational
        "3DES-CBC": {
            "class":    TripleDESCipher,
            "key_size": 24,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "Medium (~112-bit)",
            "speed":    "Slow",
        },
        "CAMELLIA-128-CBC": {
            "class":    CamelliaCBCCipher,
            "key_size": 16,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "High (128-bit)",
            "speed":    "Fast",
        },
        "CAMELLIA-256-CBC": {
            "class":    CamelliaCBCCipher,
            "key_size": 32,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "Very High (256-bit)",
            "speed":    "Fast",
        },
    }

    # Conditionally add Blowfish
    if BLOWFISH_AVAILABLE:
        _REGISTRY["BLOWFISH-128-CBC"] = {
            "class":    BlowfishCBCCipher,
            "key_size": 16,
            "aead":     False,
            "category": "CBC + HMAC",
            "security": "Low (64-bit block)",
            "speed":    "Fast",
        }

    # ── Factory method ───────────────────────────────────────────

    @classmethod
    def create(cls, cipher_name: str,
               key_material: bytes) -> SymmetricCipher:
        """
        Create a cipher instance.

        Parameters
        ----------
        cipher_name : str
            One of the registered cipher names (e.g. "AES-256-GCM").
        key_material : bytes
            At least 32 bytes of key material from ECDH/HKDF.
            The factory truncates to the cipher's required key size
            and derives a separate MAC key for non-AEAD ciphers.

        Returns
        -------
        SymmetricCipher
            Ready-to-use cipher instance.
        """
        if cipher_name not in cls._REGISTRY:
            raise ValueError(
                f"Unknown cipher: {cipher_name}. "
                f"Available: {cls.list_ciphers()}"
            )

        info     = cls._REGISTRY[cipher_name]
        key_size = info["key_size"]

        if len(key_material) < key_size:
            raise ValueError(
                f"{cipher_name} needs {key_size} bytes of key "
                f"material, got {len(key_material)}"
            )

        enc_key = key_material[:key_size]

        if info["aead"]:
            cipher = info["class"](enc_key)
        else:
            mac_key = cls._derive_mac_key(key_material)
            cipher  = info["class"](enc_key, mac_key)

        logger.debug(
            "Created cipher: %s (key=%d bits, aead=%s)",
            cipher.cipher_name, cipher.key_size_bits, info["aead"],
        )
        return cipher

    # ── MAC key derivation ───────────────────────────────────────

    @staticmethod
    def _derive_mac_key(key_material: bytes) -> bytes:
        """
        Derive a 32-byte MAC key from the full key material.
        Uses HMAC-SHA256(key_material, constant) so the MAC key
        is cryptographically independent of the encryption key.
        """
        h = crypto_hmac.HMAC(key_material, hashes.SHA256())
        h.update(b"securecrypt-mac-key-derivation-v1")
        return h.finalize()

    # ── Discovery ────────────────────────────────────────────────

    @classmethod
    def list_ciphers(cls) -> list[str]:
        """Return all registered cipher names, ordered by preference."""
        preferred_order = [
            "AES-256-GCM",
            "CHACHA20-POLY1305",
            "AES-192-GCM",
            "AES-128-GCM",
            "AES-256-CBC",
            "AES-256-CTR",
            "AES-192-CBC",
            "AES-128-CBC",
            "CAMELLIA-256-CBC",
            "CAMELLIA-128-CBC",
            "3DES-CBC",
            "BLOWFISH-128-CBC",
        ]
        return [c for c in preferred_order if c in cls._REGISTRY]

    @classmethod
    def list_aead_ciphers(cls) -> list[str]:
        """Return only AEAD cipher names."""
        return [
            name for name, info in cls._REGISTRY.items()
            if info["aead"]
        ]

    @classmethod
    def get_info(cls, cipher_name: str) -> dict:
        """Return metadata for a cipher."""
        if cipher_name not in cls._REGISTRY:
            raise ValueError(f"Unknown cipher: {cipher_name}")
        info = cls._REGISTRY[cipher_name]
        return {
            "name":      cipher_name,
            "key_bits":  info["key_size"] * 8,
            "aead":      info["aead"],
            "category":  info["category"],
            "security":  info["security"],
            "speed":     info["speed"],
        }

    @classmethod
    def get_all_info(cls) -> list[dict]:
        """Return metadata for all ciphers (for GUI table)."""
        return [
            cls.get_info(name) for name in cls.list_ciphers()
        ]

    @classmethod
    def is_available(cls, cipher_name: str) -> bool:
        return cipher_name in cls._REGISTRY

    @classmethod
    def get_required_key_size(cls, cipher_name: str) -> int:
        """Return required key size in bytes."""
        if cipher_name not in cls._REGISTRY:
            raise ValueError(f"Unknown cipher: {cipher_name}")
        return cls._REGISTRY[cipher_name]["key_size"]

    @classmethod
    def recommend(cls, data_size_mb: float = 1.0,
                  has_aes_ni: bool = True) -> str:
        """
        Recommend the best cipher based on conditions.

        Parameters
        ----------
        data_size_mb : float
            Expected data throughput in MB.
        has_aes_ni : bool
            Whether the CPU has AES-NI instructions.
        """
        if not has_aes_ni:
            return "CHACHA20-POLY1305"
        if data_size_mb > 100:
            return "AES-128-GCM"     # fastest AES
        return "AES-256-GCM"          # best security