"""
Encrypted key-value store backed by AES-256-GCM + PBKDF2.
"""

import json, os
from core.crypto_engine import AESCrypto, HashCrypto


class SecureStorage:
    """Persist sensitive data in an AES-GCM encrypted file."""

    def __init__(self, storage_path: str, password: str):
        self.storage_path = storage_path
        self._password    = password.encode()
        self._data: dict  = {}
        self._load()

    # ── internal ─────────────────────────────────────────────────
    def _derive_key(self, salt: bytes) -> bytes:
        _, key = HashCrypto.pbkdf2(self._password, salt=salt,
                                   iterations=600_000, key_length=32)
        return key

    def _load(self):
        if not os.path.exists(self.storage_path):
            self._data = {}
            return
        with open(self.storage_path, "rb") as f:
            raw = f.read()
        if len(raw) < 28:                       # salt(16) + nonce(12)
            self._data = {}
            return
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        key = self._derive_key(salt)
        aes = AESCrypto(key=key)
        pt  = aes.decrypt_gcm(nonce, ct)
        self._data = json.loads(pt.decode())

    def _save(self):
        salt = os.urandom(16)
        key  = self._derive_key(salt)
        aes  = AESCrypto(key=key)
        pt   = json.dumps(self._data).encode()
        nonce, ct = aes.encrypt_gcm(pt)
        with open(self.storage_path, "wb") as f:
            f.write(salt + nonce + ct)

    # ── public API ───────────────────────────────────────────────
    def set(self, key: str, value: str):
        self._data[key] = value;  self._save()

    def get(self, key: str, default=None) -> str | None:
        return self._data.get(key, default)

    def delete(self, key: str):
        self._data.pop(key, None);  self._save()

    def list_keys(self) -> list[str]:
        return list(self._data.keys())

    def clear(self):
        self._data = {};  self._save()