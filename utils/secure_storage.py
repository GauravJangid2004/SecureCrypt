from cryptography.fernet import Fernet
import os

class SecureStorage:

    def __init__(self, master_key=None):
        self.master_key = master_key or Fernet.generate_key()
        self.cipher = Fernet(self.master_key)

    def encrypt_data(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt_data(self, token: bytes) -> bytes:
        return self.cipher.decrypt(token)

    def save_encrypted(self, filepath, data: bytes):
        encrypted = self.encrypt_data(data)
        with open(filepath, "wb") as f:
            f.write(encrypted)

    def load_encrypted(self, filepath):
        with open(filepath, "rb") as f:
            return self.decrypt_data(f.read())
