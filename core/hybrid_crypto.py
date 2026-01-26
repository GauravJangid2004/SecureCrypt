from .aes_crypto import AESCrypto
from .rsa_crypto import RSACrypto
import base64

class HybridCrypto:
    def __init__(self):
        self.rsa = RSACrypto()

    def encrypt(self, plaintext: str) -> dict:
        # Step 1: Encrypt data using AES
        aes = AESCrypto()
        encrypted_data = aes.encrypt(plaintext)

        # Step 2: Encrypt AES key using RSA
        encrypted_key = self.rsa.encrypt(
            base64.b64decode(encrypted_data["key"])
        )

        return {
            "encrypted_data": encrypted_data,
            "encrypted_key": encrypted_key,
            "public_key": self.rsa.public_key.decode()
        }

    def decrypt(self, encrypted_payload: dict) -> str:
        # Step 1: Decrypt AES key using RSA private key
        decrypted_key = self.rsa.decrypt(
            encrypted_payload["encrypted_key"]
        )

        encrypted_data = encrypted_payload["encrypted_data"]
        encrypted_data["key"] = base64.b64encode(decrypted_key).decode()

        # Step 2: Decrypt data using AES
        aes = AESCrypto()
        return aes.decrypt(encrypted_data)
