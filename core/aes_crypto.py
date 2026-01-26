from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AESCrypto:
    def __init__(self, key=None):
        self.key = key or get_random_bytes(32)  # AES-256

    def encrypt(self, plaintext: str) -> dict:
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(cipher.nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "key": base64.b64encode(self.key).decode()
        }

    def decrypt(self, enc_data: dict) -> str:
        key = base64.b64decode(enc_data["key"])
        nonce = base64.b64decode(enc_data["nonce"])
        tag = base64.b64decode(enc_data["tag"])
        ciphertext = base64.b64decode(enc_data["ciphertext"])

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return plaintext.decode()
