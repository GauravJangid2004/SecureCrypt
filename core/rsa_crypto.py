from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACrypto:
    def __init__(self, key_size=2048):
        self.key = RSA.generate(key_size)
        self.private_key = self.key.export_key()
        self.public_key = self.key.publickey().export_key()

    def encrypt(self, data: bytes) -> str:
        public_key = RSA.import_key(self.public_key)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(data)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encrypted_data: str) -> bytes:
        private_key = RSA.import_key(self.private_key)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted
