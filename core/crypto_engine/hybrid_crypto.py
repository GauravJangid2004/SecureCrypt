import os
from .aes_crypto import AESCrypto
from .rsa_crypto import RSACrypto

class HybridCrypto:

    def __init__(self):
        self.aes = AESCrypto()
        self.rsa = RSACrypto()

    def encrypt(self, data: bytes, public_key):
        aes_key = os.urandom(32)
        encrypted_data = self.aes.encrypt(data, aes_key)
        encrypted_key = self.rsa.encrypt(aes_key, public_key)

        return encrypted_key, encrypted_data

    def decrypt(self, encrypted_key, encrypted_data, private_key):
        aes_key = self.rsa.decrypt(encrypted_key, private_key)
        return self.aes.decrypt(encrypted_data, aes_key)
