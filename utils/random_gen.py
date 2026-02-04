import os

class SecureRandom:

    @staticmethod
    def random_bytes(length=32):
        return os.urandom(length)

    @staticmethod
    def random_key_aes():
        return os.urandom(32)  # AES-256

    @staticmethod
    def random_iv():
        return os.urandom(16)
