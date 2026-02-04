from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class AESCrypto:

    def encrypt(self, plaintext: bytes, key: bytes):
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv + ciphertext

    def decrypt(self, ciphertext: bytes, key: bytes):
        iv = ciphertext[:16]
        data = ciphertext[16:]

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext
