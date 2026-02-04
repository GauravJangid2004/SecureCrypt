from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
from .aes_crypto import AESCrypto

class ECCCrypto:

    def generate_keys(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        return private_key, private_key.public_key()

    def derive_shared_key(self, private_key, peer_public_key):
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"securecrypt-ecc",
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key

    def encrypt(self, plaintext: bytes, sender_private_key, receiver_public_key):
        aes = AESCrypto()
        shared_key = self.derive_shared_key(sender_private_key, receiver_public_key)
        return aes.encrypt(plaintext, shared_key)

    def decrypt(self, ciphertext: bytes, receiver_private_key, sender_public_key):
        aes = AESCrypto()
        shared_key = self.derive_shared_key(receiver_private_key, sender_public_key)
        return aes.decrypt(ciphertext, shared_key)
