from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

class KeyManager:

    def generate_rsa_keypair(self, size=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )
        return private_key, private_key.public_key()

    def save_private_key(self, private_key, filepath, password=None):
        enc_algo = (
            serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
        )

        with open(filepath, "wb") as f:
            f.write(pem)

    def load_private_key(self, filepath, password=None):
        with open(filepath, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password,
                backend=default_backend()
            )
