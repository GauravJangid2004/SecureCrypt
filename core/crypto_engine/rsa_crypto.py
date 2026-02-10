"""
RSA asymmetric encryption, signing and key serialisation.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization


class RSACrypto:
    """RSA-OAEP encryption + PSS signing."""

    def __init__(self, key_size: int = 4096):
        self.key_size    = key_size
        self.private_key = None
        self.public_key  = None

    # ── key generation ───────────────────────────────────────────
    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key

    # ── encrypt / decrypt ────────────────────────────────────────
    def encrypt(self, plaintext: bytes, public_key=None) -> bytes:
        key = public_key or self.public_key
        return key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # ── sign / verify ────────────────────────────────────────────
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

    def verify(self, message: bytes, signature: bytes,
               public_key=None) -> bool:
        key = public_key or self.public_key
        try:
            key.verify(
                signature,
                message,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    # ── serialisation ────────────────────────────────────────────
    def export_private_key(self, password: bytes | None = None) -> bytes:
        enc = (serialization.BestAvailableEncryption(password)
               if password else serialization.NoEncryption())
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    def export_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_private_key(self, pem_data: bytes,
                         password: bytes | None = None):
        self.private_key = serialization.load_pem_private_key(
            pem_data, password=password)
        self.public_key = self.private_key.public_key()

    def load_public_key(self, pem_data: bytes):
        self.public_key = serialization.load_pem_public_key(pem_data)