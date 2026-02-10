"""
Elliptic-Curve cryptography — ECDH key exchange + ECDSA signing.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECCCrypto:
    """ECDH key agreement + ECDSA signing."""

    CURVES = {
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1(),
    }

    def __init__(self, curve_name: str = "SECP384R1"):
        self.curve       = self.CURVES.get(curve_name, ec.SECP384R1())
        self.private_key = None
        self.public_key  = None

    # ── key generation ───────────────────────────────────────────
    def generate_keys(self):
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key  = self.private_key.public_key()
        return self.private_key, self.public_key

    # ── ECDH ─────────────────────────────────────────────────────
    def derive_shared_key(self, peer_public_key,
                          key_length: int = 32,
                          salt: bytes | None = None,
                          info: bytes = b"securecrypt-ecdh") -> bytes:
        shared = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            info=info,
        ).derive(shared)

    # ── ECDSA ────────────────────────────────────────────────────
    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, message: bytes, signature: bytes,
               public_key=None) -> bool:
        key = public_key or self.public_key
        try:
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
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