"""
Generate, persist and load RSA / ECC key-pairs.
"""

import os
from core.crypto_engine import RSACrypto, ECCCrypto
from config.settings import Settings


class KeyManager:

    def __init__(self, keys_dir: str | None = None):
        self.keys_dir = keys_dir or Settings.KEYS_DIR
        os.makedirs(self.keys_dir, exist_ok=True)

    # ── RSA ──────────────────────────────────────────────────────
    def generate_rsa_keypair(self, name: str = "server",
                             key_size: int = 4096,
                             password: bytes | None = None):
        r = RSACrypto(key_size=key_size)
        r.generate_keys()
        priv = os.path.join(self.keys_dir, f"{name}_private.pem")
        pub  = os.path.join(self.keys_dir, f"{name}_public.pem")
        with open(priv, "wb") as f:
            f.write(r.export_private_key(password))
        with open(pub, "wb") as f:
            f.write(r.export_public_key())
        return priv, pub

    def load_rsa_private(self, name: str = "server",
                         password: bytes | None = None) -> RSACrypto:
        path = os.path.join(self.keys_dir, f"{name}_private.pem")
        with open(path, "rb") as f:
            pem = f.read()
        r = RSACrypto()
        r.load_private_key(pem, password)
        return r

    def load_rsa_public(self, name: str = "server") -> RSACrypto:
        path = os.path.join(self.keys_dir, f"{name}_public.pem")
        with open(path, "rb") as f:
            pem = f.read()
        r = RSACrypto()
        r.load_public_key(pem)
        return r

    # ── ECC ──────────────────────────────────────────────────────
    def generate_ecc_keypair(self, name: str = "server",
                             curve: str = "SECP384R1",
                             password: bytes | None = None):
        e = ECCCrypto(curve_name=curve)
        e.generate_keys()
        priv = os.path.join(self.keys_dir, f"{name}_ecc_private.pem")
        pub  = os.path.join(self.keys_dir, f"{name}_ecc_public.pem")
        with open(priv, "wb") as f:
            f.write(e.export_private_key(password))
        with open(pub, "wb") as f:
            f.write(e.export_public_key())
        return priv, pub

    def load_ecc_private(self, name: str = "server",
                         password: bytes | None = None) -> ECCCrypto:
        path = os.path.join(self.keys_dir, f"{name}_ecc_private.pem")
        with open(path, "rb") as f:
            pem = f.read()
        e = ECCCrypto()
        e.load_private_key(pem, password)
        return e

    def load_ecc_public(self, name: str = "server") -> ECCCrypto:
        path = os.path.join(self.keys_dir, f"{name}_ecc_public.pem")
        with open(path, "rb") as f:
            pem = f.read()
        e = ECCCrypto()
        e.load_public_key(pem)
        return e

    # ── helpers ──────────────────────────────────────────────────
    def key_exists(self, name: str, key_type: str = "rsa") -> bool:
        if key_type == "rsa":
            priv = os.path.join(self.keys_dir, f"{name}_private.pem")
            pub  = os.path.join(self.keys_dir, f"{name}_public.pem")
        else:
            priv = os.path.join(self.keys_dir, f"{name}_ecc_private.pem")
            pub  = os.path.join(self.keys_dir, f"{name}_ecc_public.pem")
        return os.path.exists(priv) and os.path.exists(pub)

    def list_keys(self) -> list[str]:
        return [f for f in os.listdir(self.keys_dir)
                if f.endswith(".pem")]