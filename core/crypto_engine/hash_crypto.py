from cryptography.hazmat.primitives import hashes, hmac

class HashCrypto:

    def sha256(self, data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()

    def sha512(self, data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA512())
        digest.update(data)
        return digest.finalize()

    def hmac_sha256(self, data: bytes, key: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()
