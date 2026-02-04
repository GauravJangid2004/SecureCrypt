from .hybrid_crypto import HybridCrypto

hybrid = HybridCrypto()

message = "SecureCrypt Hybrid Encryption Test"
encrypted = hybrid.encrypt(message)

print("\n--- ENCRYPTED PAYLOAD ---")
print(encrypted)

decrypted = hybrid.decrypt(encrypted)
print("\n--- DECRYPTED MESSAGE ---")
print(decrypted)
