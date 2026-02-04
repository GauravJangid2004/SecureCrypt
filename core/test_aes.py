from aes_crypto import AESCrypto

aes = AESCrypto()

data = "SecureCrypt First Encryption Test"
encrypted = aes.encrypt(data)

print("Encrypted:", encrypted)

decrypted = aes.decrypt(encrypted)
print("Decrypted:", decrypted)
