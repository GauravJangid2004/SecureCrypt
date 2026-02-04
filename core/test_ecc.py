from core.crypto_engine.ecc_crypto import ECCCrypto

ecc = ECCCrypto()

priv1, pub1 = ecc.generate_keys()
priv2, pub2 = ecc.generate_keys()

msg = b"ECC Secure Message"
enc = ecc.encrypt(msg, priv1, pub2)
dec = ecc.decrypt(enc, priv2, pub1)

assert msg == dec
print("ECC encryption works!")
