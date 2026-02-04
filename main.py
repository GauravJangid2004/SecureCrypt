print("SecureCrypt initialized successfully")
print("Cryptography engine ready")


from traffic.proxy_client import SecureProxyClient

client = SecureProxyClient()
client.connect()

response = client.send_data(b"Hello Internet (Encrypted)")
print("Server replied:", response.decode())

client.close()
