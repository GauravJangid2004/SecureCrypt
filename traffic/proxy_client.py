import socket
from traffic.session_manager import SessionManager
from core.crypto_engine.aes_crypto import AESCrypto

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

class SecureProxyClient:
    def __init__(self):
        self.session_mgr = SessionManager()

    def connect(self):
        self.session_id, key = self.session_mgr.create_session()
        self.aes = AESCrypto(key)

        self.sock = socket.socket()
        self.sock.connect((SERVER_HOST, SERVER_PORT))

        # Send session ID
        self.sock.sendall(self.session_id.encode())

    def send_data(self, data: bytes):
        encrypted = self.aes.encrypt_bytes(data)
        self.sock.sendall(encrypted)
        return self.aes.decrypt_bytes(self.sock.recv(4096))

    def close(self):
        self.sock.close()
