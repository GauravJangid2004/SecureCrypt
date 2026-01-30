import socket
import threading
from core.crypto_engine.aes_crypto import AESCrypto
from traffic.session_manager import SessionManager

HOST = "127.0.0.1"
PORT = 9000

session_mgr = SessionManager()

def handle_client(conn):
    try:
        session_id = conn.recv(1024).decode()
        key = session_mgr.get_key(session_id)

        aes = AESCrypto(key)

        while True:
            encrypted = conn.recv(4096)
            if not encrypted:
                break

            decrypted = aes.decrypt_bytes(encrypted)
            print("[SERVER RECEIVED]:", decrypted.decode())

            # Echo response
            response = aes.encrypt_bytes(b"ACK")
            conn.sendall(response)

    finally:
        conn.close()

def start_server():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen()

    print("[+] Secure Tunnel Server Running")

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()

if __name__ == "__main__":
    start_server()
