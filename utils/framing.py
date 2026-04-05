"""
Length-prefixed binary framing for the SecureCrypt wire protocol.

Frame layout:
    [4 bytes – payload length (big-endian)]
    [1 byte  – message type]
    [N bytes – payload]
"""

import struct


class MessageType:
    # ── Existing (tunnel/proxy) ─────────────────────────────────
    HANDSHAKE_HELLO    = 0x01
    HANDSHAKE_RESPONSE = 0x02
    HANDSHAKE_FINISH   = 0x03
    DATA               = 0x10
    KEEPALIVE          = 0x20
    CLOSE              = 0xFF

    # ── New: Relay / E2E messaging ──────────────────────────────
    RELAY              = 0x30    # relay control messages (JSON)
    PEER_MESSAGE       = 0x31   # E2E encrypted peer message
    FILE_META          = 0x40   # file transfer metadata
    FILE_CHUNK         = 0x41   # encrypted file chunk
    FILE_COMPLETE      = 0x42   # file transfer complete signal
    FILE_ACK           = 0x43   # file receipt acknowledgment


class Framing:
    HEADER_SIZE      = 5
    MAX_PAYLOAD_SIZE = 16 * 1024 * 1024          # 16 MiB

    @staticmethod
    def create_frame(msg_type: int, payload: bytes) -> bytes:
        header = struct.pack("!IB", len(payload), msg_type)
        return header + payload

    @staticmethod
    def parse_header(header: bytes) -> tuple[int, int]:
        if len(header) < Framing.HEADER_SIZE:
            raise ValueError("Header too short")
        length, msg_type = struct.unpack("!IB", header[:Framing.HEADER_SIZE])
        if length > Framing.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {length}")
        return length, msg_type

    @staticmethod
    def _recv_exact(sock, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def recv_frame(sock) -> tuple[int, bytes]:
        header            = Framing._recv_exact(sock, Framing.HEADER_SIZE)
        length, msg_type  = Framing.parse_header(header)
        payload           = Framing._recv_exact(sock, length) if length else b""
        return msg_type, payload

    @staticmethod
    def send_frame(sock, msg_type: int, payload: bytes):
        sock.sendall(Framing.create_frame(msg_type, payload))