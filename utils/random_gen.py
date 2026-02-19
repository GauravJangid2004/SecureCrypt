"""
Cryptographically-secure random value generators.
"""

import os
import secrets


class SecureRandom:

    @staticmethod
    def generate_bytes(length: int) -> bytes:
        return os.urandom(length)

    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        return os.urandom(length)

    @staticmethod
    def generate_iv(length: int = 16) -> bytes:
        return os.urandom(length)

    @staticmethod
    def generate_token(length: int = 32) -> str:
        return secrets.token_hex(length)

    @staticmethod
    def generate_session_id() -> str:
        return secrets.token_hex(16)

    @staticmethod
    def generate_int(min_val: int, max_val: int) -> int:
        return secrets.randbelow(max_val - min_val + 1) + min_val