import os


class Settings:
    """Centralised application configuration."""

    # ── application ──────────────────────────────────────────────
    APP_NAME    = "SecureCrypt"
    APP_VERSION = "1.0.0"

    # ── paths ────────────────────────────────────────────────────
    BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    KEYS_DIR     = os.path.join(BASE_DIR, "keys")
    STORAGE_FILE = os.path.join(BASE_DIR, "secure_storage.enc")
    LOG_FILE     = os.path.join(BASE_DIR, "securecrypt.log")

    # ── network ──────────────────────────────────────────────────
    PROXY_HOST   = "127.0.0.1"
    PROXY_PORT   = 8080
    TUNNEL_HOST  = "0.0.0.0"
    TUNNEL_PORT  = 9090
    BUFFER_SIZE  = 65536

    # ── crypto defaults ──────────────────────────────────────────
    DEFAULT_CIPHER = "AES-256-GCM"
    RSA_KEY_SIZE   = 4096
    ECC_CURVE      = "SECP384R1"
    AES_KEY_SIZE   = 32          # 256 bits

    # ── session ──────────────────────────────────────────────────
    SESSION_TIMEOUT   = 3600     # seconds
    HANDSHAKE_TIMEOUT = 30       # seconds

    # ── logging ──────────────────────────────────────────────────
    LOG_LEVEL = "DEBUG"