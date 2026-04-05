import os


class Settings:
    APP_NAME    = "SecureCrypt"
    APP_VERSION = "2.0.0"

    BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    KEYS_DIR     = os.path.join(BASE_DIR, "keys")
    STORAGE_FILE = os.path.join(BASE_DIR, "secure_storage.enc")
    LOG_FILE     = os.path.join(BASE_DIR, "securecrypt.log")

    # ── Port Allocation ──────────────────────────────────────────
    PROXY_HOST   = "127.0.0.1"    # LOCAL ONLY — browser connects here
    PROXY_PORT   = 8080           # HTTP proxy for browser

    TUNNEL_HOST  = "0.0.0.0"     # Exit node listens on all interfaces
    TUNNEL_PORT  = 9090           # Encrypted tunnel / exit node

    RELAY_HOST   = "0.0.0.0"     # E2E relay server
    RELAY_PORT   = 9091           # E2E messaging relay

    BUFFER_SIZE  = 65536

    # ── Crypto ───────────────────────────────────────────────────
    DEFAULT_CIPHER = "AES-256-GCM"
    RSA_KEY_SIZE   = 4096
    ECC_CURVE      = "SECP384R1"
    AES_KEY_SIZE   = 32

    # ── Session ──────────────────────────────────────────────────
    SESSION_TIMEOUT   = 3600
    HANDSHAKE_TIMEOUT = 30

    LOG_LEVEL = "DEBUG"