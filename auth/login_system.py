"""
SecureCrypt Zero Trust Login System
====================================
Zero Trust Policy:
  - Never trust, always verify
  - Every login requires full credential verification
  - Session tokens expire and rotate every 10 minutes
  - Multi-factor authentication enforced
  - Every action requires re-validation
  - Brute force protection with lockout
  - Cryptographic session tokens (no predictable IDs)
  - All events are audit-logged
"""

import os
import time
import json
import hmac
import hashlib
import secrets
import threading
import logging
import base64
from dataclasses import dataclass, field, asdict
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("SecureCrypt.Auth")

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────
KEY_ROTATION_INTERVAL   = 600        # 10 minutes in seconds
MAX_LOGIN_ATTEMPTS      = 5
LOCKOUT_DURATION        = 300        # 5 minutes
SESSION_IDLE_TIMEOUT    = 1800       # 30 minutes
TOKEN_BYTE_LENGTH       = 32         # 256-bit session token
PBKDF2_ITERATIONS       = 600_000    # NIST recommended
TOTP_WINDOW             = 1          # ±1 step tolerance
TOTP_STEP               = 30         # seconds per TOTP step

# ─────────────────────────────────────────────────────────────
# TOTP Helper Functions
# ─────────────────────────────────────────────────────────────

def hex_to_base32(hex_str: str) -> str:
    """Convert hex string to base32 (for Google Authenticator)."""
    secret_bytes = bytes.fromhex(hex_str)
    return base64.b32encode(secret_bytes).decode().rstrip('=')

def format_totp_display(hex_secret: str) -> str:
    """Format TOTP secret for display to user (base32)."""
    return hex_to_base32(hex_secret)

def generate_otpauth_uri(username: str, hex_secret: str, issuer: str = "SecureCrypt") -> str:
    """Generate otpauth:// URI for QR code generation (RFC 6238)."""
    base32_secret = hex_to_base32(hex_secret)
    return f"otpauth://totp/{issuer}:{username}?secret={base32_secret}&issuer={issuer}"

# ─────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────

@dataclass
class UserRecord:
    """Stored user record (passwords are NEVER stored in plaintext)."""
    username: str
    password_hash: str          # hex: PBKDF2-SHA256
    password_salt: str          # hex: 16 random bytes
    totp_secret: str            # hex: 20 random bytes (TOTP seed)
    created_at: float = field(default_factory=time.time)
    failed_attempts: int = 0
    locked_until: float = 0.0
    last_login: float = 0.0
    role: str = "user"          # "user" | "admin"
    active: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "UserRecord":
        return cls(**d)


@dataclass
class SessionToken:
    """
    A Zero-Trust session token.
    Rotates automatically every KEY_ROTATION_INTERVAL seconds.
    """
    username: str
    token: str                  # hex: 256-bit cryptographic token
    session_key: bytes          # 256-bit AES session key
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    rotation_count: int = 0     # how many times key has rotated
    ip_address: str = "unknown"
    authenticated: bool = True

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def idle_seconds(self) -> float:
        return time.time() - self.last_activity

    @property
    def needs_rotation(self) -> bool:
        return self.age_seconds >= KEY_ROTATION_INTERVAL

    @property
    def is_idle_timeout(self) -> bool:
        return self.idle_seconds >= SESSION_IDLE_TIMEOUT

    def rotate_key(self) -> bytes:
        """Generate new session key using HKDF-style derivation."""
        old_key = self.session_key
        rotation_info = (
            f"rotation-{self.rotation_count}-"
            f"{self.username}-{time.time()}"
        ).encode()
        # Derive new key from old key + rotation info
        new_key = hashlib.pbkdf2_hmac(
            "sha256",
            old_key + rotation_info,
            os.urandom(16),         # fresh salt every rotation
            iterations=10_000,      # lighter than login KDF (speed vs security balance)
            dklen=32,
        )
        self.session_key = new_key
        self.created_at = time.time()   # reset the rotation timer
        self.rotation_count += 1
        self.token = secrets.token_hex(TOKEN_BYTE_LENGTH)  # new token too
        logger.info(
            "[ZeroTrust] Session key rotated for '%s' "
            "(rotation #%d)",
            self.username, self.rotation_count,
        )
        return new_key

    def touch(self):
        """Update last_activity timestamp (Zero Trust continuous auth)."""
        self.last_activity = time.time()


@dataclass
class AuditEvent:
    """Immutable audit log entry."""
    timestamp: float
    event_type: str     # "LOGIN_OK", "LOGIN_FAIL", "LOGOUT",
                        # "KEY_ROTATED", "LOCKED", "ACCESS_DENIED"
    username: str
    ip_address: str
    details: str
    token_hint: str = ""  # first 8 chars of token (non-sensitive)


# ─────────────────────────────────────────────────────────────
# TOTP (Time-Based One-Time Password) — RFC 6238
# ─────────────────────────────────────────────────────────────

class TOTP:
    """
    Pure-Python TOTP implementation (RFC 6238).
    Uses SHA-1 HMAC as per the standard.
    """

    def __init__(self, secret_hex: str):
        self._secret = bytes.fromhex(secret_hex)

    def _hotp(self, counter: int) -> int:
        msg = counter.to_bytes(8, "big")
        h = hmac.new(self._secret, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = (
            (h[offset] & 0x7F) << 24
            | (h[offset + 1] & 0xFF) << 16
            | (h[offset + 2] & 0xFF) << 8
            | (h[offset + 3] & 0xFF)
        )
        return code % 1_000_000

    def now(self) -> str:
        """Return current 6-digit TOTP code."""
        counter = int(time.time()) // TOTP_STEP
        return f"{self._hotp(counter):06d}"

    def verify(self, code: str, window: int = TOTP_WINDOW) -> bool:
        """Verify code within ±window time steps."""
        counter = int(time.time()) // TOTP_STEP
        for delta in range(-window, window + 1):
            expected = f"{self._hotp(counter + delta):06d}"
            # Constant-time comparison
            if hmac.compare_digest(expected.encode(), code.encode()):
                return True
        return False


# ─────────────────────────────────────────────────────────────
# Zero Trust Login Manager
# ─────────────────────────────────────────────────────────────

class ZeroTrustLoginManager:
    """
    Zero Trust Authentication Manager for SecureCrypt.

    Principles enforced:
      1. Never trust — every request re-verified
      2. Always verify — cryptographic proof required
      3. Least privilege — sessions expire aggressively
      4. Key rotation — session keys reset every 10 minutes
      5. Audit everything — all events logged immutably
      6. Fail secure — any doubt → deny access
    """

    def __init__(self, storage_path: str = "auth_db.enc"):
        self._storage_path = storage_path
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, SessionToken] = {}
        self._audit_log: list[AuditEvent] = []
        self._lock = threading.RLock()
        self._running = False

        # Master key for encrypting the user database at rest
        self._master_key: Optional[bytes] = None

        self._load_users()
        self._start_rotation_daemon()

    # ─────────────────────────────────────────────────────────
    # Setup
    # ─────────────────────────────────────────────────────────

    def initialize(self, master_password: str):
        """
        Initialize the auth system with a master password.
        Must be called once before any other operation.
        """
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        self._master_key = kdf.derive(master_password.encode())
        logger.info("[ZeroTrust] Auth system initialized")

    def set_master_key_from_bytes(self, key: bytes):
        """Set master key directly (for testing)."""
        if len(key) != 32:
            raise ValueError("Master key must be 32 bytes")
        self._master_key = key

    # ─────────────────────────────────────────────────────────
    # User Management
    # ─────────────────────────────────────────────────────────

    def register_user(
        self,
        username: str,
        password: str,
        role: str = "user",
    ) -> str:
        """
        Register a new user.
        Returns the TOTP secret (display to user ONCE, then discard).
        """
        if not username or not password:
            raise ValueError("Username and password required")
        if len(password) < 12:
            raise ValueError(
                "Password must be at least 12 characters"
            )

        with self._lock:
            if username in self._users:
                raise ValueError(f"User '{username}' already exists")

            salt = os.urandom(16)
            pw_hash = self._hash_password(password, salt)
            totp_secret = secrets.token_hex(20)  # 20 bytes = 160-bit

            user = UserRecord(
                username=username,
                password_hash=pw_hash,
                password_salt=salt.hex(),
                totp_secret=totp_secret,
                role=role,
            )
            self._users[username] = user
            self._save_users()

            self._audit("REGISTER", username, "127.0.0.1",
                        f"User registered (role={role})")
            logger.info(
                "[ZeroTrust] User '%s' registered (role=%s)",
                username, role,
            )
            return totp_secret  # Show to user for authenticator app

    def change_password(
        self,
        token: str,
        old_password: str,
        new_password: str,
        ip: str = "unknown",
    ) -> bool:
        """Change password — requires valid session + old password."""
        session = self._validate_session(token, ip)
        if not session:
            return False

        if len(new_password) < 12:
            self._audit("CHANGE_PW_FAIL", session.username, ip,
                        "New password too short")
            return False

        with self._lock:
            user = self._users.get(session.username)
            if not user:
                return False

            # Verify old password (Zero Trust: re-authenticate)
            old_salt = bytes.fromhex(user.password_salt)
            if not self._verify_password(old_password, old_salt,
                                         user.password_hash):
                self._audit("CHANGE_PW_FAIL", session.username, ip,
                            "Old password incorrect")
                return False

            new_salt = os.urandom(16)
            user.password_hash = self._hash_password(new_password,
                                                       new_salt)
            user.password_salt = new_salt.hex()
            self._save_users()

            # Invalidate all existing sessions (force re-login)
            self._invalidate_user_sessions(session.username)

            self._audit("CHANGE_PW_OK", session.username, ip,
                        "Password changed — all sessions invalidated")
            return True

    # ─────────────────────────────────────────────────────────
    # Authentication — Zero Trust Login
    # ─────────────────────────────────────────────────────────

    def login(
        self,
        username: str,
        password: str,
        totp_code: str,
        ip: str = "unknown",
    ) -> Optional[str]:
        """
        Zero Trust Login.

        Requires:
          1. Valid username
          2. Correct password (PBKDF2-SHA256 verified)
          3. Valid TOTP code (time-based OTP)

        Returns session token string on success, None on failure.
        """
        with self._lock:
            # ── Step 1: User exists? ──────────────────────────
            user = self._users.get(username)
            if not user:
                # Constant-time dummy work to prevent timing attacks
                self._dummy_hash()
                self._audit("LOGIN_FAIL", username, ip,
                            "User not found")
                logger.warning(
                    "[ZeroTrust] Login failed — unknown user '%s' "
                    "from %s",
                    username, ip,
                )
                return None

            # ── Step 2: Account active? ───────────────────────
            if not user.active:
                self._audit("LOGIN_FAIL", username, ip,
                            "Account disabled")
                return None

            # ── Step 3: Brute-force lockout? ──────────────────
            if user.locked_until > time.time():
                remaining = int(user.locked_until - time.time())
                self._audit("LOGIN_FAIL", username, ip,
                            f"Account locked for {remaining}s")
                logger.warning(
                    "[ZeroTrust] Login blocked — '%s' locked "
                    "for %ds",
                    username, remaining,
                )
                return None

            # ── Step 4: Password verification ─────────────────
            pw_salt = bytes.fromhex(user.password_salt)
            if not self._verify_password(password, pw_salt,
                                          user.password_hash):
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = (
                        time.time() + LOCKOUT_DURATION
                    )
                    self._audit(
                        "LOCKED", username, ip,
                        f"Too many failures — locked {LOCKOUT_DURATION}s",
                    )
                    logger.warning(
                        "[ZeroTrust] Account '%s' LOCKED after "
                        "%d failures",
                        username, user.failed_attempts,
                    )
                else:
                    self._audit(
                        "LOGIN_FAIL", username, ip,
                        f"Bad password (attempt "
                        f"{user.failed_attempts}/{MAX_LOGIN_ATTEMPTS})",
                    )
                self._save_users()
                return None

            # ── Step 5: TOTP verification ──────────────────────
            totp = TOTP(user.totp_secret)
            if not totp.verify(totp_code.strip()):
                user.failed_attempts += 1
                self._audit("LOGIN_FAIL", username, ip,
                            "Invalid TOTP code")
                logger.warning(
                    "[ZeroTrust] Login failed — bad TOTP from '%s'",
                    username,
                )
                self._save_users()
                return None

            # ── All checks passed ──────────────────────────────
            user.failed_attempts = 0
            user.locked_until    = 0.0
            user.last_login      = time.time()
            self._save_users()

            # Generate cryptographic session
            session_key = os.urandom(32)
            token_str   = secrets.token_hex(TOKEN_BYTE_LENGTH)

            session = SessionToken(
                username    = username,
                token       = token_str,
                session_key = session_key,
                ip_address  = ip,
            )
            self._sessions[token_str] = session

            self._audit(
                "LOGIN_OK", username, ip,
                f"Login successful — session created "
                f"(key rotates every {KEY_ROTATION_INTERVAL}s)",
                token_hint=token_str[:8],
            )
            logger.info(
                "[ZeroTrust] '%s' logged in from %s — "
                "token: %s... (rotates in %ds)",
                username, ip, token_str[:8],
                KEY_ROTATION_INTERVAL,
            )
            return token_str

    def logout(self, token: str, ip: str = "unknown") -> bool:
        """Invalidate a session token immediately."""
        with self._lock:
            session = self._sessions.pop(token, None)
            if session:
                session.authenticated = False
                self._audit(
                    "LOGOUT", session.username, ip,
                    f"Session ended after "
                    f"{session.age_seconds:.0f}s, "
                    f"{session.rotation_count} key rotations",
                    token_hint=token[:8],
                )
                logger.info(
                    "[ZeroTrust] '%s' logged out (%d rotations)",
                    session.username, session.rotation_count,
                )
                return True
            return False

    # ─────────────────────────────────────────────────────────
    # Session Validation — Called on EVERY Protected Action
    # ─────────────────────────────────────────────────────────

    def validate_session(
        self,
        token: str,
        ip: str = "unknown",
        required_role: Optional[str] = None,
    ) -> Optional[SessionToken]:
        """
        Zero Trust continuous verification.

        Called before EVERY protected operation.
        Returns the session if valid, None if denied.
        Automatically rotates keys when due.
        """
        return self._validate_session(token, ip, required_role)

    def _validate_session(
        self,
        token: str,
        ip: str = "unknown",
        required_role: Optional[str] = None,
    ) -> Optional[SessionToken]:
        with self._lock:
            session = self._sessions.get(token)

            # ── Token exists? ─────────────────────────────────
            if not session:
                self._audit("ACCESS_DENIED", "unknown", ip,
                            "Invalid token")
                return None

            # ── Session still active? ─────────────────────────
            if not session.authenticated:
                self._audit("ACCESS_DENIED", session.username, ip,
                            "Session already invalidated")
                self._sessions.pop(token, None)
                return None

            # ── Idle timeout? (Zero Trust: no idle sessions) ──
            if session.is_idle_timeout:
                self._audit(
                    "ACCESS_DENIED", session.username, ip,
                    f"Session idle timeout "
                    f"({session.idle_seconds:.0f}s)",
                )
                session.authenticated = False
                self._sessions.pop(token, None)
                return None

            # ── IP binding check ──────────────────────────────
            # Allow "unknown" to be lenient (can match any IP)
            if (session.ip_address != ip and 
                ip != "unknown" and 
                session.ip_address != "unknown"):
                self._audit(
                    "ACCESS_DENIED", session.username, ip,
                    f"IP mismatch: bound={session.ip_address}, "
                    f"request={ip}",
                )
                logger.warning(
                    "[ZeroTrust] IP mismatch for '%s' — "
                    "POSSIBLE HIJACK from %s",
                    session.username, ip,
                )
                # Invalidate on IP mismatch (Zero Trust: deny)
                session.authenticated = False
                self._sessions.pop(token, None)
                return None

            # ── User still valid? ─────────────────────────────
            user = self._users.get(session.username)
            if not user or not user.active:
                self._audit("ACCESS_DENIED", session.username, ip,
                            "User disabled mid-session")
                session.authenticated = False
                self._sessions.pop(token, None)
                return None

            # ── Role check ────────────────────────────────────
            if required_role and user.role != required_role:
                self._audit(
                    "ACCESS_DENIED", session.username, ip,
                    f"Insufficient role: has={user.role}, "
                    f"need={required_role}",
                )
                return None

            # ── Key rotation due? (every 10 minutes) ──────────
            if session.needs_rotation:
                old_token = session.token
                new_key   = session.rotate_key()
                new_token = session.token

                # Remap session under new token
                self._sessions.pop(old_token, None)
                self._sessions[new_token] = session

                self._audit(
                    "KEY_ROTATED", session.username, ip,
                    f"Automatic key rotation #{session.rotation_count}",
                    token_hint=new_token[:8],
                )
                # Note: caller must retrieve new token via
                # get_current_token() after this call

            # ── All checks passed — touch session ─────────────
            session.touch()
            return session

    def get_current_token(self, username: str) -> Optional[str]:
        """
        Return the current valid token for a username.
        Use after validation (token may have rotated).
        """
        with self._lock:
            for token, session in self._sessions.items():
                if (session.username == username
                        and session.authenticated):
                    return token
        return None

    def get_session_info(self, token: str) -> Optional[dict]:
        """Return safe session metadata (no keys exposed)."""
        with self._lock:
            s = self._sessions.get(token)
            if not s:
                return None
            return {
                "username":        s.username,
                "age_seconds":     round(s.age_seconds, 1),
                "idle_seconds":    round(s.idle_seconds, 1),
                "rotation_count":  s.rotation_count,
                "next_rotation_in": max(
                    0, KEY_ROTATION_INTERVAL - s.age_seconds
                ),
                "ip_address":      s.ip_address,
                "authenticated":   s.authenticated,
            }

    # ─────────────────────────────────────────────────────────
    # Key Rotation Daemon (background thread)
    # ─────────────────────────────────────────────────────────

    def _start_rotation_daemon(self):
        """
        Background daemon that:
          1. Rotates session keys every 10 minutes
          2. Expires idle sessions
          3. Cleans up dead sessions
        """
        self._running = True
        t = threading.Thread(
            target=self._rotation_loop,
            daemon=True,
            name="ZeroTrust-KeyRotation",
        )
        t.start()
        logger.info(
            "[ZeroTrust] Key rotation daemon started "
            "(interval=%ds)",
            KEY_ROTATION_INTERVAL,
        )

    def _rotation_loop(self):
        """
        Runs every 60 seconds to check for:
          - Sessions due for key rotation
          - Idle sessions to expire
          - Locked accounts to unlock
        """
        while self._running:
            time.sleep(60)  # check every minute
            self._perform_maintenance()

    def _perform_maintenance(self):
        with self._lock:
            now          = time.time()
            to_rotate    = []
            to_expire    = []

            for token, session in list(self._sessions.items()):
                if not session.authenticated:
                    to_expire.append(token)
                elif session.is_idle_timeout:
                    to_expire.append(token)
                    self._audit(
                        "SESSION_EXPIRED", session.username,
                        session.ip_address,
                        f"Idle timeout after "
                        f"{session.idle_seconds:.0f}s",
                    )
                elif session.needs_rotation:
                    to_rotate.append(token)

            # Expire idle sessions
            for token in to_expire:
                session = self._sessions.pop(token, None)
                if session:
                    session.authenticated = False
                    logger.info(
                        "[ZeroTrust] Session expired for '%s'",
                        session.username,
                    )

            # Rotate keys
            for old_token in to_rotate:
                session = self._sessions.pop(old_token, None)
                if session and session.authenticated:
                    session.rotate_key()
                    new_token = session.token
                    self._sessions[new_token] = session
                    self._audit(
                        "KEY_ROTATED", session.username,
                        session.ip_address,
                        f"Daemon rotation #{session.rotation_count}",
                        token_hint=new_token[:8],
                    )

    def stop(self):
        """Stop the rotation daemon cleanly."""
        self._running = False
        logger.info("[ZeroTrust] Auth system stopped")

    # ─────────────────────────────────────────────────────────
    # Crypto Helpers
    # ─────────────────────────────────────────────────────────

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        """PBKDF2-SHA256 with 600k iterations (NIST 2023 guideline)."""
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=PBKDF2_ITERATIONS,
            dklen=32,
        )
        return dk.hex()

    @staticmethod
    def _verify_password(
        password: str, salt: bytes, expected_hash: str
    ) -> bool:
        """Constant-time password comparison."""
        computed = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations=PBKDF2_ITERATIONS,
            dklen=32,
        )
        return hmac.compare_digest(
            computed, bytes.fromhex(expected_hash)
        )

    @staticmethod
    def _dummy_hash():
        """Prevent timing attacks on non-existent usernames."""
        dummy_salt = b"\x00" * 16
        hashlib.pbkdf2_hmac(
            "sha256", b"dummy", dummy_salt,
            iterations=PBKDF2_ITERATIONS, dklen=32,
        )

    # ─────────────────────────────────────────────────────────
    # Session helpers
    # ─────────────────────────────────────────────────────────

    def _invalidate_user_sessions(self, username: str):
        """Invalidate ALL sessions for a user (e.g. after pw change)."""
        tokens_to_remove = [
            t for t, s in self._sessions.items()
            if s.username == username
        ]
        for t in tokens_to_remove:
            s = self._sessions.pop(t, None)
            if s:
                s.authenticated = False
        if tokens_to_remove:
            logger.info(
                "[ZeroTrust] Invalidated %d session(s) for '%s'",
                len(tokens_to_remove), username,
            )

    # ─────────────────────────────────────────────────────────
    # Persistent Storage — AES-256-GCM encrypted user database
    # ─────────────────────────────────────────────────────────

    def _save_users(self):
        """Save user database encrypted at rest."""
        if self._master_key is None:
            return  # Not initialized yet

        data = json.dumps(
            {k: v.to_dict() for k, v in self._users.items()},
            indent=2,
        ).encode()

        aesgcm = AESGCM(self._master_key)
        nonce  = os.urandom(12)
        ct     = aesgcm.encrypt(nonce, data, b"securecrypt-auth-db")

        with open(self._storage_path, "wb") as f:
            f.write(nonce + ct)

    def _load_users(self):
        """Load and decrypt user database from disk."""
        if not os.path.exists(self._storage_path):
            return

        if self._master_key is None:
            # Will be loaded later when initialized
            return

        try:
            with open(self._storage_path, "rb") as f:
                raw = f.read()
            nonce, ct = raw[:12], raw[12:]
            aesgcm = AESGCM(self._master_key)
            data   = aesgcm.decrypt(nonce, ct, b"securecrypt-auth-db")
            users_dict = json.loads(data.decode())
            self._users = {
                k: UserRecord.from_dict(v)
                for k, v in users_dict.items()
            }
            logger.info(
                "[ZeroTrust] Loaded %d user(s) from storage",
                len(self._users),
            )
        except Exception as exc:
            logger.error("[ZeroTrust] Failed to load users: %s", exc)
            self._users = {}

    # ─────────────────────────────────────────────────────────
    # Audit Log
    # ─────────────────────────────────────────────────────────

    def _audit(
        self,
        event_type: str,
        username: str,
        ip: str,
        details: str,
        token_hint: str = "",
    ):
        evt = AuditEvent(
            timestamp   = time.time(),
            event_type  = event_type,
            username    = username,
            ip_address  = ip,
            details     = details,
            token_hint  = token_hint,
        )
        self._audit_log.append(evt)
        logger.info(
            "[AUDIT] %-15s user=%-15s ip=%-15s %s",
            event_type, username, ip, details,
        )

    def get_audit_log(
        self,
        limit: int = 100,
        username_filter: Optional[str] = None,
    ) -> list[dict]:
        """Return recent audit log entries."""
        log = self._audit_log
        if username_filter:
            log = [e for e in log if e.username == username_filter]
        return [
            {
                "timestamp":  e.timestamp,
                "time":       time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(e.timestamp),
                ),
                "event":      e.event_type,
                "username":   e.username,
                "ip":         e.ip_address,
                "details":    e.details,
                "token_hint": e.token_hint,
            }
            for e in reversed(log[-limit:])
        ]

    # ─────────────────────────────────────────────────────────
    # Status helpers
    # ─────────────────────────────────────────────────────────

    def active_session_count(self) -> int:
        with self._lock:
            return sum(
                1 for s in self._sessions.values()
                if s.authenticated
            )

    def user_count(self) -> int:
        with self._lock:
            return len(self._users)

    def get_all_users(self) -> list[dict]:
        """Return safe user info (no password hashes exposed)."""
        with self._lock:
            return [
                {
                    "username":   u.username,
                    "role":       u.role,
                    "active":     u.active,
                    "last_login": u.last_login,
                    "locked":     u.locked_until > time.time(),
                }
                for u in self._users.values()
            ]

    def disable_user(self, admin_token: str, target_username: str,
                     ip: str = "unknown") -> bool:
        """Admin action: disable a user account."""
        session = self._validate_session(admin_token, ip,
                                          required_role="admin")
        if not session:
            return False
        with self._lock:
            user = self._users.get(target_username)
            if not user:
                return False
            user.active = False
            self._invalidate_user_sessions(target_username)
            self._save_users()
            self._audit("USER_DISABLED", session.username, ip,
                        f"Disabled account: {target_username}")
            return True

    def enable_user(self, admin_token: str, target_username: str,
                    ip: str = "unknown") -> bool:
        """Admin action: enable a disabled user account."""
        session = self._validate_session(admin_token, ip,
                                          required_role="admin")
        if not session:
            return False
        with self._lock:
            user = self._users.get(target_username)
            if not user:
                return False
            user.active = True
            user.failed_attempts = 0
            user.locked_until = 0.0
            self._save_users()
            self._audit("USER_ENABLED", session.username, ip,
                        f"Enabled account: {target_username}")
            return True

    def get_user_totp_secret(self, token: str, target_username: str,
                             ip: str = "unknown") -> Optional[tuple[str, str]]:
        """
        Get TOTP secret for a user.
        Admin can get any user's, regular users can only get their own.
        Returns (hex_secret, base32_secret) or None if not allowed.
        """
        session = self._validate_session(token, ip)
        if not session:
            return None

        with self._lock:
            # Get requesting user's role
            requesting_user = self._users.get(session.username)
            if not requesting_user:
                return None
            
            # Regular users can only see their own secret
            if requesting_user.role != "admin" and session.username != target_username:
                self._audit("ACCESS_DENIED", session.username, ip,
                            f"Tried to view {target_username} TOTP secret")
                return None

            user = self._users.get(target_username)
            if not user:
                return None

            # Convert hex secret to base32 for display
            from auth.login_system import hex_to_base32
            base32 = hex_to_base32(user.totp_secret)
            return (user.totp_secret, base32)

    def delete_user(self, admin_token: str, target_username: str,
                    ip: str = "unknown") -> bool:
        """Admin action: delete a user account."""
        session = self._validate_session(admin_token, ip,
                                          required_role="admin")
        if not session:
            return False

        if target_username == session.username:
            self._audit("USER_DELETE_FAIL", session.username, ip,
                        "Cannot delete own account")
            return False

        with self._lock:
            if target_username not in self._users:
                return False

            del self._users[target_username]
            self._invalidate_user_sessions(target_username)
            self._save_users()
            self._audit("USER_DELETED", session.username, ip,
                        f"Deleted account: {target_username}")
            return True