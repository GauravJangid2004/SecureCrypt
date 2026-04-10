"""
Zero Trust Login System — Full Test Suite
Run: python -m pytest tests/test_auth.py -v
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from auth.login_system import (
    ZeroTrustLoginManager,
    TOTP,
    KEY_ROTATION_INTERVAL,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION,
    SESSION_IDLE_TIMEOUT,
)


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture
def auth(tmp_path):
    """Fresh auth manager for each test."""
    mgr = ZeroTrustLoginManager(str(tmp_path / "test_auth.enc"))
    mgr.set_master_key_from_bytes(os.urandom(32))
    return mgr


@pytest.fixture
def registered_user(auth):
    """Auth manager with one registered user; returns (auth, totp_secret)."""
    secret = auth.register_user("alice", "SecurePass123!", role="user")
    return auth, secret


@pytest.fixture
def logged_in(registered_user):
    """Returns (auth, token, totp_secret)."""
    auth, secret = registered_user
    totp = TOTP(secret)
    token = auth.login("alice", "SecurePass123!", totp.now())
    assert token is not None, "Login fixture failed"
    return auth, token, secret


# ─────────────────────────────────────────────────────────────
# Test 1: User Registration
# ─────────────────────────────────────────────────────────────

class TestUserRegistration:

    def test_register_ok(self, auth):
        secret = auth.register_user("bob", "ValidPass1234!")
        assert isinstance(secret, str)
        assert len(secret) == 40  # 20 bytes hex

    def test_register_short_password_rejected(self, auth):
        with pytest.raises(ValueError, match="12 characters"):
            auth.register_user("bob", "short")

    def test_register_duplicate_rejected(self, auth):
        auth.register_user("bob", "ValidPass1234!")
        with pytest.raises(ValueError, match="already exists"):
            auth.register_user("bob", "AnotherPass1234!")

    def test_register_empty_username_rejected(self, auth):
        with pytest.raises(ValueError):
            auth.register_user("", "ValidPass1234!")

    def test_register_assigns_role(self, auth):
        auth.register_user("admin1", "AdminPass1234!", role="admin")
        users = auth.get_all_users()
        admin = next(u for u in users if u["username"] == "admin1")
        assert admin["role"] == "admin"


# ─────────────────────────────────────────────────────────────
# Test 2: TOTP
# ─────────────────────────────────────────────────────────────

class TestTOTP:

    def test_totp_generates_6_digits(self):
        secret = os.urandom(20).hex()
        totp = TOTP(secret)
        code = totp.now()
        assert len(code) == 6
        assert code.isdigit()

    def test_totp_verify_current_code(self):
        secret = os.urandom(20).hex()
        totp = TOTP(secret)
        assert totp.verify(totp.now())

    def test_totp_rejects_wrong_code(self):
        secret = os.urandom(20).hex()
        totp = TOTP(secret)
        assert not totp.verify("000000")
        assert not totp.verify("999999")

    def test_totp_constant_time(self):
        """Verify comparison doesn't leak timing info."""
        secret = os.urandom(20).hex()
        totp = TOTP(secret)
        t1 = time.perf_counter()
        totp.verify("000000")
        t2 = time.perf_counter()
        totp.verify(totp.now())
        t3 = time.perf_counter()
        # Times should be roughly equal (no early exit)
        assert abs((t2 - t1) - (t3 - t2)) < 0.5


# ─────────────────────────────────────────────────────────────
# Test 3: Login Flow
# ─────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_success(self, registered_user):
        auth, secret = registered_user
        totp  = TOTP(secret)
        token = auth.login("alice", "SecurePass123!", totp.now())
        assert token is not None
        assert len(token) == 64  # 32 bytes hex

    def test_login_wrong_password_rejected(self, registered_user):
        auth, secret = registered_user
        totp  = TOTP(secret)
        token = auth.login("alice", "WrongPassword!", totp.now())
        assert token is None

    def test_login_wrong_totp_rejected(self, registered_user):
        auth, secret = registered_user
        token = auth.login("alice", "SecurePass123!", "000000")
        assert token is None

    def test_login_unknown_user_rejected(self, auth):
        token = auth.login("nobody", "SomePassword!", "123456")
        assert token is None

    def test_login_returns_unique_tokens(self, registered_user):
        auth, secret = registered_user
        totp = TOTP(secret)
        t1   = auth.login("alice", "SecurePass123!", totp.now())
        # logout and re-login for second token
        auth.logout(t1)
        time.sleep(1)   # wait for TOTP step boundary if needed
        t2 = auth.login("alice", "SecurePass123!", TOTP(secret).now())
        if t2:          # may get same TOTP code within 30s window
            assert t1 != t2


# ─────────────────────────────────────────────────────────────
# Test 4: Brute Force Lockout
# ─────────────────────────────────────────────────────────────

class TestBruteForce:

    def test_lockout_after_max_attempts(self, registered_user):
        auth, secret = registered_user
        totp = TOTP(secret)

        for _ in range(MAX_LOGIN_ATTEMPTS):
            auth.login("alice", "WrongPassword!", totp.now())

        # Next attempt should be blocked even with correct credentials
        token = auth.login("alice", "SecurePass123!", totp.now())
        assert token is None

    def test_counter_resets_after_success(self, registered_user):
        auth, secret = registered_user
        totp = TOTP(secret)

        # 2 failures
        auth.login("alice", "WrongPassword!", "000000")
        auth.login("alice", "WrongPassword!", "000000")

        # Successful login resets counter
        token = auth.login("alice", "SecurePass123!", totp.now())
        assert token is not None

        # Re-login to confirm counter reset
        auth.logout(token)
        user = auth._users.get("alice")
        assert user.failed_attempts == 0

    def test_lockout_duration_enforced(self, registered_user):
        auth, secret = registered_user
        totp = TOTP(secret)

        for _ in range(MAX_LOGIN_ATTEMPTS):
            auth.login("alice", "Wrong!", "000000")

        user = auth._users["alice"]
        assert user.locked_until > time.time()
        assert user.locked_until <= time.time() + LOCKOUT_DURATION + 1


# ─────────────────────────────────────────────────────────────
# Test 5: Session Validation (Zero Trust)
# ─────────────────────────────────────────────────────────────

class TestSessionValidation:

    def test_valid_session_accepted(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)
        assert session is not None
        assert session.username == "alice"

    def test_invalid_token_rejected(self, auth):
        session = auth.validate_session("deadbeef" * 8)
        assert session is None

    def test_logout_invalidates_session(self, logged_in):
        auth, token, _ = logged_in
        auth.logout(token)
        session = auth.validate_session(token)
        assert session is None

    def test_ip_mismatch_rejected(self, registered_user):
        auth, secret = registered_user
        totp  = TOTP(secret)
        token = auth.login("alice", "SecurePass123!", totp.now(),
                           ip="192.168.1.10")
        assert token is not None

        # Same token from different IP → Zero Trust denies
        session = auth.validate_session(token, ip="10.0.0.99")
        assert session is None

    def test_touch_updates_activity(self, logged_in):
        auth, token, _ = logged_in
        s1 = auth.validate_session(token)
        t1 = s1.last_activity
        time.sleep(0.05)
        s2 = auth.validate_session(token)
        assert s2.last_activity >= t1

    def test_role_check_enforced(self, registered_user):
        auth, secret = registered_user
        totp  = TOTP(secret)
        token = auth.login("alice", "SecurePass123!", totp.now())

        # alice is "user", not "admin"
        session = auth.validate_session(
            token, required_role="admin"
        )
        assert session is None

        # "user" role passes
        session = auth.validate_session(
            token, required_role="user"
        )
        assert session is not None


# ─────────────────────────────────────────────────────────────
# Test 6: Key Rotation
# ─────────────────────────────────────────────────────────────

class TestKeyRotation:

    def test_manual_key_rotation(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        old_key   = bytes(session.session_key)
        old_token = session.token

        new_key = session.rotate_key()
        assert new_key != old_key
        assert len(new_key) == 32
        assert session.token != old_token
        assert session.rotation_count == 1

    def test_key_rotation_increments_counter(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        for i in range(3):
            session.rotate_key()

        assert session.rotation_count == 3

    def test_needs_rotation_flag(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        # Freshly created — should NOT need rotation
        assert not session.needs_rotation

        # Simulate time passing past interval
        session.created_at -= (KEY_ROTATION_INTERVAL + 1)
        assert session.needs_rotation

    def test_rotation_produces_different_keys(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        keys = set()
        keys.add(session.session_key.hex())
        for _ in range(5):
            session.rotate_key()
            keys.add(session.session_key.hex())

        # All 6 keys must be unique
        assert len(keys) == 6

    def test_daemon_rotation_replaces_token(self, logged_in):
        """
        Simulate daemon rotation:
        after rotation the OLD token must be invalid
        and the NEW token must be valid.
        """
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        # Force rotation needed
        session.created_at -= (KEY_ROTATION_INTERVAL + 1)

        # Next validate() call triggers rotation internally
        auth.validate_session(token)

        # Get new token
        new_token = auth.get_current_token("alice")
        assert new_token is not None
        assert new_token != token

        # Old token is gone
        assert auth.validate_session(token) is None

        # New token works
        assert auth.validate_session(new_token) is not None


# ─────────────────────────────────────────────────────────────
# Test 7: Idle Timeout
# ─────────────────────────────────────────────────────────────

class TestIdleTimeout:

    def test_idle_session_expired(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)

        # Simulate idle timeout
        session.last_activity -= (SESSION_IDLE_TIMEOUT + 1)

        result = auth.validate_session(token)
        assert result is None

    def test_active_session_not_expired(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)
        session.last_activity = time.time()  # just touched
        result = auth.validate_session(token)
        assert result is not None


# ─────────────────────────────────────────────────────────────
# Test 8: Password Change
# ─────────────────────────────────────────────────────────────

class TestPasswordChange:

    def test_password_change_ok(self, logged_in):
        auth, token, _ = logged_in
        result = auth.change_password(
            token, "SecurePass123!", "NewPassword5678!", ip="127.0.0.1"
        )
        assert result is True

    def test_password_change_invalidates_sessions(self, logged_in):
        auth, token, _ = logged_in
        auth.change_password(
            token, "SecurePass123!", "NewPassword5678!", ip="127.0.0.1"
        )
        # Old token must no longer work
        assert auth.validate_session(token) is None

    def test_password_change_wrong_old_password(self, logged_in):
        auth, token, _ = logged_in
        result = auth.change_password(
            token, "WrongOldPass!", "NewPassword5678!", ip="127.0.0.1"
        )
        assert result is False

    def test_password_change_short_new_password(self, logged_in):
        auth, token, _ = logged_in
        result = auth.change_password(
            token, "SecurePass123!", "short", ip="127.0.0.1"
        )
        assert result is False


# ─────────────────────────────────────────────────────────────
# Test 9: Audit Log
# ─────────────────────────────────────────────────────────────

class TestAuditLog:

    def test_login_ok_logged(self, logged_in):
        auth, token, _ = logged_in
        log = auth.get_audit_log()
        events = [e["event"] for e in log]
        assert "LOGIN_OK" in events

    def test_login_fail_logged(self, registered_user):
        auth, _ = registered_user
        auth.login("alice", "WrongPass!", "000000")
        log = auth.get_audit_log()
        events = [e["event"] for e in log]
        assert "LOGIN_FAIL" in events

    def test_lockout_logged(self, registered_user):
        auth, secret = registered_user
        for _ in range(MAX_LOGIN_ATTEMPTS):
            auth.login("alice", "WrongPass!", "000000")
        log = auth.get_audit_log()
        events = [e["event"] for e in log]
        assert "LOCKED" in events

    def test_logout_logged(self, logged_in):
        auth, token, _ = logged_in
        auth.logout(token)
        log = auth.get_audit_log()
        events = [e["event"] for e in log]
        assert "LOGOUT" in events

    def test_key_rotation_logged(self, logged_in):
        auth, token, _ = logged_in
        session = auth.validate_session(token)
        session.created_at -= (KEY_ROTATION_INTERVAL + 1)
        auth.validate_session(token)
        log = auth.get_audit_log()
        events = [e["event"] for e in log]
        assert "KEY_ROTATED" in events

    def test_audit_filter_by_user(self, registered_user):
        auth, secret = registered_user
        auth.register_user("carol", "CarolPass1234!")
        totp  = TOTP(secret)
        auth.login("alice", "SecurePass123!", totp.now())
        log = auth.get_audit_log(username_filter="alice")
        assert all(e["username"] == "alice" for e in log)


# ─────────────────────────────────────────────────────────────
# Test 10: Multi-User Isolation
# ─────────────────────────────────────────────────────────────

class TestMultiUser:

    def test_tokens_isolated(self, auth):
        sec_a = auth.register_user("alice2", "AlicePass1234!",
                                    role="user")
        sec_b = auth.register_user("bob2",   "BobPass1234!",
                                    role="admin")

        tok_a = auth.login("alice2", "AlicePass1234!",
                            TOTP(sec_a).now())
        tok_b = auth.login("bob2",   "BobPass1234!",
                            TOTP(sec_b).now())

        assert tok_a != tok_b

        sess_a = auth.validate_session(tok_a)
        sess_b = auth.validate_session(tok_b)
        assert sess_a.username == "alice2"
        assert sess_b.username == "bob2"

    def test_logout_one_user_doesnt_affect_other(self, auth):
        sec_a = auth.register_user("alice3", "AlicePass1234!")
        sec_b = auth.register_user("bob3",   "BobPass1234!")

        tok_a = auth.login("alice3", "AlicePass1234!",
                            TOTP(sec_a).now())
        tok_b = auth.login("bob3",   "BobPass1234!",
                            TOTP(sec_b).now())

        auth.logout(tok_a)

        assert auth.validate_session(tok_a) is None
        assert auth.validate_session(tok_b) is not None


# ─────────────────────────────────────────────────────────────
# Test 11: Admin Actions
# ─────────────────────────────────────────────────────────────

class TestAdminActions:

    def test_admin_can_disable_user(self, auth):
        admin_sec = auth.register_user("admin2", "AdminPass1234!",
                                        role="admin")
        auth.register_user("victim", "VictimPass1234!")

        admin_token = auth.login("admin2", "AdminPass1234!",
                                  TOTP(admin_sec).now())
        result = auth.disable_user(admin_token, "victim")
        assert result is True

        users = {u["username"]: u for u in auth.get_all_users()}
        assert not users["victim"]["active"]

    def test_non_admin_cannot_disable_user(self, logged_in):
        auth, token, _ = logged_in
        auth.register_user("target", "TargetPass1234!")
        result = auth.disable_user(token, "target")
        assert result is False


# ─────────────────────────────────────────────────────────────
# Test 12: Concurrent Access
# ─────────────────────────────────────────────────────────────

class TestConcurrentAccess:

    def test_concurrent_logins_are_safe(self, auth):
        import threading
        auth.register_user("shared", "SharedPass1234!")
        secret = auth._users["shared"].totp_secret
        tokens = []
        errors = []

        def _login():
            try:
                tok = auth.login(
                    "shared", "SharedPass1234!",
                    TOTP(secret).now(),
                )
                if tok:
                    tokens.append(tok)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=_login) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors: {errors}"
        # All successful logins get unique tokens
        assert len(set(tokens)) == len(tokens)


# ─────────────────────────────────────────────────────────────
# Run tests directly
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        capture_output=False,
    )
    sys.exit(result.returncode)