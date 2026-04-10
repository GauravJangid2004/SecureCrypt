"""
Run once to create the admin account:
  python -m auth.setup_admin
"""
import os
import sys
import getpass
import qrcode  # pip install qrcode[pil]  (optional)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from auth.login_system import ZeroTrustLoginManager, TOTP


def setup():
    print("=" * 55)
    print("  SecureCrypt — Zero Trust Admin Account Setup")
    print("=" * 55)
    print()

    master_pw = getpass.getpass(
        "Set MASTER password (encrypts user database): "
    )
    confirm = getpass.getpass("Confirm master password: ")
    if master_pw != confirm:
        print("❌ Passwords do not match.")
        sys.exit(1)

    auth = ZeroTrustLoginManager("auth_db.enc")
    auth.initialize(master_pw)

    username = input("Admin username [admin]: ").strip() or "admin"
    user_pw  = getpass.getpass("Admin password (min 12 chars): ")
    if len(user_pw) < 12:
        print("❌ Password too short (min 12 chars).")
        sys.exit(1)

    try:
        totp_secret = auth.register_user(username, user_pw,
                                          role="admin")
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    print()
    print("✅ Admin account created!")
    print()
    print("─" * 55)
    print("  TOTP Setup (add to Google Authenticator / Authy)")
    print("─" * 55)
    totp = TOTP(totp_secret)
    print(f"  Secret (hex): {totp_secret}")
    print(f"  Current code: {totp.now()}")
    print()
    print("  ⚠  SAVE THIS SECRET — it cannot be recovered!")
    print("─" * 55)

    # Try to show QR code
    try:
        import qrcode as qr
        uri = (
            f"otpauth://totp/SecureCrypt:{username}"
            f"?secret={bytes.fromhex(totp_secret).hex().upper()}"
            f"&issuer=SecureCrypt"
        )
        img = qr.make(uri)
        img.save("totp_qr.png")
        print("  QR code saved to: totp_qr.png")
    except ImportError:
        print("  (install 'qrcode[pil]' to generate QR code)")

    print()
    print("Setup complete. Run: python main.py")


if __name__ == "__main__":
    setup()