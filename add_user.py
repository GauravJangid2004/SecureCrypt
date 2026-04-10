#!/usr/bin/env python3
"""
SecureCrypt - Add New User Account

Interactive script to add new user accounts without giving admin access.
"""

import os
import sys
from auth.login_system import ZeroTrustLoginManager, TOTP, format_totp_display, generate_otpauth_uri
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _hashes


def validate_password(password: str) -> bool:
    """Check if password meets requirements."""
    if len(password) < 12:
        print("❌ Password must be at least 12 characters")
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    if not (has_upper and has_lower and has_digit and has_symbol):
        print("❌ Password must contain:")
        print("   • UPPERCASE letters (A-Z)")
        print("   • lowercase letters (a-z)")
        print("   • Numbers (0-9)")
        print("   • Symbols (!@#$%^&* etc)")
        return False
    
    return True


def main():
    print("\n" + "=" * 70)
    print("SecureCrypt - Add New User Account")
    print("=" * 70)
    
    # Check if auth database exists
    auth_db_path = "auth_db.enc"
    if not os.path.exists(auth_db_path):
        print("\n❌ Error: auth_db.enc not found!")
        print("   The database must exist first.")
        print("   Run: python main.py (to create it)")
        sys.exit(1)
    
    # Get master password
    print("\n🔐 Authentication:")
    master_pw = input("Enter MASTER password: ").strip()
    if not master_pw:
        print("❌ Master password required!")
        sys.exit(1)
    
    # Derive master key (same as main.py)
    try:
        kdf = PBKDF2HMAC(
            algorithm=_hashes.SHA256(),
            length=32,
            salt=b"securecrypt-master-salt-v1",
            iterations=100_000,
        )
        master_key = kdf.derive(master_pw.encode())
    except Exception as e:
        print(f"❌ Failed to derive master key: {e}")
        sys.exit(1)
    
    # Connect to database
    try:
        auth = ZeroTrustLoginManager(auth_db_path)
        auth.set_master_key_from_bytes(master_key)
        auth._load_users()
    except Exception as e:
        print(f"❌ Failed to load database: {e}")
        sys.exit(1)
    
    # Get new user credentials
    print("\n📝 New User Details:")
    username = input("Enter username: ").strip()
    
    if not username:
        print("❌ Username required!")
        sys.exit(1)
    
    # Check if user exists
    if username in auth._users:
        print(f"❌ User '{username}' already exists!")
        sys.exit(1)
    
    password = input("Enter password (12+ chars, uppercase, lowercase, numbers, symbols): ").strip()
    
    if not validate_password(password):
        sys.exit(1)
    
    # Select role
    print("\n👤 User Role:")
    print("   1) User (regular access)")
    print("   2) Admin (full access)")
    role_choice = input("Select role [1-2] (default 1): ").strip() or "1"
    
    if role_choice == "2":
        role = "admin"
    else:
        role = "user"
    
    # Create user
    print(f"\n⏳ Creating user '{username}' with role '{role}'...")
    try:
        totp_secret = auth.register_user(username, password, role=role)
        totp = TOTP(totp_secret)
        base32_secret = format_totp_display(totp_secret)
        current_code = totp.now()
        otpauth_uri = generate_otpauth_uri(username, totp_secret)
        
        print("\n" + "=" * 70)
        print("✅ USER ACCOUNT CREATED SUCCESSFULLY!")
        print("=" * 70)
        
        print(f"\n📝 Login Credentials:")
        print(f"   Username: {username}")
        print(f"   Password: {password}")
        print(f"   Role:     {role}")
        
        print(f"\n📱 TOTP Setup (for Google Authenticator):")
        print(f"   Base32 Secret:  {base32_secret}")
        print(f"   Current Code:   {current_code}")
        
        print(f"\n🔗 otpauth URI (for QR code):")
        print(f"   {otpauth_uri}")
        
        print(f"\n📖 How to add to Google Authenticator:")
        print(f"   Option 1 - Manual Entry:")
        print(f"     1. Open Google Authenticator app")
        print(f"     2. Tap '+' button")
        print(f"     3. Tap 'Enter a setup key'")
        print(f"     4. Enter Account name: {username}")
        print(f"     5. Enter Key: {base32_secret}")
        print(f"     6. Set Type to 'Time based'")
        print(f"     7. Tap 'Add'")
        print(f"\n   Option 2 - QR Code:")
        print(f"     1. Tap '+' in Google Authenticator")
        print(f"     2. Tap 'Scan a QR code'")
        print(f"     3. Scan the URI above with a QR scanner")
        
        print(f"\n✅ User can now log in with:")
        print(f"   - Username: {username}")
        print(f"   - Password: {password}")
        print(f"   - 6-digit code from Google Authenticator")
        
        print("\n" + "=" * 70)
        
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
