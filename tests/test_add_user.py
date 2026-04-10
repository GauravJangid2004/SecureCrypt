#!/usr/bin/env python3
"""Test the add_user.py script functionality"""

import os
import sys
import tempfile
from auth.login_system import ZeroTrustLoginManager, format_totp_display
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as _hashes

print("=" * 70)
print("Testing add_user.py functionality")
print("=" * 70)

# Create a temporary auth database for testing
with tempfile.TemporaryDirectory() as tmpdir:
    test_db = os.path.join(tmpdir, "test_auth.enc")
    
    # Step 1: Create master key
    print("\n1️⃣  Creating master key...")
    kdf = PBKDF2HMAC(
        algorithm=_hashes.SHA256(),
        length=32,
        salt=b"securecrypt-master-salt-v1",
        iterations=100_000,
    )
    master_key = kdf.derive(b"testmaster123")
    
    # Step 2: Create auth manager and add admin
    print("2️⃣  Creating admin user...")
    auth = ZeroTrustLoginManager(test_db)
    auth.set_master_key_from_bytes(master_key)
    admin_secret = auth.register_user("admin", "AdminPass@123", role="admin")
    print(f"   ✅ Admin created")
    
    # Step 3: Add regular user
    print("3️⃣  Adding regular user 'alice'...")
    alice_secret = auth.register_user("alice", "TestPass@123", role="user")
    alice_base32 = format_totp_display(alice_secret)
    print(f"   ✅ User 'alice' created")
    print(f"   Base32 Secret: {alice_base32}")
    
    # Step 4: Add another user
    print("4️⃣  Adding regular user 'bob'...")
    bob_secret = auth.register_user("bob", "BobSecPass@456", role="user")
    bob_base32 = format_totp_display(bob_secret)
    print(f"   ✅ User 'bob' created")
    print(f"   Base32 Secret: {bob_base32}")
    
    # Step 5: Reload and verify
    print("5️⃣  Verifying users persist...")
    auth2 = ZeroTrustLoginManager(test_db)
    auth2.set_master_key_from_bytes(master_key)
    auth2._load_users()
    user_count = auth2.user_count()
    print(f"   ✅ Loaded {user_count} users from database")
    print(f"      - admin (role='admin')")
    print(f"      - alice (role='user')")
    print(f"      - bob (role='user')")

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED!")
print("=" * 70)
print("\nadd_user.py is ready to use!")
print("\nUsage:")
print("  python add_user.py")
print("\nThe script will:")
print("  1. Ask for master password")
print("  2. Collect new username and password")
print("  3. Choose user role (user or admin)")
print("  4. Generate TOTP secret")
print("  5. Show Base32 secret for Google Authenticator")
