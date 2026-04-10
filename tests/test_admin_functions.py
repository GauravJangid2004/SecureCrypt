#!/usr/bin/env python3
"""Test new admin functions for user management UI"""

import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(__file__))

from auth.login_system import ZeroTrustLoginManager, TOTP


def test_admin_functions():
    """Test enable_user, delete_user, get_user_totp_secret"""
    
    # Create temp database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_auth.db")
    
    try:
        # Initialize auth manager
        auth_mgr = ZeroTrustLoginManager(db_path)
        auth_mgr._master_key = b'x' * 32  # Fake master key
        
        # Register admin
        admin_token = auth_mgr.register_user("admin", "AdminPass@123", role="admin")
        print(f"✅ Admin registered, TOTP: {admin_token[:8]}...")
        
        # Login as admin to get session
        totp_gen = TOTP(admin_token)
        totp_code = totp_gen.now()
        session = auth_mgr.login("admin", "AdminPass@123", totp_code)
        if not session:
            print("❌ Admin login failed")
            return False
        admin_session_token = session
        print(f"✅ Admin session created: {admin_session_token[:10]}...")
        
        # Register regular user
        auth_mgr.register_user("testuser", "TestPass@123", role="user")
        print("✅ Test user registered")
        
        # Test 1: get_user_totp_secret (admin viewing user's secret)
        result = auth_mgr.get_user_totp_secret(admin_session_token, "testuser")
        if result:
            hex_secret, base32_secret = result
            print(f"✅ Got user's TOTP secret: {base32_secret}")
        else:
            print("❌ Failed to get user's TOTP secret")
            return False
        
        # Test 2: disable_user
        success = auth_mgr.disable_user(admin_session_token, "testuser")
        if success:
            print("✅ User disabled")
        else:
            print("❌ Failed to disable user")
            return False
        
        # Verify user is disabled
        users = auth_mgr.get_all_users()
        testuser = next((u for u in users if u["username"] == "testuser"), None)
        if testuser and not testuser["active"]:
            print("✅ Verified user is disabled")
        else:
            print("❌ User not disabled")
            return False
        
        # Test 3: enable_user
        success = auth_mgr.enable_user(admin_session_token, "testuser")
        if success:
            print("✅ User enabled")
        else:
            print("❌ Failed to enable user")
            return False
        
        # Verify user is enabled
        users = auth_mgr.get_all_users()
        testuser = next((u for u in users if u["username"] == "testuser"), None)
        if testuser and testuser["active"]:
            print("✅ Verified user is enabled")
        else:
            print("❌ User not enabled")
            return False
        
        # Test 4: delete_user
        success = auth_mgr.delete_user(admin_session_token, "testuser")
        if success:
            print("✅ User deleted")
        else:
            print("❌ Failed to delete user")
            return False
        
        # Verify user is deleted
        users = auth_mgr.get_all_users()
        testuser = next((u for u in users if u["username"] == "testuser"), None)
        if testuser is None:
            print("✅ Verified user is deleted")
        else:
            print("❌ User still exists")
            return False
        
        print("\n✅ ALL ADMIN TESTS PASSED!")
        return True
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    success = test_admin_functions()
    sys.exit(0 if success else 1)
