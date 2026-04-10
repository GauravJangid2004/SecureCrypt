#!/usr/bin/env python3
"""Integration test: Verify UserManagementTab imports and code is valid"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))


def test_imports():
    """Test that all necessary components can be imported"""
    
    try:
        # Import main module components
        from main import UserManagementTab, SignalBridge, MainWindow
        print("✅ UserManagementTab imported successfully")
        print("✅ SignalBridge imported successfully")
        print("✅ MainWindow imported successfully")
        
        # Import auth module
        from auth.login_system import ZeroTrustLoginManager, TOTP
        print("✅ ZeroTrustLoginManager imported successfully")
        print("✅ TOTP imported successfully")
        
        # Verify UserManagementTab has required methods
        required_methods = [
            'set_auth_context',
            '_show_my_totp',
            '_change_password',
            '_add_new_user',
            '_refresh_user_list',
            '_show_user_totp',
            '_toggle_user',
            '_delete_user',
        ]
        
        for method in required_methods:
            assert hasattr(UserManagementTab, method), f"Missing method: {method}"
            print(f"✅ UserManagementTab.{method}() exists")
        
        # Verify auth manager has new admin methods
        required_auth_methods = [
            'enable_user',
            'disable_user',
            'delete_user',
            'get_user_totp_secret',
            'get_all_users',
        ]
        
        for method in required_auth_methods:
            assert hasattr(ZeroTrustLoginManager, method), f"Missing method: {method}"
            print(f"✅ ZeroTrustLoginManager.{method}() exists")
        
        print("\n✅ ALL IMPORT & STRUCTURE TESTS PASSED!")
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    except AssertionError as e:
        print(f"❌ Structure validation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
