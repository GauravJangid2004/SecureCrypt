#!/usr/bin/env python3
"""Test that UserManagementTab initializes without garbage collection errors"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from PyQt6.QtWidgets import QApplication
from main import UserManagementTab, SignalBridge


def test_widget_init():
    """Test widget creation and auth context setting"""
    
    try:
        app = QApplication.instance() or QApplication(sys.argv)
        
        # Create bridge and tab
        bridge = SignalBridge()
        tab = UserManagementTab(bridge)
        print("✅ UserManagementTab created successfully")
        
        # Verify inner widget is stored and alive
        assert hasattr(tab, '_inner_widget'), "Inner widget not stored"
        print("✅ Inner widget reference preserved in self._inner_widget")
        
        # Show tab (this would be done by MainWindow)
        tab.show()
        print("✅ Tab can be shown without errors")
        
        # Create mock auth manager
        class MockAuth:
            def get_all_users(self):
                return [
                    {"username": "admin", "role": "admin", "active": True, "last_login": 0, "locked": False}
                ]
        
        # Set auth context (this was causing the RuntimeError before)
        tab.set_auth_context(MockAuth(), "test_token", "admin", "admin")
        print("✅ set_auth_context() called successfully without RuntimeError")
        
        # Verify UI elements are accessible
        assert tab.lbl_username.text() == "admin", "Username not set"
        assert "ADMIN" in tab.lbl_role.text(), "Role not displayed"
        print("✅ Widget text properties are accessible")
        
        # Verify admin section is visible for admin
        assert tab.admin_section.isVisible(), "Admin section should be visible"
        print("✅ Admin section visibility correct for admin role")
        
        print("\n✅ ALL WIDGET INITIALIZATION TESTS PASSED - BUG FIXED!")
        return True
        
    except RuntimeError as e:
        if "deleted" in str(e):
            print(f"❌ Garbage collection bug still present: {e}")
        else:
            print(f"❌ RuntimeError: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_widget_init()
    sys.exit(0 if success else 1)
