# Adding Users - Quick Start Guide

## The Easy Way: Use add_user.py

### Step 1: Start the App First
```bash
python main.py
```
- Enter your master password
- This creates the database if it doesn't exist
- You can close it after first-run setup

### Step 2: Add New Users
```bash
python add_user.py
```

### Step 3: Follow the Interactive Prompts

**Example session:**
```
SecureCrypt - Add New User Account
====================================================================

🔐 Authentication:
Enter MASTER password: [your-master-password]

📝 New User Details:
Enter username: alice
Enter password: AliceSecure@Pass123

👤 User Role:
   1) User (regular access)
   2) Admin (full access)
Select role [1-2] (default 1): 1

⏳ Creating user 'alice' with role 'user'...

✅ USER ACCOUNT CREATED SUCCESSFULLY!
====================================================================

📝 Login Credentials:
   Username: alice
   Password: AliceSecure@Pass123
   Role:     user

📱 TOTP Setup (for Google Authenticator):
   Base32 Secret:  TKMWZDL2QXQXBD6GKWJWZ6GEBNF2EFKS
   Current Code:   123456

✅ User can now log in with:
   - Username: alice
   - Password: AliceSecure@Pass123
   - 6-digit code from Google Authenticator
```

---

## Password Requirements

The script enforces strong passwords:

✅ **Valid:** `AliceSecure@Pass123`
- 18+ characters
- Uppercase: A, P, S
- Lowercase: lice, ecure, ass
- Numbers: 1, 2, 3
- Symbols: @

❌ **Invalid:** `alice123`
- Missing uppercase
- Missing symbols
- Too short

**Requirements:**
- At least 12 characters
- Must have UPPERCASE letters
- Must have lowercase letters  
- Must have Numbers
- Must have Symbols (!@#$%^&* etc)

---

## Creating Multiple Users

Run the script multiple times:

```bash
# Create alice
python add_user.py
# → Enter all details

# Create bob
python add_user.py
# → Enter all details

# Create charlie
python add_user.py
# → Enter all details
```

Each user gets:
- Unique username
- Unique password
- Unique TOTP secret (for their phone)
- Choice of role (user or admin)

---

## User Roles: What's the Difference?

| Feature | User | Admin |
|---------|------|-------|
| Login | ✅ Yes | ✅ Yes |
| Access Features | ✅ Limited | ✅ Full |
| Change Password | ✅ Yes | ✅ Yes |
| View Audit Logs | ✅ Limited | ✅ Full |
| Manage Users | ❌ No | ✅ Yes |

**Recommendation:**
- Give most people **"User"** role
- Give team leads **"Admin"** role

---

## First Login for New Users

Each new user should follow this on their first login:

1. **Start the app**
   ```bash
   python main.py
   ```

2. **Enter master password**
   ```
   Enter MASTER password: [ask admin for this]
   ```

3. **Login dialog appears**
   - Username: `alice`
   - Password: `AliceSecure@Pass123`
   - TOTP code: `123456` (from Google Authenticator)

4. **App launches** ✅

---

## Passwords: How to Give Them to Users

**DO NOT:**
- Email passwords in plain text
- Write on sticky notes
- Share in group chats

**DO:**
- Print and hand to user in sealed envelope
- Send through encrypted channel
- User should change password after first login

---

## Troubleshooting add_user.py

### Error: "auth_db.enc not found"
**Solution:** Database doesn't exist yet
```bash
python main.py  # Creates it
# Then run add_user.py
```

### Error: "Wrong master password"
**Solution:** Master password must match what you use in main.py
- Try again with correct password
- Contact admin if you don't know it

### Error: "User 'alice' already exists"
**Solution:** That username is taken
- Choose a different username
- Or reset the user's password manually

---

## Resetting User Passwords (Admin Only)

If a user forgets their password, you can reset it:

```python
from auth.login_system import ZeroTrustLoginManager, TOTP, format_totp_display
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"securecrypt-master-salt-v1",
    iterations=100_000,
)
master_key = kdf.derive(b"your-master-password")

auth = ZeroTrustLoginManager("auth_db.enc")
auth.set_master_key_from_bytes(master_key)
auth._load_users()

# Delete the old user and recreate with new password
del auth._users["alice"]
auth._save_users()

# Now create alice again with new password
new_secret = auth.register_user("alice", "NewPassword@123", role="user")
print(f"New TOTP Base32: {format_totp_display(new_secret)}")
```

---

## Next Steps

1. ✅ Create admin password (during first run)
2. ✅ Create team member accounts (use `add_user.py`)
3. ✅ Each user adds TOTP secret to their phone
4. ✅ Each user changes password after first login
5. ✅ Keep master password safe and secure

---

**Questions?** See AUTHENTICATION_SETUP.md for more details!
