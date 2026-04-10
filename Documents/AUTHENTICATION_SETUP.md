# SecureCrypt Authentication Setup Guide

## Overview
SecureCrypt uses **Zero Trust authentication** with:
- Master password protection for the user database
- PBKDF2-SHA256 password hashing (600,000 iterations)
- TOTP (Time-based One-Time Password) for MFA
- Automatic session key rotation every 10 minutes
- Brute-force protection (5 attempts = 5 min lockout)

---

## First Run Setup

### Step 1: Start the Application
```bash
python main.py
```

### Step 2: Set Master Password
When you first run the app, you'll be prompted to enter a **MASTER PASSWORD**:

```
Enter MASTER password to decrypt user database:
(Use same password every time you start the app)
```

**Important:** Use the **same master password every time** you start the app. This password encrypts and decrypts the user database.

### Step 3: Auto-Created Admin Account
If no users exist, the app automatically creates a default admin account:

**Default Credentials:**
- Username: `admin`
- Password: `SecureCrypt@Admin123`
- TOTP: Display shows current code and secret

### Step 4: Save TOTP Secret & Add to Authenticator
You'll see a message box with:
- Current 6-digit TOTP code (for verification)
- **Base32 secret** (for Google Authenticator - NOT hex!)
- otpauth:// URI (for QR code scanning)

**⚠️ CRITICAL:** Use the **Base32 secret**, NOT the hex one!

**How to add to Google Authenticator:**

**Option 1: Manual Entry (Recommended if QR fails)**
1. Open **Google Authenticator** app on your phone
2. Tap **+** button (Add Account)
3. Tap **"Enter a setup key"** (or **"Manual entry"**)
4. **Paste the Base32 secret** (the short code in the dialog)
5. Set **Key type** to **"Time based"** or **"TOTP"**
6. Tap **"Add"**
7. You should now see a 6-digit code that changes every 30 seconds
8. **Verify it matches the code shown** in SecureCrypt dialog

**Option 2: QR Code**
1. Open Google Authenticator
2. Tap **+** (Add Account)
3. Tap **"Scan a QR code"**
4. The otpauth:// URI in the dialog can be converted to QR code

**Step 5: Login with TOTP Code**
1. Username: `admin`
2. Password: `SecureCrypt@Admin123`
3. **6-digit code from Google Authenticator** (changes every 30 seconds)
4. If you see "bad TOTP" error:
   - Wait for next code (30 seconds)
   - Make sure your phone time is synced with internet
   - Try a fresh code from the app

---

## Adding New Users

### ⭐ Option 1: Using add_user.py (EASIEST - Recommended!)

```bash
python add_user.py
```

**Interactive script that guides you through:**
1. Asks for master password (security check)
2. Collects new username
3. Collects password with validation (must be 12+ chars with mixed case, numbers, symbols)
4. Choose role: User (regular) or Admin (full access)
5. Generates TOTP secret automatically
6. Shows Base32 secret for Google Authenticator
7. Shows setup instructions

**Example output:**
```
SecureCrypt - Add New User Account
====================================================================

🔐 Authentication:
Enter MASTER password: [hidden]

📝 New User Details:
Enter username: alice
Enter password: SecurePass@123

👤 User Role:
   1) User (regular access)
   2) Admin (full access)
Select role [1-2] (default 1): 1

⏳ Creating user 'alice' with role 'user'...

✅ USER ACCOUNT CREATED SUCCESSFULLY!
====================================================================

📝 Login Credentials:
   Username: alice
   Password: SecurePass@123
   Role:     user

📱 TOTP Setup (for Google Authenticator):
   Base32 Secret:  UGZMHVHF62Q3FQ6U4X3A
   Current Code:   123456

✅ User can now log in with:
   - Username: alice
   - Password: SecurePass@123
   - 6-digit code from Google Authenticator
```

### Option 2: Using setup_admin.py (For Admin Reset)
```bash
python -m auth.setup_admin
```

This interactive script guides you through:
1. Setting/resetting master password
2. Creating admin account
3. Displaying TOTP secret
4. Generating QR code (optional)

### Option 3: Manually in Code
```python
from auth.login_system import ZeroTrustLoginManager, TOTP, format_totp_display
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Setup master key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"securecrypt-master-salt-v1",
    iterations=100_000,
)
master_key = kdf.derive(b"your-master-password")

# Create auth manager
auth = ZeroTrustLoginManager("auth_db.enc")
auth.set_master_key_from_bytes(master_key)
auth._load_users()

# Add new user (as regular user)
totp_secret = auth.register_user("alice", "SecurePass@123", role="user")
totp = TOTP(totp_secret)
base32_secret = format_totp_display(totp_secret)

print(f"Created user: alice")
print(f"Base32 Secret: {base32_secret}")
print(f"Current Code: {totp.now()}")

# Or add admin user
totp_secret = auth.register_user("bob", "AdminPass@123", role="admin")
```

---

## User Roles Explained

| Role | Access | Use Case |
|------|--------|----------|
| **user** | Limited access to features | Team members, regular staff |
| **admin** | Full access to all features | Team leads, administrators |

**Password Requirements:**
- ✅ Minimum 12 characters
- ✅ Uppercase letters (A-Z)
- ✅ Lowercase letters (a-z) 
- ✅ Numbers (0-9)
- ✅ Symbols (!@#$%^&* etc)
- ❌ No common words or dictionary words

---

## Troubleshooting

### Error: "Login failed — bad TOTP from 'admin'"
**Most Common Cause: Using HEX secret instead of Base32**
- ❌ WRONG: Entered the 40-character hex string into Google Authenticator
- ✅ CORRECT: Use the short base32 secret from first-run dialog
- Fix: Delete `auth_db.enc`, restart app, **use Base32 secret only**

**Other Causes:**

1. **Time sync issue** - Authenticator app clock is out of sync
   - Open Google Authenticator → Settings → Correct time
   - Fix: Sync device time with internet
   - Most common on Android devices

2. **Old or expired code** - TOTP codes change every 30 seconds
   - Fix: Wait for next code to appear
   - Fix: Enter code **immediately** (before 30s window expires)
   - Fix: Never enter the same code twice

3. **Phone time is incorrect** - Device clock >30 seconds off
   - Fix: Enable automatic time sync on phone
   - Fix: Go to Settings → Date & Time → use automatic time
   - Fix: Check if phone time matches computer time

4. **Entered code with spaces or wrong format**
   - Fix: Enter exactly 6 digits, no spaces or dashes
   - Example: `123456` (not `123-456` or `123 456`)

**Step-by-Step Recovery:**
```
1. Open Google Authenticator settings
2. Look for "Correct time" or "Sync time" option
3. Let it automatically sync
4. Wait 30 seconds for code to refresh
5. Try login with new code
6. If still fails: Delete auth_db.enc, restart, re-add Base32 secret
```

### Error: "Login failed — unknown user 'admin'"
**Solution:** Database is empty. Auto-creation might have failed:
1. Delete `auth_db.enc`
2. Restart the app
3. Follow first-run setup again
4. **Pay attention: Use Base32 secret, NOT hex**

### Error: "Account locked — retry in 300s"
**Cause:** Too many failed login attempts (5 attempts = 5 min lockout)
**Solution:** Wait 5 minutes, then try again with:
- Correct username
- Correct password
- **Fresh TOTP code from Google Authenticator**

### Lost TOTP Secret?
If you lose your TOTP secret or think you entered the wrong one:
1. Delete `auth_db.enc`
2. Restart app
3. **Follow first-run setup carefully**
4. **Use the Base32 secret** (the shorter one, not 40-character hex)
5. Re-add to Google Authenticator and verify code matches

### Verify TOTP is Working:
When adding to Google Authenticator:
- You should see a 6-digit code **immediately** after adding
- This code should **match the code shown** in SecureCrypt dialog
- Code changes every 30 seconds
- If not matching: delete and re-add with correct Base32 secret

---

## Password Requirements
- **Minimum 12 characters**
- Must contain uppercase, lowercase, numbers, and symbols
- Examples:
  - ✅ `SecureCrypt@Admin123`
  - ✅ `MyP@ssw0rd!Secure`
  - ❌ `admin` (too short)
  - ❌ `password123` (no uppercase/symbol)

---

## Environment Variables

### SC_MASTER_KEY
For automated/headless deployments:
```bash
export SC_MASTER_KEY="your-master-password"
python main.py
```

The app will derive a consistent 32-byte key from this password.

---

## Security Best Practices

1. **Master Password**
   - Use a strong, unique password
   - Never share it
   - Write it down securely (encrypted password manager)

2. **TOTP Secret**
   - Save in secure location
   - Do not share
   - Back up (especially if using phone app)

3. **Session Tokens**
   - Auto-expire after 30 minutes of inactivity
   - Auto-rotate every 10 minutes
   - Invalidated when password changes

4. **Passwords**
   - Change after first login
   - Use strong, unique passwords
   - Never reuse across accounts

5. **Audit Log**
   - Check Logs tab for suspicious activity
   - Review login timestamps and IPs
   - Investigate unknown logins

---

## File Locations

```
SecureCrypt/
├── auth_db.enc          ← Encrypted user database
├── secure_storage.enc   ← Encrypted sensitive data
├── auth/
│   ├── login_system.py
│   ├── login_gui.py
│   └── setup_admin.py
└── main.py
```

---

## How Authentication Works (Technical)

### Login Flow
```
1. Username lookup → User exists?
2. Account active? → Check if disabled
3. Brute-force check? → Check lockout status
4. Password verification → PBKDF2-SHA256 (600K iterations)
5. TOTP verification → RFC 6238 with ±1 time window
6. Session creation → 256-bit cryptographic token
7. Key rotation → Every 10 minutes (automatic)
```

### Password Hashing
```
salt = random(16 bytes)
hash = PBKDF2-SHA256(password, salt, iterations=600_000, length=32)
store: (salt, hash)
```

### TOTP Implementation
```
counter = floor(time.time() / 30)  ← 30-second steps
code = HOTP(secret, counter) % 1_000_000
verify(input_code, ±1 time window)
```

---

## Quick Start

```bash
# 1. First run - will ask for master password
python main.py

# 2. Authenticate with auto-created admin account
# Username: admin
# Password: SecureCrypt@Admin123
# TOTP: (from authenticator app)

# 3. Main application opens!
```

---

## Support

If issues persist:
1. Check logs in 📋 Logs tab
2. Delete `auth_db.enc` to reset
3. Restart and follow setup again
4. Ensure authenticator app is time-synced
5. Check master password spelling (case-sensitive)

---

**Last Updated:** 2026-04-05  
**System:** SecureCrypt v2.0.0
