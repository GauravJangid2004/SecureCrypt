# User Management System - How It Works

## Overview Diagram

```
SecureCrypt User Management Flow
═══════════════════════════════════════════════════════════════

FIRST TIME SETUP
─────────────────────────────────────────────────────────────
  python main.py
         ↓
  Enter Master Password
         ↓
  [Auto-creates default admin account]
         ↓
  Login with admin credentials
         ↓
  Main app opens ✅


ADDING MORE USERS
─────────────────────────────────────────────────────────────
  python add_user.py
         ↓
  Enter Master Password (security check)
         ↓
  Enter new username
         ↓
  Enter password (12+ chars, mixed case, numbers, symbols)
         ↓
  Choose role (User or Admin)
         ↓
  [System generates TOTP secret]
         ↓
  Display Base32 secret for Google Authenticator
         ↓
  User adds secret to their phone ✅


SUBSEQUENT LOGINS (All Users)
─────────────────────────────────────────────────────────────
  python main.py
         ↓
  Enter Master Password
         ↓
  Any user can now log in:
    - Username: their username
    - Password: their password
    - TOTP: 6-digit code from their phone
         ↓
  Session created with session token
         ↓
  Session token refreshes every 10 minutes
         ↓
  Session expires after 30 minutes idle ✅
```

---

## User Lifecycle

### Phase 1: Creation
```
Admin runs:         python add_user.py
                    ↓
User created with:  • Unique username
                    • Strong password (hashed with PBKDF2)
                    • TOTP secret (for MFA)
                    • Role assignment (user/admin)
                    • Active status = True
```

### Phase 2: First Login
```
User enters:        username
                    password
                    TOTP code (from Google Authenticator)
                    ↓
System verifies:    1. User exists?
                    2. Account active?
                    3. Not locked out?
                    4. Password hash matches?
                    5. TOTP code valid?
                    ↓
On success:         Session token created
                    Session token loaded into memory
                    User can use app ✅
```

### Phase 3: Session Management
```
Every 10 minutes:   Session key rotates
                    ↓
Every API call:     Session validated
                    ↓
After 30 min idle:  Session expires
                    User must log in again
```

### Phase 4: Password Change
```
User changes pwd:   Old sessions invalidated
                    ↓
User must log in:   With new password
                    ↓
New session token:  Created with new credentials
```

---

## Files and Their Purposes

```
SecureCrypt/
├── main.py                      ← Start here (creates first admin)
├── add_user.py                  ← Use to add more users ⭐
├── AUTHENTICATION_SETUP.md      ← Detailed auth docs
├── ADD_USERS_GUIDE.md           ← Guide for adding users ⭐
├── auth/
│   ├── login_system.py          ← Core authentication logic
│   ├── login_gui.py             ← Login dialog UI
│   └── setup_admin.py           ← Admin account setup
├── auth_db.enc                  ← Encrypted user database
│                                   (only after first run)
└── requirements.txt             ← Python dependencies
```

---

## Database Security

### How Users Are Stored (auth_db.enc)

```
auth_db.enc (Encrypted)
├── Encrypted with: Master key (derived from master password)
├── Format: JSON (encrypted at rest with AES-256-GCM)
└── Contains:
    {
      "username": {
        "username": "alice",
        "password_hash": "pbkdf2_hash...",
        "password_salt": "random_16bytes...",
        "totp_secret": "hex_string...",
        "role": "user",
        "active": true,
        "locked_until": 0,
        "failed_attempts": 0
      }
    }
```

### Security Details

**Password Storage:**
- Algorithm: PBKDF2-SHA256
- Iterations: 600,000 (NIST recommended)
- Salt: Random 16 bytes per user
- Never stored in plaintext ✅

**TOTP Storage:**
- Format: Hex internally, Base32 for display
- Used for Multi-Factor Authentication
- Time-based (syncs with phone time)
- Verifies with ±30 second window ✅

**Master Key:**
- Derived from master password
- Algorithm: PBKDF2-SHA256
- Salt: Fixed "securecrypt-master-salt-v1"
- Encrypts entire database ✅

---

## User Types and Permissions

### Regular User (role="user")
```
Allowed:
  ✓ Log in
  ✓ Change own password
  ✓ Use core features
  ✓ View own audit logs

Not allowed:
  ✗ Add/remove users
  ✗ Modify other users
  ✗ View full audit logs
  ✗ Change system settings
```

### Admin User (role="admin")
```
Allowed:
  ✓ Log in
  ✓ Change own password
  ✓ Use all features
  ✓ Add/remove users
  ✓ Change user passwords
  ✓ View full audit logs
  ✓ Configure system

Responsibility:
  • Keep master password safe
  • Manage user accounts
  • Review audit logs for suspicious activity
```

---

## Common Operations

### Add a User
```bash
python add_user.py
# Interactive script guides you through
```

### Change a Password (User)
```
In app:
  1. Settings/Account menu
  2. Change password
  3. Enter old password + new password
  4. All other sessions are invalidated
```

### Reset a Password (Admin)
```python
# See ADD_USERS_GUIDE.md for Python code
```

### Check Who's Logged In
```
In app:
  Logs tab → Filter by LOGIN_OK events
  Shows timestamps, user, IP address
```

### Review Activity
```
In app:
  Logs tab → View all events
  - Login successes/failures
  - Password changes
  - Account lockouts
  - Failed TOTP attempts
```

---

## Security Best Practices

### For Admins
1. **Master Password**
   - Write it down and store securely (password manager)
   - Never send it via email
   - Use the same one every time
   - Change it if anyone sees it

2. **User Accounts**
   - Create strong initial passwords
   - Tell users to change on first login
   - Review audit logs monthly
   - Disable inactive user accounts

3. **TOTP Secrets**
   - Keep records of TOTP secrets
   - Have backup recovery process
   - If user loses phone: delete their account and recreate

### For Users
1. **Password**
   - Change after first login
   - Never share with anyone
   - Use different password than other apps
   - Change if you think it's compromised

2. **TOTP Secret**
   - Save in authenticator app
   - Backup if phone is important
   - If you lose phone: contact admin to get new code

3. **Sessions**
   - Sessions auto-expire after 30 minutes
   - Log in again after break
   - Don't share your login credentials

---

## Troubleshooting

### "User 'alice' already exists"
- Username is taken
- Choose different username
- Or contact admin to delete old account

### "Wrong master password"
- Password doesn't match
- It must match what you use in main.py
- Contact admin if forgotten

### "auth_db.enc not found"
- Database hasn't been created
- Run `python main.py` first to create it

### "Invalid TOTP code"
- Token from Google Authenticator doesn't match
- Check phone time is synced
- Wait 30 seconds for fresh code
- Try new code

---

## Quick Reference

| Task | Command |
|------|---------|
| Start app | `python main.py` |
| Add user | `python add_user.py` |
| View users | Look in logs / auth_db.enc |
| Reset password | Contact admin with Python script |
| View audit log | In app → Logs tab |
| Change own password | In app → Settings |
| Delete user | Contact admin with Python script |

---

**For detailed instructions, see:**
- [AUTHENTICATION_SETUP.md](AUTHENTICATION_SETUP.md) - Complete auth guide
- [ADD_USERS_GUIDE.md](ADD_USERS_GUIDE.md) - Step-by-step user creation
- auth/login_system.py - Source code
