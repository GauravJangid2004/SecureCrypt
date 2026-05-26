<div align="center">

#  SecureCrypt

### End-to-End Encrypted Traffic Protection — Multi-Cipher

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.5%2B-41CD52?style=flat-square&logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![Cryptography](https://img.shields.io/badge/cryptography-41.0%2B-FF6B6B?style=flat-square)](https://cryptography.io)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)](https://github.com)

*A desktop application for encrypted TCP tunneling, peer-to-peer messaging, HTTP/HTTPS proxy, and secure file transfer — all backed by modern cryptography.*

---

</div>

##  Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Cryptography](#cryptography)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Two-Laptop E2E Setup](#two-laptop-e2e-messaging-setup)
- [Configuration](#configuration)
- [Security Model](#security-model)
- [Directory Structure](#directory-structure)


---

## 🔍 Overview

SecureCrypt is a Python desktop application that gives you full control over encrypted network traffic. Whether you need to tunnel TCP connections through an encrypted channel, route browser traffic through a local proxy, or chat securely with a peer on your LAN — SecureCrypt handles it with strong, modern cryptography and zero reliance on third-party servers.

Everything runs locally. No cloud. No accounts. No telemetry.

---

## ✨ Features

### 🔒 Encryption
- **12 cipher modes** — AES-GCM, AES-CBC, AES-CTR, ChaCha20-Poly1305, Camellia-CBC, 3DES-CBC, Blowfish-CBC
- **AEAD ciphers** (AES-GCM, ChaCha20-Poly1305) with built-in authentication tags
- **Non-AEAD ciphers** protected with Encrypt-then-MAC (HMAC-SHA256)
- **RSA-4096** for identity signing and verification
- **ECDH on SECP384R1** for ephemeral session key agreement (forward secrecy)
- **HKDF** for key derivation from ECDH shared secrets

### 🖧 Encrypted TCP Tunnel
- Multi-cipher negotiation during 4-step ECDH handshake
- Server and client both specify cipher preference lists — best common cipher wins
- Optional TCP forwarding to a backend service
- Live cipher update without restarting the server
- Session tracking with per-session byte counters

### 🔀 HTTP/HTTPS Proxy
- CONNECT tunnel support for HTTPS traffic
- HTTP forwarding through the encrypted tunnel
- Domain blocklist
- PAC file served at `http://127.0.0.1:8080/proxy.pac`
- System proxy auto-configuration (Windows, macOS, GNOME)
- One-click tunnel attachment — proxy routes through your tunnel session

### 💬 E2E Peer-to-Peer Messaging
- RSA-4096 identity keys with SHA-256 fingerprints
- Per-session ephemeral ECDH key exchange — MITM-resistant (relay cannot forge keys)
- Every message encrypted with the negotiated cipher and RSA-signed
- Peer discovery and key exchange via a local relay server
- Any cipher from the factory can be used per session

### 📁 Encrypted File Transfer
- Files split into 512 KB chunks, each encrypted with the session cipher
- SHA-256 hash of the entire file, RSA-signed by the sender
- Receiver verifies both hash and signature before accepting
- Progress bar during send and receive

### 🗝 Key Manager
- Generate and persist RSA-4096 or ECC-P384 key pairs
- Optional password encryption for private keys
- View and delete keys from within the app

### 🔐 Crypto Tools Playground
- AES-256-GCM encrypt / decrypt with a generated or pasted key
- SHA-256, SHA-512, BLAKE2b hashing
- RSA-4096 round-trip test (keygen → encrypt → decrypt → sign → verify)
- ECDH shared-secret derivation test (Alice ↔ Bob)

---

## 🏗 Architecture

```
SecureCrypt/
│
├── main.py                  ← PyQt6 GUI — all 8 tabs
│
├── config/
│   └── settings.py          ← Centralised config (ports, paths, defaults)
│
├── core/
│   ├── crypto_engine/       ← All cryptographic primitives
│   │   ├── symmetric_base.py    Abstract SymmetricCipher interface
│   │   ├── cipher_factory.py    CipherFactory — create any cipher by name
│   │   ├── aes_crypto.py        AES-GCM / CBC / CTR
│   │   ├── chacha_crypto.py     ChaCha20-Poly1305
│   │   ├── camellia_crypto.py   Camellia-CBC
│   │   ├── blowfish_crypto.py   Blowfish-CBC (legacy)
│   │   ├── des_crypto.py        3DES-CBC (legacy)
│   │   ├── ecc_crypto.py        ECDH + ECDSA (SECP384R1)
│   │   ├── rsa_crypto.py        RSA-OAEP + RSA-PSS
│   │   └── hash_crypto.py       SHA-256/512, BLAKE2b, PBKDF2, Scrypt
│   │
│   ├── e2e_engine.py        ← E2E identity, sessions, key exchange
│   └── file_transfer.py     ← Chunked encrypted file send/receive
│
├── traffic/
│   ├── handshake.py         ← 4-step ECDH handshake + cipher negotiation
│   ├── session_manager.py   ← Session lifecycle, encrypt/decrypt framing
│   ├── tunnel_server.py     ← Encrypted TCP tunnel server + client
│   ├── proxy_client.py      ← HTTP/HTTPS proxy with tunnel support
│   ├── relay_server.py      ← P2P relay (routes E2E messages, no decryption)
│   ├── peer_client.py       ← Peer client (connects to relay, sends messages/files)
│   └── exit_node.py         ← Internet exit point for tunnelled traffic
│
└── utils/
    ├── framing.py           ← Length-prefixed binary wire protocol
    ├── key_manager.py       ← RSA / ECC key persistence
    ├── random_gen.py        ← Cryptographically-secure random values
    └── secure_storage.py    ← AES-GCM encrypted key-value store (PBKDF2)
```

### Data flow — Tunnel mode

```
Browser ──► Local Proxy ──► Encrypt (negotiated cipher)
                                │
                         Tunnel (TCP)
                                │
                         Exit Node ──► Decrypt ──► Internet
```

### Data flow — E2E Messaging

```
Alice                          Relay Server                        Bob
  │                                 │                               │
  │── ECDH pub (RSA-signed) ───────►│── route ──────────────────►   │
  │                                 │                               │── ECDH pub (RSA-signed) ──►│
  │◄─────────────────────── route ──│◄──────────────────────────────│
  │                                 │                               │
  │  Derive shared session key (ECDH + HKDF)                        │
  │                                 │                               │
  │── Encrypt(msg) + RSA-sign ─────►│── route ──────────────────►   │
  │                                 │                  Verify sig + Decrypt
```

The relay server routes encrypted blobs — it **cannot read messages or forge keys**.

---

## 🔐 Cryptography

### Cipher Registry

| Name | Key | Auth | Speed |
|------|-----|------|-------|
| `AES-256-GCM` ⭐ | 256-bit | AEAD | Fast (AES-NI) |
| `CHACHA20-POLY1305` ⭐ | 256-bit | AEAD | Fast (no AES-NI needed) |
| `AES-192-GCM` | 192-bit | AEAD | Fast |
| `AES-128-GCM` | 128-bit | AEAD | Very Fast |
| `AES-256-CBC` | 256-bit | HMAC-SHA256 | Fast |
| `AES-256-CTR` | 256-bit | HMAC-SHA256 | Fast |
| `AES-192-CBC` | 192-bit | HMAC-SHA256 | Fast |
| `AES-128-CBC` | 128-bit | HMAC-SHA256 | Fast |
| `CAMELLIA-256-CBC` | 256-bit | HMAC-SHA256 | Fast |
| `CAMELLIA-128-CBC` | 128-bit | HMAC-SHA256 | Fast |
| `3DES-CBC` | 112-bit eff. | HMAC-SHA256 | Slow (legacy) |
| `BLOWFISH-128-CBC` | 128-bit | HMAC-SHA256 | Fast (legacy) |

> ⭐ Recommended for new deployments. AEAD ciphers provide confidentiality + integrity in a single pass.

### Wire Protocol — Frame layout

```
┌────────────────┬──────────────┬────────────────────────────┐
│  Length (4B)   │  Type (1B)   │  Payload (N bytes)         │
│  big-endian    │  0x01–0xFF   │  encrypted or plaintext    │
└────────────────┴──────────────┴────────────────────────────┘
```

### Handshake — 4 steps

```
Client                                        Server
  │── HELLO (ciphers[], ECDH pub, nonce) ──►  │
  │◄─ RESPONSE (cipher, ECDH pub, nonce) ──   │
  │   Both derive: HKDF(ECDH shared, nonces)  │
  │── FINISH (HMAC proof client) ───────────► │
  │◄─ FINISH (HMAC proof server) ──────────   │
```

---

## 📦 Installation

### Requirements

- Python **3.11** or newer
- pip

### Clone & install

```bash
git clone https://github.com/GauravJangid2004/SecureCrypt.git
cd SecureCrypt
pip install -r requirements.txt
```

### `requirements.txt`

```
cryptography>=41.0.0
PyQt6>=6.5.0
```

### Run

```bash
python main.py
```

---

## 🚀 Quick Start

### 1 — Encrypted tunnel (single machine test)

**Terminal A — Server**
```bash
python main.py
# Go to "Tunnel Server" tab → click "▶ Start Server"
```

**Terminal B — Client**
```bash
python main.py
# Go to "Tunnel Client" tab → Remote Host: 127.0.0.1 → click "⚡ Connect"
# Negotiated cipher appears in Session Info
```

### 2 — HTTP/HTTPS proxy

1. Start the Tunnel Server (step above)
2. Connect the Tunnel Client
3. Go to **Proxy** tab → click **▶ Start Proxy**
4. Click **🔗 Attach Tunnel** — proxy now routes through the encrypted tunnel
5. Set your browser proxy to `127.0.0.1:8080`

### 3 — Encrypt a message

Go to **🔐 Crypto Tools** tab:
1. Click **⟳ Generate** to create an AES-256 key
2. Type text in the Plaintext box → **🔒 Encrypt**
3. Copy the hex output, paste it back → **🔓 Decrypt**

---

## 💬 Two-Laptop E2E Messaging Setup

> This is the most common setup question — follow these steps exactly.

### Laptop A (relay host)

1. Open SecureCrypt
2. Go to **💬 E2E Messaging** tab
3. Set **Username** (e.g. `alice`)
4. Click **▶ Start Relay** — the relay binds on `0.0.0.0:9091`
5. Note your **LAN IP** shown in the green banner (e.g. `192.168.1.10`)
6. Keep **Relay Host** as `127.0.0.1` (you connect to your own relay locally)
7. Click **⚡ Connect & Register**

### Laptop B (remote peer)

1. Open SecureCrypt
2. Go to **💬 E2E Messaging** tab
3. Set **Username** (e.g. `bob`)
4. Set **Relay Host** to Laptop A's LAN IP (e.g. `192.168.1.10`)
5. Click **🔌 Test Connection** — should say ✅ reachable
6. Click **⚡ Connect & Register**

### Establish E2E session (from either laptop)

1. Click **🔄 Refresh Peers** — the other user appears with a 🟢 icon
2. Select them in the list
3. Choose a cipher (default: `AES-256-GCM`)
4. Click **🔐 Establish E2E Session**
5. Both sides see `✅ E2E established` in the chat — start messaging!

### Troubleshooting connection issues

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| "Connection refused" | Relay not started | Click ▶ Start Relay on Laptop A first |
| "Timeout" | Wrong IP or firewall | Check LAN IP in banner; allow port 9091 in firewall |
| Only `127.0.0.1` shown in banner | No network adapter / VPN interference | Enter IP manually in the override field |
| Peer doesn't appear after Refresh | Both on same laptop | Use two different usernames on two real machines |
| E2E session fails | Peer list out of date | Click 🔄 Refresh Peers to fetch fresh public keys |

### Firewall — required port

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| `9091` | TCP | inbound on Laptop A | Relay server (E2E messaging) |
| `9090` | TCP | inbound | Tunnel server (optional) |
| `8080` | TCP | localhost only | Local proxy (optional) |

---

## ⚙ Configuration

All defaults live in `config/settings.py`:

```python
# Network
PROXY_HOST   = "127.0.0.1"
PROXY_PORT   = 8080
TUNNEL_HOST  = "0.0.0.0"
TUNNEL_PORT  = 9090
BUFFER_SIZE  = 65536        # 64 KB read buffer

# Cryptography
DEFAULT_CIPHER = "AES-256-GCM"
RSA_KEY_SIZE   = 4096
ECC_CURVE      = "SECP384R1"
AES_KEY_SIZE   = 32         # 256-bit

# Sessions
SESSION_TIMEOUT   = 3600    # seconds — idle sessions are expired
HANDSHAKE_TIMEOUT = 30      # seconds
```

Change these values and restart the app — no rebuild needed.

---

## 🛡 Security Model

### What SecureCrypt protects against

| Threat | Protection |
|--------|-----------|
| Passive eavesdropping on LAN | AES-256-GCM or ChaCha20-Poly1305 encryption |
| Active MITM on tunnel | ECDH public keys bound to session via HMAC finish |
| MITM on E2E key exchange | ECDH public keys RSA-signed with identity key |
| Message tampering | AEAD tag (GCM/Poly1305) or HMAC-SHA256 |
| Replay attacks | Fresh nonce/IV per message; session IDs |
| Key compromise (future sessions) | Ephemeral ECDH per session = forward secrecy |
| File corruption in transit | SHA-256 hash verified after reassembly |
| Impersonation in file transfer | SHA-256 hash RSA-signed by sender |
| Relay reading messages | Relay only sees encrypted blobs, no session key |

### Key derivation chain

```
Password ──PBKDF2(600,000 iter)──► AES-256 key ──► Encrypted storage

ECDH exchange ──HKDF-SHA256──► 32-byte session key
                                      │
                         ┌────────────┴────────────┐
                   enc_key[:N]              HMAC-SHA256(session_key,
                         │                  "securecrypt-mac-key-derivation-v1")
                   AES/Camellia/etc.             │
                                            mac_key (non-AEAD only)
```

---

## 📁 Directory Structure

```
securecrypt/
├── main.py                  GUI entry point
├── requirements.txt
├── README.md
│
├── config/
│   └── settings.py
│
├── core/
│   ├── __init__.py
│   ├── e2e_engine.py
│   ├── file_transfer.py
│   └── crypto_engine/
│       ├── __init__.py
│       ├── symmetric_base.py
│       ├── cipher_factory.py
│       ├── aes_crypto.py
│       ├── chacha_crypto.py
│       ├── camellia_crypto.py
│       ├── blowfish_crypto.py
│       ├── des_crypto.py
│       ├── ecc_crypto.py
│       ├── rsa_crypto.py
│       └── hash_crypto.py
│
├── traffic/
│   ├── __init__.py
│   ├── handshake.py
│   ├── session_manager.py
│   ├── tunnel_server.py
│   ├── proxy_client.py
│   ├── relay_server.py
│   ├── peer_client.py
│   └── exit_node.py
│
├── utils/
│   ├── __init__.py
│   ├── framing.py
│   ├── key_manager.py
│   ├── random_gen.py
│   └── secure_storage.py
│
├── keys/                    Generated key pairs (git-ignored)
└── downloads/               Received files (git-ignored)
```

---

### Running a quick sanity check

```bash
# In Crypto Tools tab — run both round-trip tests
# RSA: keygen → encrypt → decrypt → sign → verify — all ✅
# ECC: ECDH + sign/verify — all ✅

# In E2E tab — two-laptop test (see setup guide above)
```

---

<div align="center">

Built with [Python](https://python.org) · [PyQt6](https://pypi.org/project/PyQt6/) · [cryptography](https://cryptography.io)

*SecureCrypt is provided for educational and personal use.*
*Always verify key fingerprints out-of-band for maximum security.*

</div>
