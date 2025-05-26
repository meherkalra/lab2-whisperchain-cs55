# CS 55 Lab 2 WhisperChain+
# Meher Kalra & Atharv Agashe

**Anonymous Messaging with Role-Based Access Control**

WhisperChain+ is a secure and private platform that lets users send encrypted, anonymous messages while maintaining auditability, role-based permissions, and abuse resistance. The system enforces end-to-end encryption, RBAC, and tamper-resistant append only logging without compromising anonymity.

---

## Design Overview

WhisperChain+ uses RSA encryption, hashed tokens, and append-only logs to create a controlled yet anonymous compliment delivery platform. The system ensures:

- Senders remain anonymous but rate-limited (10 mins)
- Recipients decrypt messages privately using their private key and can flag abusive messages
- Moderators can act on abuse by freezing the sender without knowing sender identity
- Admins manage users and role assignment, but cannot access private content

---

## Architecture

```
.
├── client.py               # CLI interface for all users
├── utils/
│   ├── auth.py             # Registration, login, key generation
│   └── storage.py          # Manages users, messages, tokens, logs
├── crypto/
│   ├── tokens.py           # Token issuance, encryption, and validation
│   └── messages.py         # message encryption/decryption
├── data/
│   ├── private_keys/       # Each user's private key (.pem)
│   ├── public_keys.json    # All public keys (indexed by username)
│   ├── tokens.json         # One token per round, per user (hashed, encrypted)
│   ├── messages.json       # Encrypted messages + metadata
│   ├── users.json          # All user accounts + roles
│   └── audit_log.json      # Append-only action log
```

---

## Running the Project

### Requirements
- Python 3.8+
- `cryptography` library

### To Run
```bash
pip install cryptography
python client.py
```
