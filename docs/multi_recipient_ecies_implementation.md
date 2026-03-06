# Multi-Recipient ECIES Implementation

## Overview

This implementation provides multi-recipient ECIES encryption supporting up to 25 recipients using hybrid encryption. The system uses Brainpool elliptic curves for key encryption and AES-GCM for payload encryption.

## Components

### 1. Key Block Format

The format is documented in `docs/multi_recipient_ecies_format.md`. Key features:
- Binary format with fixed header (16 bytes)
- Variable-length recipient key blocks
- Encrypted payload with authentication
- Supports 1-25 recipients

### 2. Callsign Key Store

**File:** `python/callsign_key_store.py`

Provides persistent storage for mapping radio amateur callsigns to public keys:
- JSON-based storage
- Callsign validation (ITU format)
- Key lookup by callsign
- Normalization (uppercase, trimmed)

**Usage:**
```python
from python.callsign_key_store import CallsignKeyStore

store = CallsignKeyStore()
store.add_key("W1ABC", public_key_pem)
public_key = store.get_key("W1ABC")
```

### 3. Brainpool key agreement (ECKA-EG)

**File:** `python/crypto_helpers.py`

`CryptoHelpers.brainpool_ecka_eg()` implements a BSI-style Elliptic Curve Key Agreement (ECKA-EG): ECDH shared secret plus HKDF with domain-separated `info`. Used where a single symmetric key must be derived from a Brainpool key agreement (e.g. for key encapsulation or protocol layering).

**Usage:**
```python
from python.crypto_helpers import CryptoHelpers

crypto = CryptoHelpers()
alice_priv, alice_pub = crypto.generate_brainpool_keypair("brainpoolP256r1")
bob_priv, bob_pub = crypto.generate_brainpool_keypair("brainpoolP256r1")

key_alice = crypto.brainpool_ecka_eg(alice_priv, bob_pub, key_length=32)
key_bob = crypto.brainpool_ecka_eg(bob_priv, alice_pub, key_length=32)
# key_alice == key_bob
```

### 4. Multi-Recipient ECIES

**File:** `python/multi_recipient_ecies.py`

Implements the encryption/decryption logic:
- Hybrid encryption (symmetric + asymmetric)
- HKDF key derivation
- AES-GCM or ChaCha20-Poly1305 authenticated encryption
- Format parsing and generation
- Optional sender authentication: `encrypt_and_sign()` / `verify_and_decrypt()` (sign the ciphertext with sender's Brainpool ECDSA; verify before decrypt)

**Usage:**
```python
from python.multi_recipient_ecies import MultiRecipientECIES

ecies = MultiRecipientECIES(curve="brainpoolP256r1", key_store_path=store_path)
encrypted = ecies.encrypt(plaintext, ["W1ABC", "K2XYZ"])
decrypted = ecies.decrypt(encrypted, "W1ABC", private_key_pem)

# Sender-authenticated (signature returned separately; transport both)
encrypted, sig = ecies.encrypt_and_sign(plaintext, ["W1ABC"], sender_private_key_pem)
plaintext = ecies.verify_and_decrypt(encrypted, "W1ABC", rec_private_key_pem, sig, sender_public_key_pem)
```

### 5. Tests

**Unit Tests:** `tests/test_multi_recipient_ecies.py`
- Single recipient encryption/decryption
- Multiple recipients (2, 5, 10, 15, 20, 25)
- All recipient counts (1-25)
- Known test vectors
- Error handling (wrong recipient, tampered data, etc.)
- Different curves
- Large payloads
- Callsign group isolation (no cross-group decryption)
- Brainpool ECKA-EG (`TestBrainpoolEckaEg`: same key both sides, domain separation, key length)
- Sender-authenticated multi-recipient (`encrypt_and_sign` / `verify_and_decrypt`, reject bad signature)

**Integration Tests:** `tests/integration_test_multi_recipient.py`
- Comprehensive round-trip tests
- All recipient counts (1-25)
- All supported curves
- Validates each recipient can decrypt

## Security Properties

1. **Forward Secrecy**: Each encryption uses a new ephemeral key pair
2. **Authenticated Encryption**: AES-GCM provides confidentiality and authenticity
3. **Key Independence**: Each recipient's encrypted key is independent
4. **Tamper Detection**: Authentication tags detect modification
5. **Efficient**: Symmetric encryption for payload, asymmetric only for keys

## Testing

Run unit tests:
```bash
python3 -m pytest tests/test_multi_recipient_ecies.py -v
```

Run integration tests:
```bash
python3 tests/integration_test_multi_recipient.py
```

## Limitations

- Maximum 25 recipients per message
- Callsigns limited to 10 ASCII characters
- Payload size limited to 4GB (32-bit length field)
- Requires OpenSSL/cryptography library

## Future Enhancements

- C++ GNU Radio blocks for real-time processing (existing blocks do not yet embed sender signature in format)
- Message port support for dynamic recipient lists
- Key rotation support
- Compression support
- Nitrokey/OpenPGP Card bridge for decrypt (private key operations on-card)
- Shamir's Secret Sharing for session key (K-of-N quorum decryption)
- HPKE-style high-level wrapper API

