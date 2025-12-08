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

### 3. Multi-Recipient ECIES

**File:** `python/multi_recipient_ecies.py`

Implements the encryption/decryption logic:
- Hybrid encryption (symmetric + asymmetric)
- HKDF key derivation
- AES-GCM authenticated encryption
- Format parsing and generation

**Usage:**
```python
from python.multi_recipient_ecies import MultiRecipientECIES

ecies = MultiRecipientECIES(curve="brainpoolP256r1")
encrypted = ecies.encrypt(plaintext, ["W1ABC", "K2XYZ"], key_store)
decrypted = ecies.decrypt(encrypted, "W1ABC", private_key_pem)
```

### 4. Tests

**Unit Tests:** `tests/test_multi_recipient_ecies.py`
- Single recipient encryption/decryption
- Multiple recipients (2, 5, 10, 15, 20, 25)
- All recipient counts (1-25)
- Known test vectors
- Error handling (wrong recipient, tampered data, etc.)
- Different curves
- Large payloads

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

- C++ GNU Radio blocks for real-time processing
- Message port support for dynamic recipient lists
- Key rotation support
- Compression support
- Additional authentication mechanisms

