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

### 5. Shamir Secret Sharing (K-of-N quorum)

**File:** `python/shamir_secret_sharing.py`

With Shamir over a session key, you can encrypt a transmission so that the content is only recoverable when K of N designated operators each contribute their share. No single operator, and no coalition smaller than K, can read it alone. This is qualitatively different from the pairwise model: it enforces collective decision-making cryptographically rather than just socially.

Shamir's secret sharing over a prime field; the prime is the curve order of the chosen Brainpool curve (BSI TR 03111, RFC 5639). **All three Brainpool curve sizes are supported:** brainpoolP256r1 (31-byte max secret, 32-byte share encoding), brainpoolP384r1 (47-byte max secret, 48-byte share encoding), brainpoolP512r1 (63-byte max secret, 64-byte share encoding). Used for K-of-N quorum decryption of the session key.

- `split(secret, threshold_k, num_shares_n, curve=...)` / `reconstruct(shares, curve=..., secret_length=...)` for arbitrary secrets; use `curve="brainpoolP256r1"` (default), `"brainpoolP384r1"`, or `"brainpoolP512r1"`.
- `create_shamir_backed_key(threshold_k, num_shares_n, curve=...)` returns `(shares, session_key_32)` for 32-byte session keys; curve selects the prime field.
- `reconstruct_session_key(shares, curve=...)` recovers the 32-byte key from at least K shares.
- Helpers: `get_curve_prime(curve)`, `get_max_secret_bytes(curve=...)`, `get_share_value_bytes(curve)`, `SUPPORTED_CURVES`.

**Multi-recipient Shamir mode:** `MultiRecipientECIES.encrypt_shamir(plaintext, callsigns, threshold_k, curve=...)` produces a block (format version 0x02, 9-byte header with curve_id) where each recipient gets one share; any K recipients can combine shares and decrypt with `decrypt_shamir(block, collected_shares)`. Use `get_share_from_shamir_block(block, callsign)` to extract a recipient's share. Curve can be any of the three Brainpool curves (defaults to the instance curve).

### 6. HPKE-style wrapper

**File:** `python/hpke_brainpool.py`

`HPKEBrainpool` provides a single entry point to reduce misuse and simplify flowgraph design:

- `seal(plaintext, recipient_callsigns)` / `open(ciphertext, my_callsign, my_private_key_pem)` for unauthenticated encryption.
- `seal_with_auth(...)` / `open_with_auth(...)` for sender-authenticated encryption (ECDSA over the ciphertext).

Uses `MultiRecipientECIES` under the hood with configurable curve and symmetric cipher.

### 7. Nitrokey / OpenPGP Card bridge

**File:** `python/nitrokey_bridge.py`

When the recipient's private key is on an OpenPGP Card (e.g. Nitrokey), decryption can be performed with the key never leaving the device. The C++ block `brainpool_ecies_multi_decrypt` supports this: set `key_source="opgp_card"` and `recipient_key_identifier=<keygrip>` (40 hex chars from `gpg --list-secret-keys --with-keygrip`).

- `decrypt_with_card(encrypted_block, recipient_callsign, keygrip)` raises `NotImplementedError` in standalone Python with instructions to use the C++ block.
- `get_keygrip_from_key_id(key_identifier)` resolves a GnuPG key ID or fingerprint to a keygrip via `gpg`.

### 8. Tests

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

**Unit Tests:** `tests/test_shamir_hpke_nitrokey.py`
- Shamir split/reconstruct for P256, P384, P512 (curve parameter); 32-byte session key create/reconstruct for all curves
- get_curve_prime, get_max_secret_bytes, get_share_value_bytes
- Multi-recipient Shamir encrypt/decrypt (K-of-N) for P256, P384, P512 and get_share_from_shamir_block
- HPKEBrainpool seal/open and seal_with_auth/open_with_auth
- Nitrokey bridge decrypt_with_card (NotImplementedError), get_keygrip_from_key_id (optional, with gpg)

**Integration Tests:** `tests/integration_test_multi_recipient.py`
- Comprehensive round-trip tests
- All recipient counts (1-25)
- All supported curves
- Validates each recipient can decrypt

## Standards compatibility

- **BSI TR 03111:** Brainpool curves (P256r1, P384r1, P512r1) and ECKA-EG style key derivation.
- **RFC 5639:** Brainpool curve orders used as Shamir prime field (same as curve scalar field).
- **NIST:** Underlying symmetric primitives (AES-GCM, ChaCha20-Poly1305) and test vectors where applicable.

## Available APIs

**Shamir low-level**

- `split(secret, threshold_k, num_shares_n, prime, curve)` — max secret: 31 / 47 / 63 bytes for P256 / P384 / P512
- `reconstruct(shares, prime, secret_length, curve)`
- `create_shamir_backed_key(threshold_k, num_shares_n, prime, curve)` — returns a 32-byte session key
- `reconstruct_session_key(shares, prime, curve)`
- `get_curve_prime(curve)`, `get_max_secret_bytes(curve)`, `get_share_value_bytes(curve)`, `SUPPORTED_CURVES`

**MultiRecipientECIES**

- `encrypt(plaintext, recipients)` / `decrypt(ciphertext, callsign, private_key_pem)`
- `encrypt_and_sign(...)` / `verify_and_decrypt(...)`
- `encrypt_shamir(plaintext, callsigns, threshold_k, curve)` / `decrypt_shamir(...)` / `get_share_from_shamir_block(...)`

**HPKE-style**

- `HPKEBrainpool.seal(...)` / `open(...)` / `seal_with_auth(...)` / `open_with_auth(...)`

**Nitrokey / card**

- `get_keygrip_from_key_id(...)`, `decrypt_with_card(...)` (documented stub), C++ block with `key_source="opgp_card"`

## Independent use — mix and match freely

| You want | Use |
|----------|-----|
| ECIES only | `MultiRecipientECIES.encrypt` / `decrypt` |
| Shamir only | `split` / `reconstruct` or `create_shamir_backed_key` / `reconstruct_session_key` |
| ECIES + Shamir (K-of-N quorum) | `encrypt_shamir` / `decrypt_shamir` |
| Clean high-level API | `HPKEBrainpool.seal` / `open` |
| Hardware-backed keys | Nitrokey C++ block or `decrypt_with_card` |

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
- Standalone Python helper for on-card decryption (optional; currently use C++ block with key_source=opgp_card)
- HPKE-style API in C++ or GRC (Python API implemented in `hpke_brainpool.py`)

