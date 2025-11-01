# GNU Radio Linux Crypto Module

A GNU Radio module that provides **Linux-specific cryptographic infrastructure integration**, focusing on what's missing from existing crypto modules (gr-openssl, gr-nacl).

## Table of Contents

1. [What This Module Provides (Unique Features)](#what-this-module-provides-unique-features)
   - [Kernel Keyring Integration](#1-kernel-keyring-integration)
   - [Hardware Security Module Integration](#2-hardware-security-module-integration)
   - [Kernel Crypto API Integration](#3-kernel-crypto-api-integration)
2. [What This Module Does NOT Provide (Avoiding Duplication)](#what-this-module-does-not-provide-avoiding-duplication)
   - [Basic OpenSSL Operations (Use gr-openssl)](#basic-openssl-operations-use-gr-openssl)
   - [Modern Crypto (NaCl/libsodium) - Use gr-nacl](#modern-crypto-nacllibsodium---use-gr-nacl)
   - [GnuPG/OpenPGP Operations](#gnupgopenpgp-operations)
3. [Integration Architecture](#integration-architecture)
4. [Key Design Principles](#key-design-principles)
5. [Usage Flowchart](#usage-flowchart)
6. [Documentation](#documentation)
7. [Usage Examples](#usage-examples)
   - [Kernel Keyring as Key Source for gr-openssl](#kernel-keyring-as-key-source-for-gr-openssl)
   - [Hardware Security Module with gr-nacl](#hardware-security-module-with-gr-nacl)
   - [Brainpool Elliptic Curve Cryptography](#brainpool-elliptic-curve-cryptography)
8. [Dependencies](#dependencies)
   - [Required](#required)
   - [Python Dependencies](#python-dependencies)
   - [Optional](#optional)
9. [Installation](#installation)
10. [Important Note](#important-note)
11. [Cryptographic Operations Overview](#cryptographic-operations-overview)
    - [Encryption (AES block)](#1-encryption-aes-block)
    - [Signing & Key Exchange (Brainpool ECC block)](#2-signing--key-exchange-brainpool-ecc-block)
    - [Common Use Pattern](#common-use-pattern)
12. [Supported Ciphers and Algorithms](#supported-ciphers-and-algorithms)
    - [Symmetric Encryption](#symmetric-encryption)
    - [Asymmetric Cryptography](#asymmetric-cryptography)
    - [Key Management](#key-management)
    - [Authentication Modes](#authentication-modes)
13. [Security & Testing](#security--testing)
14. [What You Actually Need to Extract/Create](#what-you-actually-need-to-extractcreate)
    - [Native C++ Blocks (Implemented)](#1-native-c-blocks-implemented)
    - [Integration Helpers (Implemented)](#2-integration-helpers-implemented)
    - [GNU Radio Companion Blocks (Implemented)](#3-gnu-radio-companion-blocks-implemented)
15. [Why This Approach?](#why-this-approach)
16. [Comparison with Existing Modules](#comparison-with-existing-modules)
17. [Cryptographic Algorithm Background](#cryptographic-algorithm-background)
    - [Cryptographic Ciphers Influenced by the NSA](#cryptographic-ciphers-influenced-by-the-nsa)
    - [Cryptographic Ciphers NOT Influenced by the NSA](#cryptographic-ciphers-not-influenced-by-the-nsa)
    - [Known Scandals Involving NSA and Cryptography](#known-scandals-involving-nsa-and-cryptography)

## What This Module Provides (Unique Features)

### 1. **Kernel Keyring Integration**
- **Unique to Linux**: Direct integration with Linux kernel keyring
- **Secure key storage**: Keys protected by kernel, not user space
- **Key management**: Add, retrieve, link, unlink keys from kernel keyring
- **No duplication**: This is NOT available in gr-openssl or gr-nacl

### 2. **Hardware Security Module Integration**  
- **Nitrokey support**: Hardware-based key storage and operations
- **TPM integration**: Trusted Platform Module support
- **Hardware acceleration**: Use hardware crypto when available
- **No duplication**: This is NOT available in existing modules

**Nitrokey Functionality with libnitrokey Library**

The `nitrokey_interface` block provides full Nitrokey hardware security module integration when `libnitrokey` is available at compile time.

**When libnitrokey is available:**
- `is_nitrokey_available()` → Returns `TRUE` if Nitrokey device is connected
- `is_key_loaded()` → Returns `TRUE` if key data is loaded from password safe slot
- `get_key_size()` → Returns size of loaded key data
- `load_key_from_nitrokey()` → Loads key from specified password safe slot (0-15)
- `get_available_slots()` → Returns list of slots that contain data
- `work()` → Outputs key data (repeating or single-shot based on `auto_repeat` setting)

**When libnitrokey is NOT available at compile time:**
- All functions return safe defaults (FALSE, 0, empty)
- `work()` outputs zeros
- Error messages indicate libnitrokey is not available

**To use Nitrokey functionality:**
1. Install `libnitrokey-dev` package: `sudo apt-get install libnitrokey-dev` (or equivalent)
2. Ensure CMake detects libnitrokey (should happen automatically via pkg-config)
3. Rebuild the module: `cmake .. && make`
4. Connect a Nitrokey device to your system
5. Store key data in Nitrokey password safe slots (0-15) using Nitrokey App or CLI tools

**Implementation Notes:**
- Uses libnitrokey C++ API (`NitrokeyManager`)
- Reads key data from Nitrokey password safe slots
- Supports all Nitrokey models (Pro, Storage, etc.)
- Thread-safe with proper mutex protection
- Gracefully handles device disconnection

### 3. **Kernel Crypto API Integration**
- **AF_ALG sockets**: Direct use of Linux kernel crypto subsystem
- **Hardware acceleration**: CPU crypto instructions via kernel
- **Performance**: Bypass user-space crypto libraries when possible
- **No duplication**: This is NOT available in existing modules

## What This Module Does NOT Provide (Avoiding Duplication)

### **Basic OpenSSL Operations (Use gr-openssl)**

**What gr-openssl provides:**
- **Symmetric Encryption**: AES (all key sizes and modes), DES, 3DES, Blowfish, Camellia
- **Hashing**: SHA-1, SHA-256, SHA-384, SHA-512, MD5
- **HMAC**: Message authentication codes
- **Asymmetric Cryptography**: RSA encryption/decryption, RSA signing/verification
- **Additional ECC Curves**: NIST curves (P-256, P-384, P-521), secp256k1
- **Key Derivation**: PBKDF2, scrypt
- **OpenSSL EVP API**: Comprehensive OpenSSL cryptographic operations

**Example using gr-openssl:**
```python
from gnuradio import gr, crypto, linux_crypto

# Use gr-openssl for AES encryption
tb = gr.top_block()
key = [0x01] * 32  # 256-bit key
iv = [0x02] * 16   # 128-bit IV
cipher_desc = crypto.sym_ciph_desc("aes-256-cbc", key, iv)
encryptor = crypto.sym_enc(cipher_desc)

# Use gr-openssl for SHA-256 hashing
hasher = crypto.hash("sha256")

# Use gr-openssl for RSA operations
rsa_encryptor = crypto.rsa_encrypt(public_key)
rsa_decryptor = crypto.rsa_decrypt(private_key)

# Optional: Use gr-linux-crypto kernel keyring as key source
keyring_src = linux_crypto.kernel_keyring_source(key_id=12345)
tb.connect(keyring_src, encryptor)
```

**Note**: The above API calls are conceptual examples. Consult gr-openssl documentation for exact function names and signatures.

**gr-linux-crypto integration**: Provides kernel keyring as secure key source for gr-openssl blocks.

### **Modern Crypto (NaCl/libsodium) - Use gr-nacl**

**What gr-nacl provides:**
- **Curve25519/X25519**: Elliptic curve Diffie-Hellman key exchange
  - Fast, secure key exchange
  - 256-bit security level
  - High performance on modern CPUs
- **Ed25519**: Elliptic curve digital signatures
  - Deterministic signatures
  - Fast signing and verification
  - 128-bit security level
- **ChaCha20-Poly1305**: Authenticated encryption
  - Stream cipher with authentication
  - AEAD (Authenticated Encryption with Associated Data)
  - RFC 8439 compliant
  - High performance, especially on ARM processors

**Example using gr-nacl:**
```python
from gnuradio import gr, nacl, linux_crypto

# Use gr-nacl for Curve25519/X25519 key exchange
tb = gr.top_block()

# X25519 key exchange (gr-nacl supports X25519)
alice_private = nacl.generate_private_key_curve25519()
alice_public = nacl.generate_public_key_curve25519(alice_private)
bob_private = nacl.generate_private_key_curve25519()
bob_public = nacl.generate_public_key_curve25519(bob_private)

# Shared secret via X25519
alice_shared = nacl.dh_curve25519(alice_private, bob_public)
bob_shared = nacl.dh_curve25519(bob_private, alice_public)
# alice_shared == bob_shared

# Use Ed25519 for digital signatures
message = b"Important message"
signature = nacl.sign_ed25519(message, alice_private)
is_valid = nacl.verify_ed25519(message, signature, alice_public)

# Use ChaCha20-Poly1305 for authenticated encryption
nonce = nacl.generate_nonce()
encrypted = nacl.encrypt_chacha20poly1305(message, alice_shared, nonce)
decrypted = nacl.decrypt_chacha20poly1305(encrypted, bob_shared, nonce)

# Optional: Use gr-linux-crypto Nitrokey for secure key storage
nitrokey_src = linux_crypto.nitrokey_interface(slot=1)
# Connect nitrokey key to nacl operations
```

**Note**: The above API calls are conceptual examples. Consult gr-nacl documentation for exact function names and signatures.

**gr-linux-crypto integration**: Provides hardware security modules (Nitrokey, kernel keyring) as secure key storage for gr-nacl operations.

**Why not duplicate?**
- gr-openssl and gr-nacl are mature, well-tested modules
- Avoiding duplication reduces maintenance burden
- Focus gr-linux-crypto on unique Linux-specific features

### **GnuPG/OpenPGP Operations**
- **Limited integration**: Provides subprocess-based GnuPG wrapper for session key exchange
- **PIN handling**: Uses GnuPG agent and pinentry programs (see documentation)
- **Not native blocks**: Python utilities only, not stream-processing blocks
- **See**: [GnuPG Integration Guide](docs/gnupg_integration.md) for setup, PIN handling, and usage patterns

**What is GnuPG?**

GnuPG (GNU Privacy Guard) is a hybrid encryption system that combines two types of cryptography:

1. **Symmetric-key encryption** - Fast encryption using the same key for both encrypting and decrypting. Used for the actual message data because it's fast.
2. **Public-key encryption** - Secure key exchange using separate public and private keys. Used to securely share the symmetric key.

**How it works:**

Instead of encrypting the entire message with slow public-key encryption, GnuPG:
- Generates a random "session key" (symmetric)
- Encrypts your message with the fast session key
- Encrypts the session key with the recipient's public key
- Sends both: encrypted session key + encrypted message

The recipient uses their private key to decrypt the session key, then uses the session key to decrypt your message. This gives you both speed (from symmetric encryption) and secure key exchange (from public-key encryption).

GnuPG also supports digital signatures to verify who sent a message and that it wasn't changed. It follows the OpenPGP standard, which is widely used for email encryption.

**References:**
- [Symmetric-key algorithms](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) - Same key for encryption and decryption
- [Public-key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) - Separate public/private keys
- [Hybrid cryptosystem](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) - Combining symmetric and public-key encryption

**Legal and Appropriate Uses for Amateur Radio:**

1. **Digital Signatures (Primary Use Case)**
   - Cryptographically sign transmissions to verify sender identity
   - Prevent callsign spoofing
   - Replace error-prone DTMF authentication
   - **Legal**: Digital signatures do not obscure content and are generally permitted

2. **Message Integrity**
   - Detect transmission errors
   - Verify message authenticity
   - Non-obscuring authentication tags
   - **Legal**: Integrity verification does not hide message content

3. **Key Management Infrastructure**
   - Secure key storage (Nitrokey, kernel keyring)
   - Off-air key exchange (ECDH)
   - Authentication key distribution
   - **Legal**: Key management does not encrypt on-air content

**Experimental and Research Uses:**

For experiments or research on frequencies where encryption is legally permitted:
- Encryption may be used in accordance with local regulations
- Users must verify applicable frequency bands and regulations
- This module provides the technical capability; users are responsible for legal compliance

**User Responsibility:**

**Critical:** Users must check local regulations before using cryptographic features.
- Encryption regulations vary by country and jurisdiction
- Frequency bands have different rules (amateur, ISM, experimental allocations)
- **The responsibility for legal compliance is 100% the user's**
- This module and its developers assume no liability for improper use
- Consult with local regulatory authorities (FCC, OFCOM, etc.) for specific requirements

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GNU Radio Application                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Integration Layer                           │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ gr-openssl      │ │ gr-nacl         │ │ gr-linux-    │ │
│  │ (OpenSSL ops)   │ │ (Modern crypto) │ │ crypto       │ │
│  └─────────────────┘ └─────────────────┘ └──────────────┘ │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Linux-Specific Layer                        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│  │ Kernel Keyring │ │ Hardware        │ │ Kernel       │ │
│  │ (Secure keys)  │ │ Security        │ │ Crypto API   │ │
│  └─────────────────┘ └─────────────────┘ └──────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Principles

### 1. **Don't Duplicate - Integrate!**
- **Use `gr-openssl`** for: AES, SHA, RSA, and other OpenSSL operations
- **Use `gr-nacl`** for: X25519 (Curve25519 key exchange), Ed25519 signatures, ChaCha20-Poly1305
- **Add thin wrappers** in gr-linux-crypto for: kernel keyring, hardware security modules, kernel crypto API

### 2. **Leverage Existing Tools**
- `keyctl` command for kernel keyring management
- `libnitrokey` for hardware security modules
- Existing GNU Radio crypto infrastructure

### 3. **Focus on What's Missing**
- **Kernel keyring integration** (not in existing modules)
- **Hardware security module bridges** (Nitrokey, TPM)
- **GNU Radio-specific helpers** (PDU crypto, stream crypto)

## Usage Flowchart

See [Usage Flowchart](docs/USAGE_FLOWCHART.md) for a detailed flowchart showing how to integrate gr-linux-crypto with gr-openssl and gr-nacl.

## Documentation

- [Usage Flowchart](docs/USAGE_FLOWCHART.md) - Integration patterns and workflows
- [GnuPG Integration Guide](docs/gnupg_integration.md) - GnuPG setup, PIN handling, and examples
- [Architecture Documentation](docs/architecture.md) - Module architecture and design
- [Examples](docs/examples.md) - Code examples and tutorials

## Usage Examples

### Kernel Keyring as Key Source for gr-openssl
```python
from gnuradio import gr, blocks, crypto, linux_crypto

# Create flowgraph
tb = gr.top_block()

# Load key from kernel keyring
key_source = linux_crypto.kernel_keyring_source(key_id=12345)

# Use with gr-openssl
cipher_desc = crypto.sym_ciph_desc("aes-256-cbc", key, iv)
encryptor = crypto.sym_enc(cipher_desc)

# Connect: keyring -> openssl encryption
tb.connect(key_source, encryptor)
```

### Hardware Security Module with gr-nacl
```python
from gnuradio import gr, nacl, linux_crypto

# Create flowgraph  
tb = gr.top_block()

# Load key from Nitrokey
nitrokey_source = linux_crypto.nitrokey_interface(slot=1)

# Use with gr-nacl
encryptor = nacl.encrypt_secret("nitrokey_key")

# Connect: nitrokey -> nacl encryption
tb.connect(nitrokey_source, encryptor)
```

### Brainpool Elliptic Curve Cryptography
```python
from gr_linux_crypto.crypto_helpers import CryptoHelpers

crypto = CryptoHelpers()

# Generate Brainpool key pair
private_key, public_key = crypto.generate_brainpool_keypair('brainpoolP256r1')

# ECDH key exchange
# Alice generates key pair
alice_private, alice_public = crypto.generate_brainpool_keypair('brainpoolP256r1')

# Bob generates key pair
bob_private, bob_public = crypto.generate_brainpool_keypair('brainpoolP256r1')

# Both compute shared secret
alice_secret = crypto.brainpool_ecdh(alice_private, bob_public)
bob_secret = crypto.brainpool_ecdh(bob_private, alice_public)
# alice_secret == bob_secret

# Derive encryption key from shared secret using HKDF
salt = crypto.generate_random_key(16)
info = b'gnuradio-encryption-key-v1'
encryption_key = crypto.derive_key_hkdf(alice_secret, salt=salt, info=info, length=32)

# ECDSA signing and verification
message = "Message to sign"
signature = crypto.brainpool_sign(message, private_key, hash_algorithm='sha256')
is_valid = crypto.brainpool_verify(message, signature, public_key, hash_algorithm='sha256')

# Key serialization
public_pem = crypto.serialize_brainpool_public_key(public_key)
private_pem = crypto.serialize_brainpool_private_key(private_key)
loaded_public = crypto.load_brainpool_public_key(public_pem)
loaded_private = crypto.load_brainpool_private_key(private_pem)
```



**OpenSSL Requirements:**
- Brainpool support requires OpenSSL 1.0.2 or later
- OpenSSL 3.x provides improved Brainpool support
- Accessible via standard EVP API for maximum compatibility

See `examples/brainpool_example.py` for a complete demonstration.

## Dependencies

### Required
- **GNU Radio 3.8+** (runtime and development packages)
- **Linux kernel with keyring support** (kernel modules)
- **keyutils library** (libkeyutils1)
- **libkeyutils-dev** (development package for keyutils)
- **Python 3.6+** with pip
- **CMake 3.16+**
- **C++17 compatible compiler** (GCC 7+ or Clang 5+)

### Python Dependencies
- **cryptography>=3.4.8** (for Python crypto helpers)
- **numpy>=1.20.0** (for numerical operations)
- **gnuradio>=3.8.0** (Python bindings)

### Optional
- **gr-openssl** (for OpenSSL integration)
- **gr-nacl** (for modern crypto integration)
- **libnitrokey** (for hardware security modules)
- **TPM libraries** (for TPM support)
- **OpenSSL development headers** (libssl-dev)
  - **OpenSSL 1.0.2+** required for Brainpool curve support
  - **OpenSSL 3.x** recommended for improved Brainpool support
- **libsodium development headers** (libsodium-dev)

## Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    libkeyutils-dev \
    gnuradio-dev \
    gnuradio-runtime \
    cmake \
    build-essential \
    pkg-config \
    python3-dev \
    python3-pip

# Install Python dependencies
pip3 install -r requirements.txt

# Optional: Install existing crypto modules
sudo apt-get install gr-openssl gr-nacl

# Optional: Install additional crypto libraries
sudo apt-get install libssl-dev libsodium-dev

# Build gr-linux-crypto
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

## Important Note

This module depends on the **libkeyutils-dev** package, which provides the development headers for the keyutils library. This package is required for:

- Kernel keyring operations (`keyctl` system calls)
- Key management functions
- Secure key storage integration

Without this package, the module will fail to compile due to missing `keyutils.h` header file.

## Cryptographic Operations Overview

This module provides two distinct types of cryptographic operations:

### 1. Encryption (AES block)
- **Purpose:** Confidentiality - hides data from unauthorized parties
- **Does NOT authenticate** who sent the data
- Uses symmetric keys (same key for encrypt/decrypt)

### 2. Signing & Key Exchange (Brainpool ECC block)
- **ECDSA Signing:** Proves authenticity and integrity
  - **Important:** Signing does NOT encrypt! Signed data is still readable by anyone
  - Use signing to prove "this came from me and wasn't modified"
- **ECDH Key Exchange:** Securely establish shared secrets
- **Key Generation:** Create public/private key pairs

### Common Use Pattern
1. Use ECDH to establish a shared AES key
2. Use AES to encrypt your signal data
3. Use ECDSA to sign the encrypted data (or metadata)

## Supported Ciphers and Algorithms

### Symmetric Encryption

**AES (Advanced Encryption Standard)**
- **AES-128** (128-bit keys)
  - CBC mode (Cipher Block Chaining)
  - GCM mode (Galois/Counter Mode with authentication)
  - ECB mode (Electronic Codebook)
- **AES-192** (192-bit keys)
  - CBC mode
  - ECB mode
- **AES-256** (256-bit keys)
  - CBC mode
  - GCM mode (Galois/Counter Mode with authentication)
  - ECB mode

**ChaCha20**
- **ChaCha20-Poly1305** (256-bit keys, 96-bit nonce)
  - Authenticated encryption with associated data (AEAD)
  - RFC 8439 compliant

### Asymmetric Cryptography

**Brainpool Elliptic Curves**
- **brainpoolP256r1** (256-bit curve)
  - ECDH (Elliptic Curve Diffie-Hellman) key exchange
  - ECDSA (Elliptic Curve Digital Signature Algorithm) signing/verification
- **brainpoolP384r1** (384-bit curve)
  - ECDH key exchange
  - ECDSA signing/verification
- **brainpoolP512r1** (512-bit curve)
  - ECDH key exchange
  - ECDSA signing/verification

### Key Management
- Kernel keyring integration (secure key storage)
- Hardware security modules (Nitrokey, TPM)
- Key serialization (PEM format)
- PKCS#7 padding for block ciphers
- Key derivation: PBKDF2 (password-based), HKDF (RFC 5869 for shared secrets)

### Authentication Modes
- **GCM** (Galois/Counter Mode) - for AES
- **Poly1305** - for ChaCha20
- HMAC (SHA-1, SHA-256, SHA-512)

**Note:** For additional algorithms (RSA, more ECC curves, etc.), use **gr-openssl** which provides comprehensive OpenSSL support.

## Security & Testing

**Comprehensive Security Testing Completed:**

**Coverage Testing (LibFuzzer):**
- **805+ million test executions** exploring code paths
- **374 total edges covered, 403 features** with 100% stability
- Zero crashes = Memory safety validated
- Comprehensive edge case exploration

**Combined Result:**
- Memory safety validated through extensive fuzzing
- **Zero security vulnerabilities** found
- **Production-ready** with high confidence
- **Formal Verification:** CBMC verification successful (23/23 checks passed)
- **Side-Channel Analysis:** dudect tests passed (no timing leakage detected)

**[View Detailed Test Results](tests/TEST_RESULTS.md)**  
**[View Detailed Fuzzing Results](security/fuzzing/fuzzing-results.md)**

## What You Actually Need to Extract/Create

### 1. **Native C++ Blocks** (Implemented)
```
Blocks implemented:
- kernel_keyring_source    # Load key from kernel keyring (source only)
- kernel_crypto_aes         # AES encryption via kernel crypto API
- nitrokey_interface        # Access Nitrokey via libnitrokey
- brainpool_ec              # Brainpool elliptic curve operations (ECDH, ECDSA)
```

**Note:** `keyring_key_sink` and `tpm_interface` are mentioned in design but not yet implemented.

### 2. **Integration Helpers** (Implemented)
```
Python helpers:
- keyring_helper.py        # keyctl wrapper for kernel keyring operations
- crypto_helpers.py        # Integration utilities and helper functions
- linux_crypto.py          # High-level encrypt/decrypt functions
- linux_crypto_integration.py  # Integration with gr-openssl and gr-nacl
```

### 3. **GNU Radio Companion Blocks** (Implemented)
```
GRC blocks:
- linux_crypto_kernel_keyring_source.block.yml
- linux_crypto_kernel_crypto_aes.block.yml
- linux_crypto_nitrokey_interface.block.yml
```

**Additional GRC files (legacy/non-standard names):**
- kernel_keyring_source.block.yml
- kernel_aes_encrypt.block.yml

## Why This Approach?

1. **No Duplication**: Leverages existing gr-openssl and gr-nacl
2. **Unique Value**: Provides Linux-specific features not available elsewhere
3. **Integration Focus**: Bridges existing crypto modules with Linux infrastructure
4. **Minimal Scope**: Focuses only on what's missing from existing modules
5. **Maintainable**: Small, focused codebase that's easy to maintain

## Comparison with Existing Modules

| Feature | gr-openssl | gr-nacl | gr-linux-crypto |
|---------|------------|---------|-----------------|
| **Symmetric Encryption** | | | |
| AES (all modes) | Yes | No | Kernel API only (use gr-openssl for full features) |
| DES, 3DES, Blowfish | Yes | No | No (use gr-openssl) |
| ChaCha20-Poly1305 | No | Yes | No (use gr-nacl) |
| **Asymmetric Cryptography** | | | |
| RSA | Yes | No | No (use gr-openssl) |
| X25519 (Curve25519 ECDH) | No | Yes | No (use gr-nacl) |
| Ed25519 (signatures) | No | Yes | No (use gr-nacl) |
| NIST ECC curves | Yes | No | No (use gr-openssl) |
| Brainpool ECC curves | No | No | Yes (unique) |
| **Hashing & Authentication** | | | |
| SHA (SHA-1, SHA-256, SHA-512) | Yes | No | No (use gr-openssl) |
| HMAC | Yes | No | No (use gr-openssl) |
| **Linux-Specific Features** | | | |
| Kernel keyring | No | No | Yes (unique) |
| Hardware security (Nitrokey) | No | No | Yes (unique) |
| Kernel crypto API | No | No | Yes (unique) |
| TPM integration | No | No | Yes (unique) |

This module fills the gaps in the GNU Radio crypto ecosystem by providing Linux-specific infrastructure that existing modules don't cover.

## Cryptographic Algorithm Background

### Cryptographic Ciphers Influenced by the NSA

The National Security Agency (NSA) has been involved in various cryptographic standards and algorithms. Here are some ciphers likely influenced by the NSA:

| Cipher | Description |
|--------|-------------|
| **AES** (Advanced Encryption Standard) | Endorsed by the NSA for federal applications, widely used for secure data encryption. |
| **DSA** (Digital Signature Algorithm) | Developed under NSA auspices, commonly used for digital signatures. |
| **SHA** (Secure Hash Algorithm) | NSA has influenced multiple versions, with SHA-1 and SHA-2 being widely used and critiqued for certain vulnerabilities. |
| **Skipjack** | Created by the NSA for the Clipper chip, aimed at secure voice communications. |
| **KASUMI** | A block cipher influenced by NSA standards, utilized in 3G cellular networks. |

### Cryptographic Ciphers NOT Influenced by the NSA

Several algorithms developed independently of the NSA are widely used:

| Cipher | Description |
|--------|-------------|
| **RSA** (Rivest–Shamir–Adleman) | An academic standard widely used for secure key exchange, not influenced by NSA. |
| **Elliptic Curve Cryptography (ECC)** | Developed independently, focusing on secure and efficient cryptographic solutions. |
| **ChaCha20** | Designed by Daniel Bernstein for speed and security, with no NSA involvement. |
| **Twofish** | An AES finalist created by Bruce Schneier, independently developed. |
| **Serpent** | Another AES finalist, also created without direct NSA influence. |
| **Brainpool** | A suite of elliptic curves (e.g., Brainpool P-256) developed without NSA influence, though it is implemented in many cryptographic systems. |

**Summary:** While several ciphers have ties to the NSA, such as AES and SHA, there are many robust alternatives like RSA, ChaCha20, and Brainpool, developed independently. Understanding these distinctions helps in choosing secure cryptographic solutions.

### Known Scandals Involving NSA and Cryptography

Several scandals and controversies have surrounded the NSA's involvement in cryptography, revealing concerns about security, privacy, and possible manipulation of standards. Here are some key incidents:

| Incident | Description |
|----------|-------------|
| **NSA's Involvement in Dual_EC_DRBG** | This random number generator was adopted by NIST but later revealed to be potentially compromised by the NSA, raising suspicions of backdoors. |
| **PRISM** | Exposed by Edward Snowden in 2013, revealing that the NSA collects data from major tech companies, including communications encrypted using NSA-influenced standards. |
| **Clapper's Misleading Testimony** | Then-Director James Clapper's testimony before Congress in 2013 was scrutinized after revelations about extensive surveillance practices came to light. |
| **Clipper Chip** | Launched in the early 1990s, it aimed to provide secure phone communication but faced backlash due to mandatory key escrow, which many viewed as a significant privacy infringement. |
| **SHA-1 Deprecation** | The SHA-1 hashing algorithm, once endorsed by the NSA, was later found vulnerable, leading to its deprecation and questions about the NSA's early assessments of its security. |

**Summary:** These incidents highlight significant concerns regarding the NSA's influence in cryptography and the potential implications for security and privacy. The revelations have fostered a mistrust of cryptographic standards and increased the demand for independent auditing and verification of cryptographic algorithms.
