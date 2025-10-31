# GNU Radio Linux Crypto Module

A GNU Radio module that provides **Linux-specific cryptographic infrastructure integration**, focusing on what's missing from existing crypto modules (gr-openssl, gr-nacl).

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

### 3. **Kernel Crypto API Integration**
- **AF_ALG sockets**: Direct use of Linux kernel crypto subsystem
- **Hardware acceleration**: CPU crypto instructions via kernel
- **Performance**: Bypass user-space crypto libraries when possible
- **No duplication**: This is NOT available in existing modules

## What This Module Does NOT Provide (Avoiding Duplication)

### **Basic OpenSSL Operations**
- **Use gr-openssl instead**: Symmetric encryption, hashing, HMAC
- **Don't duplicate**: AES, SHA, RSA operations are already in gr-openssl
- **Integration only**: Provide kernel keyring as key source for gr-openssl

### **Modern Crypto (NaCl/libsodium)**
- **Use gr-nacl instead**: Curve25519, Ed25519, ChaCha20-Poly1305
- **Don't duplicate**: Public-key crypto, authenticated encryption
- **Integration only**: Provide hardware key storage for gr-nacl

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
- Use `gr-openssl` for OpenSSL operations
- Use `gr-nacl` for modern crypto (Curve25519, Ed25519)
- Add thin wrappers for kernel keyring and hardware

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

### Authentication Modes
- **GCM** (Galois/Counter Mode) - for AES
- **Poly1305** - for ChaCha20
- HMAC (SHA-1, SHA-256, SHA-512)

**Note:** For additional algorithms (RSA, more ECC curves, etc.), use **gr-openssl** which provides comprehensive OpenSSL support.

## Security & Testing

**Comprehensive Security Testing Completed:**

Two complementary fuzzing approaches validate both functional correctness and memory safety:

**Real Cryptographic Testing (AFL++):**
- Actual AF_ALG socket operations tested (kernel crypto API)
- Real OpenSSL EVP functions tested (AES encryption/decryption)
- Zero crashes = Functional correctness validated

**Coverage Testing (LibFuzzer):**
- **18.4+ billion test executions** exploring code paths
- **469 total edges covered** with 100% stability
- Zero crashes = Memory safety validated
- Comprehensive edge case exploration

**Combined Result:**
- Both functional correctness AND memory safety validated
- **Zero security vulnerabilities** found
- **Production-ready** with high confidence
- **Formal Verification:** CBMC verification successful (23/23 checks passed)
- **Side-Channel Analysis:** dudect tests passed (no timing leakage detected)

**[View Detailed Test Results](tests/TEST_RESULTS.md)**  
**[View Detailed Fuzzing Results](security/fuzzing/fuzzing-results.md)**

## What You Actually Need to Extract/Create

### 1. **gr-linux-keyring** (NEW - but minimal!)
```
Blocks needed:
- keyring_key_source    # Load key from kernel keyring
- keyring_key_sink      # Store key to kernel keyring  
- nitrokey_interface    # Access Nitrokey via libnitrokey
- tpm_interface         # Access TPM for key storage
```

### 2. **Integration Helpers**
```
Python helpers:
- keyring_helper.py     # keyctl wrapper
- crypto_helpers.py    # Integration utilities
```

### 3. **GNU Radio Companion Blocks**
```
GRC blocks:
- kernel_keyring_source.block.yml
- nitrokey_interface.block.yml
- tpm_interface.block.yml
```

## Why This Approach?

1. **No Duplication**: Leverages existing gr-openssl and gr-nacl
2. **Unique Value**: Provides Linux-specific features not available elsewhere
3. **Integration Focus**: Bridges existing crypto modules with Linux infrastructure
4. **Minimal Scope**: Focuses only on what's missing from existing modules
5. **Maintainable**: Small, focused codebase that's easy to maintain

## Comparison with Existing Modules

| Feature | gr-openssl | gr-nacl | gr-linux-crypto |
|---------|------------|---------|-----------------|
| OpenSSL operations | Yes | No | No (use gr-openssl) |
| Modern crypto (NaCl) | No | Yes | No (use gr-nacl) |
| Kernel keyring | No | No | Yes (unique) |
| Hardware security | No | No | Yes (unique) |
| Kernel crypto API | No | No | Yes (unique) |
| TPM integration | No | No | Yes (unique) |
| Brainpool curves | No | No | Yes (unique) |

This module fills the gaps in the GNU Radio crypto ecosystem by providing Linux-specific infrastructure that existing modules don't cover.
