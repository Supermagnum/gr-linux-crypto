# Test Vectors

This directory contains cryptographic test vectors for gr-linux-crypto validation.

## Sources

### Wycheproof Project
- **Repository:** https://github.com/google/wycheproof
- **Description:** Comprehensive test vectors from Google's Wycheproof project
- **Format:** JSON
- **Coverage:** Brainpool curves, AES-GCM, ChaCha20-Poly1305, and more

### NIST CAVP
- **Source:** NIST Cryptographic Algorithm Validation Program
- **Format:** Text files
- **Coverage:** AES-GCM, ECDSA, ECDH

### RFC 8439
- **Source:** RFC 8439 (ChaCha20 and Poly1305)
- **Format:** Text files
- **Coverage:** ChaCha20-Poly1305 test vectors

## Setup

Run the setup script to download vectors:

```bash
./setup_test_vectors.sh
```

Or manually:

```bash
git clone https://github.com/google/wycheproof.git /tmp/wycheproof
cp /tmp/wycheproof/testvectors/*brainpool*.json tests/test_vectors/
```

## Usage

Test vectors are automatically used by:

- `test_brainpool_vectors.py` - Brainpool ECC test vectors
- `test_nist_vectors.py` - NIST CAVP vectors
- `test_brainpool_all_sources.py` - Multi-source Brainpool validation

## File Naming

- `*brainpool*.json` - Brainpool ECC test vectors (Wycheproof)
- `*aes*.json` - AES test vectors (Wycheproof)
- `*chacha*.json` - ChaCha20-Poly1305 vectors (Wycheproof)

