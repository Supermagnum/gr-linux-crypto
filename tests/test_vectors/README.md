# Test Vectors Directory

This directory should contain official test vectors for validation.

## Required Test Vector Files

### NIST CAVP Test Vectors

1. **aes_gcm_128.txt** - NIST CAVP AES-128-GCM test vectors
2. **aes_gcm_256.txt** - NIST CAVP AES-256-GCM test vectors

### RFC 8439 Test Vectors

3. **rfc8439_chacha20_poly1305.txt** - RFC 8439 ChaCha20-Poly1305 test vectors

## Obtaining Test Vectors

### NIST CAVP Test Vectors

1. Visit the NIST CAVP website:
   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-testing

2. Navigate to "AES" → "AES-GCM" test vectors

3. Download the test vector files for:
   - AES-128-GCM
   - AES-256-GCM

4. Save as:
   - `aes_gcm_128.txt`
   - `aes_gcm_256.txt`

### RFC 8439 Test Vectors

RFC 8439 (ChaCha20-Poly1305) test vectors are included in the RFC document itself.

You can extract them from:
- RFC 8439 Appendix A.5: https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.5

Or use a pre-formatted file available from various sources.

## Test Vector Format

### NIST CAVP Format (AES-GCM)

```
Count = 0
Key = <hex_string>
IV = <hex_string>
PT = <hex_string>
AAD = <hex_string>
CT = <hex_string>
Tag = <hex_string>
```

### RFC 8439 Format (ChaCha20-Poly1305)

```
Test Vector #1:
Key: <hex_string>
Nonce: <hex_string>
PT: <hex_string>
AAD: <hex_string>
CT: <hex_string>
Tag: <hex_string>
```

## Running Tests

Once test vectors are placed in this directory, run:

```bash
pytest tests/test_nist_vectors.py -v -s
```

The tests will automatically detect and use the test vector files.

## Notes

- Tests will skip gracefully if test vector files are not found
- The parser handles various whitespace and formatting variations
- Empty fields (like empty plaintext) are handled correctly

