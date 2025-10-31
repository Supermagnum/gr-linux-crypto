# Brainpool Test Vectors

This directory should contain test vectors for Brainpool ECC curve validation.

## Recommended Sources

### 1. Wycheproof Project (Google) [HIGHLY RECOMMENDED]

**URL:** https://github.com/google/wycheproof

**Direct link to test vectors:**
https://github.com/google/wycheproof/tree/master/testvectors

#### Required Files:

**ECDH Test Vectors:**
- `ecdh_brainpoolP256r1_test.json`
- `ecdh_brainpoolP384r1_test.json`
- `ecdh_brainpoolP512r1_test.json`

**ECDSA Test Vectors:**
- `ecdsa_brainpoolP256r1_sha256_test.json`
- `ecdsa_brainpoolP384r1_sha384_test.json`
- `ecdsa_brainpoolP512r1_sha512_test.json`

**Why Wycheproof is excellent:**
- JSON format (easy to parse)
- Hundreds of test cases per curve
- Includes edge cases and invalid inputs
- Tests designed to catch implementation bugs
- Covers both ECDH and ECDSA
- Actively maintained by Google security team
- Includes known vulnerability test cases

#### Download Instructions:

```bash
# Navigate to test_vectors directory
cd tests/test_vectors

# Download ECDH vectors
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdh_brainpoolP256r1_test.json
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdh_brainpoolP384r1_test.json
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdh_brainpoolP512r1_test.json

# Download ECDSA vectors
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_brainpoolP256r1_sha256_test.json
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_brainpoolP384r1_sha384_test.json
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_brainpoolP512r1_sha512_test.json
```

### 2. RFC 5639 (Official Brainpool Specification)

**URL:** https://datatracker.ietf.org/doc/html/rfc5639

**What's included:**
- Appendix A: Curve parameters (all Brainpool curves)
- Example computations
- Base point coordinates
- Curve equations

**Test data available:**
- Domain parameters for each curve
- Generator points (G)
- Order (n)
- Cofactor (h)

**Note:** RFC 5639 defines curves but has limited worked examples. More comprehensive test vectors are available from Wycheproof.

### 3. NIST CAVP (Limited Coverage)

**URL:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

**Note:** NIST focuses on their own curves. Brainpool coverage is limited in NIST CAVP.

## Test Vector Format

### Wycheproof JSON Format (ECDH)

```json
{
  "algorithm": "ECDH",
  "generatorVersion": "...",
  "numberOfTests": 123,
  "testGroups": [{
    "curve": "brainpoolP256r1",
    "type": "ECDH",
    "tests": [{
      "tcId": 1,
      "comment": "...",
      "public": "04...",
      "private": "...",
      "shared": "...",
      "result": "valid",
      "flags": []
    }]
  }]
}
```

### Wycheproof JSON Format (ECDSA)

```json
{
  "algorithm": "ECDSA",
  "testGroups": [{
    "curve": "brainpoolP256r1",
    "sha": "SHA-256",
    "type": "EcdsaVerify",
    "tests": [{
      "tcId": 1,
      "comment": "...",
      "msg": "...",
      "key": {
        "curve": "brainpoolP256r1",
        "keySize": 256,
        "type": "EcPublicKey",
        "uncompressed": "04..."
      },
      "sig": "...",
      "result": "valid"
    }]
  }]
}
```

## Running Brainpool Tests

Once test vectors are placed in this directory, run:

```bash
# Run all Brainpool tests
pytest tests/test_brainpool_comprehensive.py -v -s

# Run specific test classes
pytest tests/test_brainpool_comprehensive.py::TestBrainpoolECDHWycheproof -v
pytest tests/test_brainpool_comprehensive.py::TestBrainpoolECDSAWycheproof -v
pytest tests/test_brainpool_comprehensive.py::TestBrainpoolPerformance -v
```

## Notes

- Tests will automatically download Wycheproof vectors if not present
- Tests skip gracefully if test vector files are not found
- The parser handles various JSON format variations
- Performance tests benchmark against expected thresholds
- Interoperability tests verify BSI compliance

