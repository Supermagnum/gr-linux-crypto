# Brainpool Test Vector Sources - Complete Guide

## Quick Download

Run the download script to get all test vectors:

```bash
cd tests
./download_brainpool_vectors.sh
```

## Detailed Sources

### 1. Wycheproof Project (Google) [PRIMARY SOURCE]

**GitHub:** https://github.com/google/wycheproof  
**Test Vectors:** https://github.com/google/wycheproof/tree/master/testvectors

**Why Recommended:**
- Comprehensive JSON format
- Hundreds of test cases per curve
- Includes edge cases and known vulnerabilities
- Actively maintained by Google security team

**Download:**
```bash
cd tests/test_vectors
git clone --depth 1 https://github.com/google/wycheproof.git
cp wycheproof/testvectors/*brainpool*.json .
```

**Files:**
- `ecdh_brainpoolP256r1_test.json`
- `ecdh_brainpoolP384r1_test.json`
- `ecdh_brainpoolP512r1_test.json`
- `ecdsa_brainpoolP256r1_sha256_test.json`
- `ecdsa_brainpoolP384r1_sha384_test.json`
- `ecdsa_brainpoolP512r1_sha512_test.json`

### 2. Linux Kernel testmgr.h

**URL:** https://github.com/torvalds/linux/blob/master/crypto/testmgr.h

**What's included:**
- Kernel crypto test vectors
- ECDH test cases for Brainpool
- Used for kernel crypto subsystem validation

**Download:**
```bash
cd tests/test_vectors
wget https://raw.githubusercontent.com/torvalds/linux/master/crypto/testmgr.h
grep -A 20 brainpool testmgr.h > testmgr_brainpool.txt
```

**Usage:**
The test suite automatically extracts Brainpool vectors from testmgr.h

### 3. OpenSSL Test Suite

**GitHub:** https://github.com/openssl/openssl/tree/master/test

**Relevant Files:**
- `test/recipes/30-test_evp_data/` - EVP test data
- `test/ecdhtest.c` - ECDH test code
- `test/ecdsatest.c` - ECDSA test code
- `test/ectest.c` - General ECC tests

**Download:**
```bash
cd tests/test_vectors
git clone --depth 1 https://github.com/openssl/openssl.git
grep -r brainpool openssl/test/ > openssl_brainpool.txt
```

**Note:** OpenSSL 1.0.2+ has Brainpool support, 3.x has improved support.

### 4. libgcrypt Test Suite

**GitHub:** https://github.com/gpg/libgcrypt/tree/master/tests

**Relevant Files:**
- `tests/t-mpi-point.c` - Point operations tests
- `tests/pubkey.c` - Public key crypto tests including ECC
- `tests/curves.c` - Curve-specific tests

**Download:**
```bash
cd tests/test_vectors
git clone --depth 1 https://github.com/gpg/libgcrypt.git
grep -r brainpool libgcrypt/tests/ > libgcrypt_brainpool.txt
```

**Note:** libgcrypt has native Brainpool support since version 1.6.0.

### 5. mbedTLS Test Vectors

**GitHub:** https://github.com/Mbed-TLS/mbedtls

**Location:** `tests/suites/*.data`

**Download:**
```bash
cd tests/test_vectors
git clone --depth 1 https://github.com/Mbed-TLS/mbedtls.git
find mbedtls/tests/suites -name "*.data" -exec grep -l brainpool {} \;
```

**Format:** Test data files with curve parameters and test cases.

### 6. RFC 5639 (Official Specification)

**URL:** https://datatracker.ietf.org/doc/html/rfc5639

**What's included:**
- Official Brainpool curve definitions
- Domain parameters
- Generator points
- Mathematical specifications

**Note:** More for reference than test vectors. Use Wycheproof for actual test cases.

### 7. BSI (German Federal Office)

**URL:** https://www.bsi.bund.de/

**Technical Guidelines:**  
https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.html

**What's available:**
- Technical guidelines for Brainpool usage
- Example computations
- Formal specifications for German government use

**Note:** More specification than test vectors. Use for compliance verification.

### 8. SafeCurves Project

**URL:** https://safecurves.cr.yp.to/

**What's included:**
- Security analysis of Brainpool curves
- Implementation comparisons
- Security property validation

**Note:** Focus on security analysis rather than test vectors.

## Test Vector Format Reference

### Wycheproof JSON (ECDH)
```json
{
  "algorithm": "ECDH",
  "testGroups": [{
    "curve": "brainpoolP256r1",
    "tests": [{
      "tcId": 1,
      "private": "hex",
      "public": "hex",
      "shared": "hex",
      "result": "valid"
    }]
  }]
}
```

### Linux Kernel testmgr.h
```c
static const struct {
    .secret = { 0x... },
    .expected_shared = { 0x... },
} brainpoolP256r1_test = { ... };
```

### mbedTLS .data format
```
curve: brainpoolP256r1
dA: <hex>
xA: <hex>
yA: <hex>
Z: <hex>
```

## Running Tests with All Sources

```bash
# Run comprehensive tests
pytest tests/test_brainpool_all_sources.py -v -s

# Run with specific source
pytest tests/test_brainpool_all_sources.py::TestBrainpoolAllSources::test_wycheproof_comprehensive -v

# Run cross-implementation tests
pytest tests/test_brainpool_all_sources.py::TestBrainpoolCrossImplementation -v
```

## Notes

- Wycheproof is the most comprehensive and recommended source
- Linux kernel vectors are useful for low-level validation
- OpenSSL/mbedTLS/libgcrypt vectors help with interoperability
- BSI guidelines ensure compliance with German government standards

