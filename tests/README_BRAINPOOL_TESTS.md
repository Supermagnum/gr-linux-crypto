# Brainpool ECC Comprehensive Test Suite

Complete test suite for Brainpool elliptic curve cryptography in gr-linux-crypto.

## Quick Start

### 1. Download Test Vectors

```bash
cd tests
./download_brainpool_vectors.sh
```

This downloads test vectors from:
- Wycheproof (Google) - Primary source
- Linux kernel testmgr.h
- OpenSSL test suite
- mbedTLS test suite

### 2. Run Tests

```bash
# Run all Brainpool tests
pytest tests/test_brainpool_comprehensive.py -v

# Run comprehensive tests with all sources
pytest tests/test_brainpool_all_sources.py -v -s

# Run specific test categories
pytest tests/test_brainpool_comprehensive.py::TestBrainpoolPerformance -v
pytest tests/test_brainpool_comprehensive.py::TestBrainpoolInteroperability -v
```

## Test Coverage

### 1. Wycheproof Test Vectors
- **ECDH Key Exchange:** All three Brainpool curves
- **ECDSA Signatures:** With SHA-256, SHA-384, SHA-512
- **Hundreds of test cases** including edge cases
- **Invalid input handling** validation

### 2. Linux Kernel Validation
- testmgr.h test vectors
- Low-level crypto validation
- ECDH test cases

### 3. Cross-Implementation Validation
- **OpenSSL** compatibility
- **GnuPG** interoperability  
- **libgcrypt** compatibility
- **mbedTLS** format support

### 4. Performance Benchmarks
- Key generation performance
- ECDH operation speed
- Comparison with NIST curves
- Threshold validation (<100ms for P256)

### 5. BSI Compliance
- German Federal Office specifications
- TR-03111 compliance verification
- European implementation compatibility

### 6. Interoperability Tests
- Key serialization/deserialization
- PEM format compatibility
- Cross-platform validation

## Test Structure

```
tests/
├── test_brainpool_vectors.py          # Wycheproof & RFC 5639 parsers
├── test_brainpool_vectors_extended.py # OpenSSL, Linux, mbedTLS parsers
├── test_brainpool_comprehensive.py    # Main comprehensive test suite
├── test_brainpool_all_sources.py      # Multi-source integration tests
├── download_brainpool_vectors.sh      # Test vector download script
└── test_vectors/
    ├── *.json                         # Wycheproof vectors
    ├── testmgr.h                      # Linux kernel vectors
    └── *.data                         # mbedTLS vectors
```

## Expected Results

### Success Rates
- **Wycheproof ECDH:** >80% (format conversion may cause some skips)
- **Wycheproof ECDSA:** >70% (format conversion may cause some skips)
- **Linux Kernel:** >90% (if vectors available)
- **Cross-Implementation:** >95% (if tools available)

### Performance Thresholds
- **P256 Key Generation:** <100ms average
- **P384 Key Generation:** <300ms average
- **P512 Key Generation:** <500ms average
- **ECDH Operations:** <100ms for P256

## Troubleshooting

### Missing Test Vectors

If tests skip with "no test vectors found":

```bash
# Manually download Wycheproof vectors
cd tests/test_vectors
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdh_brainpoolP256r1_test.json
curl -O https://raw.githubusercontent.com/google/wycheproof/master/testvectors/ecdsa_brainpoolP256r1_sha256_test.json
# ... repeat for other curves
```

### OpenSSL Compatibility Issues

Some OpenSSL versions may not fully support Brainpool:

```bash
# Check OpenSSL version
openssl version

# OpenSSL 1.0.2+ required, 3.x recommended
# If not available, interoperability tests will skip
```

### Performance Test Failures

If performance tests fail:
1. Check for background processes
2. Run on a dedicated test machine
3. Increase thresholds if running on slow hardware
4. Check system load

## Integration with CI/CD

Add to your CI pipeline:

```yaml
# Example GitHub Actions
- name: Download test vectors
  run: |
    cd tests
    ./download_brainpool_vectors.sh

- name: Run Brainpool tests
  run: |
    pytest tests/test_brainpool_comprehensive.py -v --tb=short
```

## Test Vector Sources Summary

| Source | Format | Test Cases | Best For |
|--------|--------|------------|----------|
| Wycheproof | JSON | 100s/curve | Primary validation |
| Linux kernel | C structs | Dozens | Low-level validation |
| OpenSSL | Various | Limited | Interoperability |
| mbedTLS | .data files | Dozens | Format compatibility |
| RFC 5639 | Spec text | Reference | Specification compliance |
| BSI TR-03111 | PDF/Spec | Guidelines | Compliance verification |

## Next Steps

1. **Download test vectors** using the provided script
2. **Run comprehensive tests** to validate implementation
3. **Review performance** benchmarks
4. **Verify interoperability** with your target systems
5. **Check BSI compliance** for European deployments

For detailed information on test vector sources, see:
- `test_vectors/README_BRAINPOOL.md` - Brainpool-specific guide
- `test_vectors/README_SOURCES.md` - Complete source documentation

