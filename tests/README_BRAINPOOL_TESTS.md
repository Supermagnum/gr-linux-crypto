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

# Run BSI TR-03111 compliance tests
pytest tests/test_bsi_tr03111.py -v

# Run ECTester compatibility tests
pytest tests/test_ectester.py -v

# Run RFC compliance tests
pytest tests/test_rfc_compliance.py -v

# Run ECGDSA framework tests
pytest tests/test_ecgdsa.py -v
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

### 5. BSI TR-03111 Compliance Tests
- **Comprehensive BSI TR-03111 validation** (`test_bsi_tr03111.py`)
- Curve parameter validation against BSI specifications
- Key generation requirements compliance
- ECDH operation compliance
- ECDSA signature compliance
- Security level requirements
- Cofactor validation
- Key serialization compliance
- German Federal Office specifications
- European implementation compatibility

### 6. ECTester Compatibility Tests
- **ECTester-compatible test suite** (`test_ectester.py`)
- Point validation on curves
- Scalar multiplication correctness
- Point addition operations
- Invalid input handling
- Edge case testing
- Curve parameter consistency
- ECDH consistency across operations
- Signature consistency validation
- Optional ECTester tool integration

### 7. RFC Compliance Tests
- **RFC 7027 compliance** (`test_rfc_compliance.py`) - Additional Elliptic Curves for OpenPGP
- **RFC 6954 compliance** - Using Brainpool curves in IKEv2
- **RFC 8734 compliance** - Using Brainpool Curves in TLS 1.3
- Protocol-specific ECDH operations
- Key generation and serialization validation
- Test vector framework (vectors extracted from RFC appendices)

### 8. ECGDSA Framework Tests
- **ECGDSA test framework** (`test_ecgdsa.py`)
- ECGDSA function availability checks
- Implementation requirements documentation
- ECGDSA vs ECDSA comparison framework
- BSI TR-03111 ECGDSA compliance notes
- Hash algorithm support validation
- Note: ECGDSA requires specialized implementation (not yet fully implemented)

### 9. Interoperability Tests
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
├── test_bsi_tr03111.py                # BSI TR-03111 compliance tests
├── test_ectester.py                   # ECTester compatibility tests
├── test_rfc_compliance.py             # RFC 7027/6954/8734 compliance tests
├── test_rfc_vectors.py                # RFC test vector parsers
├── test_ecgdsa.py                     # ECGDSA framework tests
├── download_brainpool_vectors.sh      # Test vector download script
├── download_rfc_vectors.sh            # RFC test vector download script
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

## Test Vector Sources Summary

| Source | Format | Test Cases | Best For |
|--------|--------|------------|----------|
| Wycheproof | JSON | 100s/curve | Primary validation |
| Linux kernel | C structs | Dozens | Low-level validation |
| OpenSSL | Various | Limited | Interoperability |
| mbedTLS | .data files | Dozens | Format compatibility |
| RFC 5639 | Spec text | Reference | Specification compliance |
| RFC 7027 | Spec text | OpenPGP | OpenPGP Brainpool curves (test_rfc_compliance.py) |
| RFC 6954 | Spec text | IKEv2 | IKEv2 Brainpool curves (test_rfc_compliance.py) |
| RFC 8734 | Spec text | TLS 1.3 | TLS 1.3 Brainpool curves (test_rfc_compliance.py) |
| BSI TR-03111 | PDF/Spec | Guidelines | Compliance verification (test_bsi_tr03111.py) |
| ECTester | Tool/Test | Various | Implementation validation (test_ectester.py) |

## BSI TR-03111 Compliance Testing

The `test_bsi_tr03111.py` test suite validates compliance with BSI TR-03111 (Technical Guideline for Elliptic Curve Cryptography) requirements:

- **Curve Parameter Validation**: Verifies curve parameters match BSI specifications
- **Key Generation Compliance**: Ensures keys meet BSI requirements
- **ECDH Compliance**: Validates ECDH operations meet security requirements
- **ECDSA Signature Compliance**: Verifies signature format and hash algorithm requirements
- **Security Level Requirements**: Confirms curves provide required security levels
- **Cofactor Validation**: Ensures cofactor is 1 (required by BSI TR-03111)

Run BSI compliance tests:
```bash
pytest tests/test_bsi_tr03111.py -v
```

## ECTester Compatibility Testing

The `test_ectester.py` test suite implements ECTester-compatible tests for elliptic curve implementations:

- **Point Validation**: Verifies points are valid on curves
- **Scalar Multiplication**: Tests scalar multiplication correctness
- **Point Addition**: Validates point addition operations
- **Invalid Input Handling**: Ensures proper rejection of invalid inputs
- **Edge Cases**: Tests various edge cases and boundary conditions
- **Consistency Tests**: Validates consistency across multiple operations

Run ECTester compatibility tests:
```bash
pytest tests/test_ectester.py -v
```

Note: ECTester tool integration is optional. The test suite implements ECTester-compatible tests directly, but can also integrate with the ECTester tool if installed.

## RFC Compliance Testing

The `test_rfc_compliance.py` test suite validates compliance with RFCs that specify Brainpool curve usage:

- **RFC 7027**: Additional Elliptic Curves for OpenPGP
  - Tests OpenPGP-specific key generation and serialization
  - Validates curve support for OpenPGP applications
  
- **RFC 6954**: Using ECC Brainpool curves in IKEv2
  - Tests IKEv2 ECDH key exchange operations
  - Validates initiator/responder key exchange scenarios
  
- **RFC 8734**: Using Brainpool Curves in TLS 1.3
  - Tests TLS 1.3 ECDH key exchange operations
  - Validates client/server key exchange scenarios

Run RFC compliance tests:
```bash
pytest tests/test_rfc_compliance.py -v
```

Note: RFC test vectors are programmatically generated for compliance testing. If you have actual RFC test vectors extracted from RFC appendices, place them in JSON format in `test_vectors/` and they will be used automatically. The tests generate vectors programmatically to validate RFC compliance even without extracted vectors.

## ECGDSA Framework Testing

The `test_ecgdsa.py` test suite provides a framework for ECGDSA (Elliptic Curve German Digital Signature Algorithm) testing:

- **Function Availability**: Verifies ECGDSA functions are defined
- **Implementation Status**: Documents that ECGDSA requires specialized implementation
- **Requirements Documentation**: Details ECGDSA implementation requirements
- **Comparison Framework**: Framework for comparing ECGDSA vs ECDSA
- **BSI Compliance Notes**: Documents ECGDSA's role in BSI TR-03111 compliance

Run ECGDSA framework tests:
```bash
pytest tests/test_ecgdsa.py -v
```

Note: ECGDSA is not yet fully implemented. The Python cryptography library doesn't support ECGDSA natively. The test framework is ready for when an implementation is added (e.g., via OpenSSL or a specialized library).

## Next Steps

1. **Download test vectors** using the provided script
2. **Run comprehensive tests** to validate implementation
3. **Run BSI TR-03111 compliance tests** for European deployments
4. **Run ECTester compatibility tests** for implementation validation
5. **Review performance** benchmarks
6. **Verify interoperability** with your target systems

For detailed information on test vector sources, see:
- `test_vectors/README_BRAINPOOL.md` - Brainpool-specific guide
- `test_vectors/README_SOURCES.md` - Complete source documentation

