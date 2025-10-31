# gr-linux-crypto Test Suite

Comprehensive test suite for gr-linux-crypto encryption/decryption functionality.

## Test Coverage

### 1. Round-Trip Tests
- Encrypt/decrypt round-trip for various data sizes (0, 1, 16, 64, 1024, 4096 bytes)
- Support for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- Non-authenticated modes (AES-CBC)

### 2. Determinism Tests
- Same plaintext + key + IV produces same ciphertext
- Verified for authenticated encryption modes

### 3. Key Uniqueness Tests
- Different keys produce different ciphertexts
- Same key with different data produces different ciphertexts

### 4. Error Handling Tests
- Invalid key sizes (AES-128, AES-256, ChaCha20)
- Missing authentication tags (GCM, Poly1305)
- Corrupted authentication tags
- Corrupted ciphertext
- Invalid algorithms

### 5. Performance Tests
- Encryption performance (<100μs per 16-byte block)
- Decryption performance (<100μs per 16-byte block)

### 6. OpenSSL Cross-Validation
- Encrypt with gr-linux-crypto, validate format
- Random test cases (100 iterations per algorithm)

## Running Tests

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test Classes
```bash
# Round-trip tests only
pytest tests/test_linux_crypto.py::TestEncryptDecryptRoundTrip -v

# Error handling tests
pytest tests/test_linux_crypto.py::TestErrorHandling -v

# Performance tests
pytest tests/test_linux_crypto.py::TestPerformance -v
```

### Run with Coverage
```bash
pip install pytest-cov
pytest tests/ --cov=python --cov-report=html
```

### Run Performance Tests Only
```bash
pytest tests/test_linux_crypto.py::TestPerformance -v
```

### Run OpenSSL Cross-Validation Tests
```bash
pytest tests/test_linux_crypto.py::TestOpenSSLCrossValidation -v -m openssl
```

## Test Structure

- `conftest.py`: Shared pytest fixtures and configuration
- `test_linux_crypto.py`: Main test suite with all test classes
- `pytest.ini`: Pytest configuration

## Fixtures

Common test fixtures available:
- `random_key_128`: 128-bit random key
- `random_key_256`: 256-bit random key
- `random_key_chacha20`: ChaCha20 key
- `fixed_iv_16`: Fixed 16-byte IV
- `fixed_iv_12`: Fixed 12-byte IV/nonce
- `test_data_small`: Small test data
- `test_data_empty`: Empty test data
- `test_data_large`: Large test data (4KB)
- `variable_size_data`: Parametrized fixture for various sizes

## Expected Test Results

All tests should pass. Performance tests verify that encryption/decryption
operations complete within 100 microseconds per 16-byte block.

## Troubleshooting

### Import Errors
If you see import errors, ensure the `python/` directory is in your Python path:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
pytest tests/
```

### OpenSSL CLI Tests Skipping
OpenSSL CLI cross-validation tests may skip if:
- OpenSSL is not installed
- OpenSSL version doesn't support the algorithm
- Format compatibility issues

This is expected and tests will gracefully skip with a message.

### Performance Test Failures
If performance tests fail:
1. Ensure you're running on a reasonably fast machine
2. Check for background processes affecting performance
3. Run multiple times to account for system variance
4. Consider adjusting `PERFORMANCE_THRESHOLD_US` in test file

