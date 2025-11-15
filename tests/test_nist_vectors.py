#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIST CAVP and RFC 8439 test vector validation for gr-linux-crypto.

Tests implementation against official test vectors:
- NIST CAVP AES-GCM test vectors
- RFC 8439 ChaCha20-Poly1305 test vectors
"""

from pathlib import Path

import pytest

try:
    from test_vectors import (
        NISTCAVPParser,
        RFC8439Parser,
    )
except ImportError:
    from .test_vectors import (
        NISTCAVPParser,
        RFC8439Parser,
    )

# Import encryption functions
try:
    from python.linux_crypto import decrypt, encrypt
except ImportError:
    try:
        from linux_crypto import decrypt, encrypt
    except ImportError:
        from gr_linux_crypto.linux_crypto import decrypt, encrypt


# Test vector directory
TEST_VECTORS_DIR = Path(__file__).parent / "test_vectors"
NIST_AES_GCM_128_FILE = TEST_VECTORS_DIR / "aes_gcm_128.txt"
NIST_AES_GCM_256_FILE = TEST_VECTORS_DIR / "aes_gcm_256.txt"
RFC8439_CHACHA20_FILE = TEST_VECTORS_DIR / "rfc8439_chacha20_poly1305.txt"


class TestVectorResults:
    """Track test vector results."""

    def __init__(self):
        self.total = 0
        self.passed = 0
        self.failed = 0
        self.failures = []

    def add_result(self, passed: bool, vector_info: str, error: str = ""):
        """Add a test result."""
        self.total += 1
        if passed:
            self.passed += 1
        else:
            self.failed += 1
            self.failures.append({"vector": vector_info, "error": error})

    def get_summary(self) -> str:
        """Get summary of test results."""
        return (
            f"Test Vector Results:\n"
            f"  Total: {self.total}\n"
            f"  Passed: {self.passed}\n"
            f"  Failed: {self.failed}\n"
            f"  Success Rate: {(self.passed/self.total*100):.2f}%"
            if self.total > 0
            else "N/A"
        )

    def print_failures(self):
        """Print details of failures."""
        if self.failures:
            print("\nFailures:")
            for i, failure in enumerate(self.failures, 1):
                print(f"  {i}. {failure['vector']}")
                print(f"     Error: {failure['error']}")


def test_nist_aes_gcm_128_vectors():
    """Test AES-128-GCM against NIST CAVP test vectors."""
    if not NIST_AES_GCM_128_FILE.exists():
        pytest.skip(
            f"NIST AES-GCM-128 test vectors not found at {NIST_AES_GCM_128_FILE}"
        )

    print(f"\nLoading NIST AES-128-GCM test vectors from {NIST_AES_GCM_128_FILE}...")
    vectors = NISTCAVPParser.parse_aes_gcm_file(str(NIST_AES_GCM_128_FILE))

    if not vectors:
        pytest.skip("No test vectors found in file")

    results = TestVectorResults()

    print(f"Running {len(vectors)} test vectors...")

    for vector in vectors:
        try:
            # Encrypt with our implementation (pass AAD if available)
            ciphertext, iv_out, auth_tag = encrypt(
                "aes-128",
                vector.key,
                vector.plaintext,
                iv_mode=vector.iv,
                auth="gcm",
                aad=vector.aad,
            )

            # Verify IV matches (should be the same as input)
            if iv_out != vector.iv:
                results.add_result(
                    False,
                    f"Vector {vector.count}",
                    f"IV mismatch: expected {vector.iv.hex()}, got {iv_out.hex()}",
                )
                continue

            # Verify ciphertext matches
            if ciphertext != vector.ciphertext:
                results.add_result(
                    False,
                    f"Vector {vector.count}",
                    f"Ciphertext mismatch: expected {vector.ciphertext.hex()[:32]}..., got {ciphertext.hex()[:32]}...",
                )
                continue

            # Verify auth tag matches
            if auth_tag != vector.tag:
                results.add_result(
                    False,
                    f"Vector {vector.count}",
                    f"Auth tag mismatch: expected {vector.tag.hex()}, got {auth_tag.hex()}",
                )
                continue

            # Verify decryption works (pass AAD if available)
            try:
                decrypted = decrypt(
                    "aes-128",
                    vector.key,
                    ciphertext,
                    vector.iv,
                    auth="gcm",
                    auth_tag=auth_tag,
                    aad=vector.aad,
                )

                if decrypted != vector.plaintext:
                    results.add_result(
                        False,
                        f"Vector {vector.count}",
                        "Decryption failed: plaintext mismatch",
                    )
                    continue

            except ValueError as e:
                results.add_result(
                    False, f"Vector {vector.count}", f"Decryption error: {e}"
                )
                continue

            # All checks passed
            results.add_result(True, f"Vector {vector.count}")

        except Exception as e:
            results.add_result(
                False,
                f"Vector {vector.count}",
                f"Exception: {type(e).__name__}: {str(e)}",
            )

    # Print results
    print("\n" + results.get_summary())
    results.print_failures()

    # Assert all passed
    assert (
        results.failed == 0
    ), f"{results.failed} test vectors failed. See details above."
    assert results.total == len(vectors), "Test vector count mismatch"


def test_nist_aes_gcm_256_vectors():
    """Test AES-256-GCM against NIST CAVP test vectors."""
    if not NIST_AES_GCM_256_FILE.exists():
        pytest.skip(
            f"NIST AES-GCM-256 test vectors not found at {NIST_AES_GCM_256_FILE}"
        )

    print(f"\nLoading NIST AES-256-GCM test vectors from {NIST_AES_GCM_256_FILE}...")
    vectors = NISTCAVPParser.parse_aes_gcm_file(str(NIST_AES_GCM_256_FILE))

    if not vectors:
        pytest.skip("No test vectors found in file")

    results = TestVectorResults()

    print(f"Running {len(vectors)} test vectors...")

    for vector in vectors:
        try:
            # Encrypt with our implementation (pass AAD if available)
            ciphertext, iv_out, auth_tag = encrypt(
                "aes-256",
                vector.key,
                vector.plaintext,
                iv_mode=vector.iv,
                auth="gcm",
                aad=vector.aad,
            )

            # Verify IV matches
            if iv_out != vector.iv:
                results.add_result(False, f"Vector {vector.count}", "IV mismatch")
                continue

            # Verify ciphertext matches
            if ciphertext != vector.ciphertext:
                results.add_result(
                    False, f"Vector {vector.count}", "Ciphertext mismatch"
                )
                continue

            # Verify auth tag matches
            if auth_tag != vector.tag:
                results.add_result(
                    False,
                    f"Vector {vector.count}",
                    f"Auth tag mismatch: expected {vector.tag.hex()}, got {auth_tag.hex()}",
                )
                continue

            # Verify decryption (pass AAD if available)
            try:
                decrypted = decrypt(
                    "aes-256",
                    vector.key,
                    ciphertext,
                    vector.iv,
                    auth="gcm",
                    auth_tag=auth_tag,
                    aad=vector.aad,
                )

                if decrypted != vector.plaintext:
                    results.add_result(
                        False, f"Vector {vector.count}", "Decryption failed"
                    )
                    continue

            except ValueError as e:
                results.add_result(
                    False, f"Vector {vector.count}", f"Decryption error: {e}"
                )
                continue

            results.add_result(True, f"Vector {vector.count}")

        except Exception as e:
            results.add_result(
                False,
                f"Vector {vector.count}",
                f"Exception: {type(e).__name__}: {str(e)}",
            )

    print("\n" + results.get_summary())
    results.print_failures()

    assert results.failed == 0, f"{results.failed} test vectors failed"
    assert results.total == len(vectors), "Test vector count mismatch"


def test_rfc8439_chacha20_poly1305_vectors():
    """Test ChaCha20-Poly1305 against RFC 8439 test vectors."""
    if not RFC8439_CHACHA20_FILE.exists():
        pytest.skip(
            f"RFC 8439 ChaCha20-Poly1305 test vectors not found at {RFC8439_CHACHA20_FILE}"
        )

    print(
        f"\nLoading RFC 8439 ChaCha20-Poly1305 test vectors from {RFC8439_CHACHA20_FILE}..."
    )
    vectors = RFC8439Parser.parse_chacha20_poly1305_file(str(RFC8439_CHACHA20_FILE))

    if not vectors:
        pytest.skip("No test vectors found in file")

    results = TestVectorResults()

    print(f"Running {len(vectors)} test vectors...")

    for vector in vectors:
        try:
            # Encrypt with our implementation (pass AAD if available)
            ciphertext, nonce_out, auth_tag = encrypt(
                "chacha20",
                vector.key,
                vector.plaintext,
                iv_mode=vector.nonce,
                auth="poly1305",
                aad=vector.aad,
            )

            # Verify nonce matches
            if nonce_out != vector.nonce:
                results.add_result(
                    False, f"Test Vector #{vector.test_case}", "Nonce mismatch"
                )
                continue

            # Verify ciphertext matches
            if ciphertext != vector.ciphertext:
                results.add_result(
                    False,
                    f"Test Vector #{vector.test_case}",
                    f"Ciphertext mismatch: expected {vector.ciphertext.hex()[:32]}..., got {ciphertext.hex()[:32]}...",
                )
                continue

            # Verify auth tag matches
            if auth_tag != vector.tag:
                results.add_result(
                    False,
                    f"Test Vector #{vector.test_case}",
                    f"Auth tag mismatch: expected {vector.tag.hex()}, got {auth_tag.hex()}",
                )
                continue

            # Verify decryption (pass AAD if available)
            try:
                decrypted = decrypt(
                    "chacha20",
                    vector.key,
                    ciphertext,
                    vector.nonce,
                    auth="poly1305",
                    auth_tag=auth_tag,
                    aad=vector.aad,
                )

                if decrypted != vector.plaintext:
                    results.add_result(
                        False, f"Test Vector #{vector.test_case}", "Decryption failed"
                    )
                    continue

            except ValueError as e:
                results.add_result(
                    False, f"Test Vector #{vector.test_case}", f"Decryption error: {e}"
                )
                continue

            results.add_result(True, f"Test Vector #{vector.test_case}")

        except Exception as e:
            results.add_result(
                False,
                f"Test Vector #{vector.test_case}",
                f"Exception: {type(e).__name__}: {str(e)}",
            )

    print("\n" + results.get_summary())
    results.print_failures()

    assert results.failed == 0, f"{results.failed} test vectors failed"
    assert results.total == len(vectors), "Test vector count mismatch"


@pytest.fixture(scope="session")
def create_sample_test_vectors(tmp_path_factory):
    """Create sample test vectors for testing the parser (if real vectors not available)."""
    test_dir = tmp_path_factory.mktemp("test_vectors")

    # Create a simple AES-GCM test vector file
    aes_gcm_sample = test_dir / "aes_gcm_128_sample.txt"
    aes_gcm_sample.write_text(
        """Count = 0
Key = 00000000000000000000000000000000
IV = 000000000000000000000000
PT =
AAD =
CT =
Tag = 58e2fccefa7e3061367f1d57a4e7455a

Count = 1
Key = 00000000000000000000000000000000
IV = 000000000000000000000000
PT = 00000000000000000000000000000000
AAD =
CT = 0388dace60b6a392f328c2b971b2fe78
Tag = ab6e47d42cec13bdf53a67b21257bddf
"""
    )

    return test_dir


def test_nist_parser_with_sample(create_sample_test_vectors):
    """Test NIST parser with sample vectors."""
    sample_file = create_sample_test_vectors / "aes_gcm_128_sample.txt"
    vectors = NISTCAVPParser.parse_aes_gcm_file(str(sample_file))

    assert len(vectors) == 2, f"Expected 2 vectors, got {len(vectors)}"
    assert vectors[0].count == 0
    assert vectors[1].count == 1
    assert len(vectors[0].key) == 16, "Key should be 16 bytes"
    assert len(vectors[1].plaintext) == 16, "Plaintext should be 16 bytes"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
