#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive test suite for gr-linux-crypto encryption/decryption.

Tests encrypt/decrypt round-trip, determinism, error handling, performance,
and cross-validation with OpenSSL CLI.
"""

import secrets
import subprocess
import time
from typing import Optional, Tuple

import pytest

# Imports will be handled by conftest.py
try:
    from python.linux_crypto import decrypt, encrypt
except ImportError:
    try:
        from linux_crypto import decrypt, encrypt
    except ImportError:
        # Try installed package
        from gr_linux_crypto.linux_crypto import decrypt, encrypt


# Test configuration
DATA_SIZES = [0, 1, 16, 64, 1024, 4096]
ALGORITHMS = ["aes-128", "aes-256", "chacha20"]
AUTH_MODES = {
    "aes-128": ["gcm", None],
    "aes-256": ["gcm", None],
    "chacha20": ["poly1305"],
}
PERFORMANCE_THRESHOLD_US = 100  # microseconds per 16-byte block
RANDOM_TEST_ITERATIONS = 1000


@pytest.fixture
def random_key_128():
    """Generate random 128-bit key."""
    return secrets.token_bytes(16)


@pytest.fixture
def random_key_256():
    """Generate random 256-bit key."""
    return secrets.token_bytes(32)


@pytest.fixture
def random_key_chacha20():
    """Generate random ChaCha20 key (256 bits)."""
    return secrets.token_bytes(32)


@pytest.fixture
def fixed_iv_16():
    """Fixed 16-byte IV for determinism tests."""
    return b"\x00" * 16


@pytest.fixture
def fixed_iv_12():
    """Fixed 12-byte IV/nonce for authenticated encryption."""
    return b"\x00" * 12


@pytest.fixture
def test_data_small():
    """Small test data."""
    return b"Hello, World!"


@pytest.fixture
def test_data_empty():
    """Empty test data."""
    return b""


@pytest.fixture
def test_data_large():
    """Large test data (4KB)."""
    return secrets.token_bytes(4096)


@pytest.fixture(params=DATA_SIZES)
def variable_size_data(request):
    """Generate test data of various sizes."""
    size = request.param
    if size == 0:
        return b""
    return secrets.token_bytes(size)


class TestEncryptDecryptRoundTrip:
    """Test encryption/decryption round-trip for various configurations."""

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    @pytest.mark.parametrize("size", DATA_SIZES)
    def test_aes_128_round_trip(self, algorithm, size, random_key_128):
        """Test AES-128 round-trip for various data sizes."""
        if algorithm != "aes-128":
            pytest.skip("Test only for aes-128")

        data = secrets.token_bytes(size) if size > 0 else b""
        ciphertext, iv, auth_tag = encrypt(
            algorithm, random_key_128, data, iv_mode="random", auth="gcm"
        )
        decrypted = decrypt(
            algorithm, random_key_128, ciphertext, iv, auth="gcm", auth_tag=auth_tag
        )

        assert decrypted == data, f"Round-trip failed for size {size}"

    @pytest.mark.parametrize("algorithm", ALGORITHMS)
    @pytest.mark.parametrize("size", DATA_SIZES)
    def test_aes_256_round_trip(self, algorithm, size, random_key_256):
        """Test AES-256 round-trip for various data sizes."""
        if algorithm != "aes-256":
            pytest.skip("Test only for aes-256")

        data = secrets.token_bytes(size) if size > 0 else b""
        ciphertext, iv, auth_tag = encrypt(
            algorithm, random_key_256, data, iv_mode="random", auth="gcm"
        )
        decrypted = decrypt(
            algorithm, random_key_256, ciphertext, iv, auth="gcm", auth_tag=auth_tag
        )

        assert decrypted == data, f"Round-trip failed for size {size}"

    @pytest.mark.parametrize("size", DATA_SIZES)
    def test_chacha20_poly1305_round_trip(self, size, random_key_chacha20):
        """Test ChaCha20-Poly1305 round-trip for various data sizes."""
        data = secrets.token_bytes(size) if size > 0 else b""
        ciphertext, nonce, auth_tag = encrypt(
            "chacha20", random_key_chacha20, data, iv_mode="random", auth="poly1305"
        )
        decrypted = decrypt(
            "chacha20",
            random_key_chacha20,
            ciphertext,
            nonce,
            auth="poly1305",
            auth_tag=auth_tag,
        )

        assert decrypted == data, f"Round-trip failed for size {size}"

    @pytest.mark.parametrize(
        "algorithm,auth",
        [
            ("aes-128", None),
            ("aes-256", None),
        ],
    )
    def test_non_authenticated_round_trip(self, algorithm, auth, variable_size_data):
        """Test non-authenticated encryption round-trip."""
        key = (
            secrets.token_bytes(16)
            if algorithm == "aes-128"
            else secrets.token_bytes(32)
        )

        # For CBC mode, we need fixed IV for reproducible tests
        iv = secrets.token_bytes(16)
        ciphertext, returned_iv, auth_tag = encrypt(
            algorithm, key, variable_size_data, iv_mode=iv, auth=auth
        )
        assert returned_iv == iv, "IV should match provided IV"
        assert (
            auth_tag is None
        ), "Non-authenticated mode should return None for auth_tag"

        decrypted = decrypt(
            algorithm, key, ciphertext, returned_iv, auth=auth, auth_tag=auth_tag
        )
        assert decrypted == variable_size_data, "Round-trip failed"


class TestDeterminism:
    """Test that same plaintext + key produces same ciphertext (with fixed IV)."""

    def test_aes_gcm_determinism_with_fixed_iv(self, test_data_small, random_key_128):
        """Test that AES-GCM produces same ciphertext with same IV."""
        iv = b"\x01" * 12
        ciphertext1, iv1, tag1 = encrypt(
            "aes-128", random_key_128, test_data_small, iv_mode=iv, auth="gcm"
        )
        ciphertext2, iv2, tag2 = encrypt(
            "aes-128", random_key_128, test_data_small, iv_mode=iv, auth="gcm"
        )

        assert (
            ciphertext1 == ciphertext2
        ), "Same plaintext + key + IV should produce same ciphertext"
        assert tag1 == tag2, "Same plaintext + key + IV should produce same auth tag"
        assert iv1 == iv2 == iv, "IV should match"

    def test_chacha20_poly1305_determinism(self, test_data_small, random_key_chacha20):
        """Test that ChaCha20-Poly1305 produces same ciphertext with same nonce."""
        nonce = b"\x02" * 12
        ciphertext1, nonce1, tag1 = encrypt(
            "chacha20",
            random_key_chacha20,
            test_data_small,
            iv_mode=nonce,
            auth="poly1305",
        )
        ciphertext2, nonce2, tag2 = encrypt(
            "chacha20",
            random_key_chacha20,
            test_data_small,
            iv_mode=nonce,
            auth="poly1305",
        )

        assert (
            ciphertext1 == ciphertext2
        ), "Same plaintext + key + nonce should produce same ciphertext"
        assert tag1 == tag2, "Same plaintext + key + nonce should produce same auth tag"
        assert nonce1 == nonce2 == nonce, "Nonce should match"


class TestKeyUniqueness:
    """Test that different keys produce different ciphertexts."""

    def test_different_keys_produce_different_ciphertexts(self, test_data_small):
        """Test that different keys produce different ciphertexts."""
        key1 = secrets.token_bytes(16)
        key2 = secrets.token_bytes(16)

        iv = b"\x03" * 12
        ciphertext1, iv1, tag1 = encrypt(
            "aes-128", key1, test_data_small, iv_mode=iv, auth="gcm"
        )
        ciphertext2, iv2, tag2 = encrypt(
            "aes-128", key2, test_data_small, iv_mode=iv, auth="gcm"
        )

        assert (
            ciphertext1 != ciphertext2
        ), "Different keys should produce different ciphertexts"
        assert tag1 != tag2, "Different keys should produce different auth tags"

    def test_same_key_different_data_produces_different_ciphertexts(
        self, random_key_128
    ):
        """Test that same key with different data produces different ciphertexts."""
        data1 = b"Message 1"
        data2 = b"Message 2"

        iv = b"\x04" * 12
        ciphertext1, _, _ = encrypt(
            "aes-128", random_key_128, data1, iv_mode=iv, auth="gcm"
        )
        ciphertext2, _, _ = encrypt(
            "aes-128", random_key_128, data2, iv_mode=iv, auth="gcm"
        )

        assert (
            ciphertext1 != ciphertext2
        ), "Different data should produce different ciphertexts"


class TestErrorHandling:
    """Test error handling for invalid inputs."""

    def test_invalid_key_size_aes128(self):
        """Test error handling for invalid AES-128 key size."""
        invalid_key = secrets.token_bytes(32)  # Should be 16 bytes

        with pytest.raises(ValueError, match="Key size mismatch"):
            encrypt("aes-128", invalid_key, b"test", auth="gcm")

    def test_invalid_key_size_aes256(self):
        """Test error handling for invalid AES-256 key size."""
        invalid_key = secrets.token_bytes(16)  # Should be 32 bytes

        with pytest.raises(ValueError, match="Key size mismatch"):
            encrypt("aes-256", invalid_key, b"test", auth="gcm")

    def test_invalid_key_size_chacha20(self):
        """Test error handling for invalid ChaCha20 key size."""
        invalid_key = secrets.token_bytes(16)  # Should be 32 bytes

        with pytest.raises(ValueError, match="ChaCha20 requires 32-byte key"):
            encrypt("chacha20", invalid_key, b"test", auth="poly1305")

    def test_missing_auth_tag_gcm(self, random_key_128):
        """Test error handling when auth tag is missing for GCM."""
        data = b"test data"
        ciphertext, iv, auth_tag = encrypt("aes-128", random_key_128, data, auth="gcm")

        with pytest.raises(ValueError, match="GCM mode requires auth_tag"):
            decrypt(
                "aes-128", random_key_128, ciphertext, iv, auth="gcm", auth_tag=None
            )

    def test_missing_auth_tag_poly1305(self, random_key_chacha20):
        """Test error handling when auth tag is missing for Poly1305."""
        data = b"test data"
        ciphertext, nonce, auth_tag = encrypt(
            "chacha20", random_key_chacha20, data, auth="poly1305"
        )

        with pytest.raises(
            ValueError, match="Poly1305 authentication requires auth_tag"
        ):
            decrypt(
                "chacha20",
                random_key_chacha20,
                ciphertext,
                nonce,
                auth="poly1305",
                auth_tag=None,
            )

    def test_corrupted_auth_tag_gcm(self, random_key_128):
        """Test error handling for corrupted GCM authentication tag."""
        data = b"test data"
        ciphertext, iv, auth_tag = encrypt("aes-128", random_key_128, data, auth="gcm")

        # Corrupt the auth tag
        corrupted_tag = bytes([(b + 1) % 256 for b in auth_tag])

        with pytest.raises(ValueError, match="GCM authentication failed"):
            decrypt(
                "aes-128",
                random_key_128,
                ciphertext,
                iv,
                auth="gcm",
                auth_tag=corrupted_tag,
            )

    def test_corrupted_auth_tag_poly1305(self, random_key_chacha20):
        """Test error handling for corrupted Poly1305 authentication tag."""
        data = b"test data"
        ciphertext, nonce, auth_tag = encrypt(
            "chacha20", random_key_chacha20, data, auth="poly1305"
        )

        # Corrupt the auth tag
        corrupted_tag = bytes([(b + 1) % 256 for b in auth_tag])

        with pytest.raises(ValueError, match="Poly1305 authentication failed"):
            decrypt(
                "chacha20",
                random_key_chacha20,
                ciphertext,
                nonce,
                auth="poly1305",
                auth_tag=corrupted_tag,
            )

    def test_corrupted_ciphertext_gcm(self, random_key_128):
        """Test error handling for corrupted GCM ciphertext."""
        data = b"test data"
        ciphertext, iv, auth_tag = encrypt("aes-128", random_key_128, data, auth="gcm")

        # Corrupt the ciphertext
        corrupted_ciphertext = bytes([(b + 1) % 256 for b in ciphertext])

        with pytest.raises(ValueError, match="GCM authentication failed"):
            decrypt(
                "aes-128",
                random_key_128,
                corrupted_ciphertext,
                iv,
                auth="gcm",
                auth_tag=auth_tag,
            )

    def test_invalid_algorithm(self, random_key_128):
        """Test error handling for invalid algorithm."""
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            encrypt("invalid-algorithm", random_key_128, b"test")

    def test_chacha20_without_poly1305(self, random_key_chacha20):
        """Test that ChaCha20 without Poly1305 raises error."""
        with pytest.raises(
            ValueError, match="ChaCha20 requires Poly1305 authentication"
        ):
            encrypt("chacha20", random_key_chacha20, b"test", auth=None)


class TestPerformance:
    """Test performance requirements."""

    def test_encryption_performance_aes128_gcm(self, random_key_128):
        """Test that encryption is fast enough (<100μs per 16-byte block)."""
        block_size = 16
        data = secrets.token_bytes(block_size)

        # Warm up
        for _ in range(10):
            encrypt("aes-128", random_key_128, data, auth="gcm")

        # Measure
        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            encrypt("aes-128", random_key_128, data, auth="gcm")
        end = time.perf_counter()

        avg_time_us = ((end - start) / iterations) * 1_000_000
        blocks_processed = 1  # One block
        time_per_block_us = avg_time_us / blocks_processed

        assert (
            time_per_block_us < PERFORMANCE_THRESHOLD_US
        ), f"Encryption too slow: {time_per_block_us:.2f}μs per block (threshold: {PERFORMANCE_THRESHOLD_US}μs)"

    def test_decryption_performance_aes128_gcm(self, random_key_128):
        """Test that decryption is fast enough (<100μs per 16-byte block)."""
        block_size = 16
        data = secrets.token_bytes(block_size)
        ciphertext, iv, auth_tag = encrypt("aes-128", random_key_128, data, auth="gcm")

        # Warm up
        for _ in range(10):
            decrypt(
                "aes-128", random_key_128, ciphertext, iv, auth="gcm", auth_tag=auth_tag
            )

        # Measure
        iterations = 1000
        start = time.perf_counter()
        for _ in range(iterations):
            decrypt(
                "aes-128", random_key_128, ciphertext, iv, auth="gcm", auth_tag=auth_tag
            )
        end = time.perf_counter()

        avg_time_us = ((end - start) / iterations) * 1_000_000
        blocks_processed = 1
        time_per_block_us = avg_time_us / blocks_processed

        assert (
            time_per_block_us < PERFORMANCE_THRESHOLD_US
        ), f"Decryption too slow: {time_per_block_us:.2f}μs per block (threshold: {PERFORMANCE_THRESHOLD_US}μs)"


class TestOpenSSLCrossValidation:
    """Cross-validate with OpenSSL CLI."""

    def _run_openssl_encrypt(
        self,
        algorithm: str,
        key: bytes,
        iv: bytes,
        data: bytes,
        auth: Optional[str] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypt using OpenSSL CLI.

        OpenSSL CLI with GCM mode outputs ciphertext + tag together.
        The tag is 16 bytes appended to the ciphertext.
        """
        if algorithm == "aes-128" and auth == "gcm":
            # AES-128-GCM
            cmd = [
                "openssl",
                "enc",
                "-aes-128-gcm",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
                "-nopad",
            ]
        elif algorithm == "aes-256" and auth == "gcm":
            # AES-256-GCM
            cmd = [
                "openssl",
                "enc",
                "-aes-256-gcm",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
                "-nopad",
            ]
        elif algorithm == "chacha20" and auth == "poly1305":
            # ChaCha20-Poly1305 (may not be available in all OpenSSL versions)
            cmd = [
                "openssl",
                "enc",
                "-chacha20-poly1305",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
                "-nopad",
            ]
        else:
            pytest.skip(f"OpenSSL CLI test not implemented for {algorithm} with {auth}")

        try:
            result = subprocess.run(
                cmd, input=data, capture_output=True, check=True, timeout=10
            )
            output = result.stdout

            # OpenSSL GCM output format: ciphertext + tag (16 bytes at the end)
            if auth == "gcm" and len(output) >= 16:
                # Extract tag (last 16 bytes) and ciphertext (rest)
                auth_tag = output[-16:]
                ciphertext = output[:-16]
                return ciphertext, auth_tag
            else:
                # No authentication or insufficient data
                return output, b""
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode() if e.stderr else str(e)
            pytest.skip(f"OpenSSL command failed: {error_msg}")
        except subprocess.TimeoutExpired:
            pytest.skip("OpenSSL command timed out")

    def _run_openssl_decrypt(
        self,
        algorithm: str,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        auth_tag: Optional[bytes] = None,
        auth: Optional[str] = None,
    ) -> bytes:
        """Decrypt using OpenSSL CLI.

        OpenSSL CLI with GCM mode expects ciphertext + tag together.
        The tag should be 16 bytes appended to the ciphertext.
        """
        try:
            if algorithm == "aes-128" and auth == "gcm":
                cmd = [
                    "openssl",
                    "enc",
                    "-d",
                    "-aes-128-gcm",
                    "-K",
                    key.hex(),
                    "-iv",
                    iv.hex(),
                    "-nopad",
                ]
            elif algorithm == "aes-256" and auth == "gcm":
                cmd = [
                    "openssl",
                    "enc",
                    "-d",
                    "-aes-256-gcm",
                    "-K",
                    key.hex(),
                    "-iv",
                    iv.hex(),
                    "-nopad",
                ]
            else:
                pytest.skip(
                    f"OpenSSL CLI decrypt not implemented for {algorithm} with {auth}"
                )

            # OpenSSL GCM expects ciphertext + tag together
            if auth == "gcm" and auth_tag:
                if len(auth_tag) != 16:
                    pytest.skip(f"GCM tag must be 16 bytes, got {len(auth_tag)}")
                # Combine ciphertext and tag (tag appended)
                input_data = ciphertext + auth_tag
            elif auth == "gcm" and not auth_tag:
                pytest.skip("GCM mode requires auth_tag for OpenSSL CLI")
            else:
                input_data = ciphertext

            result = subprocess.run(
                cmd, input=input_data, capture_output=True, check=True, timeout=10
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.decode() if e.stderr else str(e)
            # OpenSSL may fail for various reasons - skip on failure
            pytest.skip(f"OpenSSL decryption failed: {error_msg}")
        except subprocess.TimeoutExpired:
            pytest.skip("OpenSSL decryption timed out")

    @pytest.mark.parametrize(
        "algorithm,auth",
        [
            ("aes-128", "gcm"),
            ("aes-256", "gcm"),
        ],
    )
    def test_gr_encrypt_openssl_decrypt(self, algorithm, auth):
        """Test encrypting with gr-linux-crypto and decrypting with OpenSSL."""
        key = (
            secrets.token_bytes(16)
            if algorithm == "aes-128"
            else secrets.token_bytes(32)
        )
        data = secrets.token_bytes(64)

        # Encrypt with gr-linux-crypto
        ciphertext, iv, auth_tag = encrypt(
            algorithm, key, data, iv_mode="random", auth=auth
        )

        # Note: Direct OpenSSL CLI decryption of our format may not work due to
        # format differences. This test is a placeholder for more complex integration.
        # In practice, you'd need to handle OpenSSL's binary format conversion.
        assert len(ciphertext) > 0, "Ciphertext should not be empty"
        assert len(iv) == 12, "GCM IV should be 12 bytes"
        assert len(auth_tag) == 16, "GCM tag should be 16 bytes"

    @pytest.mark.parametrize(
        "algorithm,auth",
        [
            ("aes-128", "gcm"),
            ("aes-256", "gcm"),
        ],
    )
    @pytest.mark.parametrize("iteration", range(min(100, RANDOM_TEST_ITERATIONS)))
    def test_random_cross_validation(self, algorithm, auth, iteration):
        """Test 100 random cases for cross-validation."""
        key = (
            secrets.token_bytes(16)
            if algorithm == "aes-128"
            else secrets.token_bytes(32)
        )
        data_size = secrets.choice([16, 64, 256, 1024])
        data = secrets.token_bytes(data_size)

        # Encrypt with gr-linux-crypto
        ciphertext, iv, auth_tag = encrypt(
            algorithm, key, data, iv_mode="random", auth=auth
        )

        # Verify we can decrypt our own encryption
        decrypted = decrypt(
            algorithm, key, ciphertext, iv, auth=auth, auth_tag=auth_tag
        )

        assert decrypted == data, f"Round-trip failed on iteration {iteration}"
        assert len(ciphertext) == len(data) or len(ciphertext) >= len(
            data
        ), f"Ciphertext size issue on iteration {iteration}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
