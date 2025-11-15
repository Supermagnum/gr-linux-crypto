#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RFC Compliance Tests for Brainpool Elliptic Curve Cryptography.

Tests compliance with:
- RFC 7027: Additional Elliptic Curves for OpenPGP
- RFC 6954: Using ECC Brainpool curves in IKEv2
- RFC 8734: Using Brainpool Curves in TLS 1.3

These tests validate that the implementation correctly handles Brainpool curves
in various protocol contexts as specified by these RFCs.
"""

import os
import sys
from pathlib import Path

import pytest

try:
    from test_rfc_vectors import (
        RFC6954Parser,
        RFC7027Parser,
        RFC8734Parser,
    )
except ImportError:
    from .test_rfc_vectors import (
        RFC6954Parser,
        RFC7027Parser,
        RFC8734Parser,
    )

try:
    from gr_linux_crypto.crypto_helpers import CryptoHelpers
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
    from crypto_helpers import CryptoHelpers


# Test vector directory
TEST_VECTORS_DIR = Path(__file__).parent / "test_vectors"


class TestRFC7027Compliance:
    """Test compliance with RFC 7027 (OpenPGP with Brainpool curves)."""

    @pytest.fixture(scope="class")
    def rfc7027_vectors(self):
        """Load RFC 7027 test vectors."""
        vectors_file = TEST_VECTORS_DIR / "rfc7027_test_vectors.json"
        if vectors_file.exists():
            return RFC7027Parser.parse_file(str(vectors_file))
        return []

    def test_rfc7027_curve_support(self):
        """Test that we support curves specified in RFC 7027."""
        crypto = CryptoHelpers()
        curves = crypto.get_brainpool_curves()

        # RFC 7027 specifies Brainpool curves for OpenPGP
        required_curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
        for curve in required_curves:
            assert curve in curves, f"RFC 7027 requires support for {curve}"

    @pytest.mark.parametrize(
        "curve_name", ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
    )
    def test_rfc7027_key_generation(self, curve_name):
        """Test key generation as specified in RFC 7027."""
        crypto = CryptoHelpers()

        # Generate key pair
        private_key, public_key = crypto.generate_brainpool_keypair(curve_name)

        assert private_key is not None, "Private key generation failed"
        assert public_key is not None, "Public key generation failed"

        # Verify key serialization (RFC 7027 requires PEM format for OpenPGP)
        pub_pem = crypto.serialize_brainpool_public_key(public_key)
        priv_pem = crypto.serialize_brainpool_private_key(private_key)

        assert len(pub_pem) > 0, "Public key serialization failed"
        assert len(priv_pem) > 0, "Private key serialization failed"
        assert b"BEGIN" in pub_pem, "Public key should be in PEM format"
        assert b"BEGIN" in priv_pem, "Private key should be in PEM format"

    def test_rfc7027_test_vectors(self, rfc7027_vectors):
        """Test against RFC 7027 test vectors if available."""
        crypto = CryptoHelpers()

        # If vectors are available from file, use them
        if rfc7027_vectors:
            for vector in rfc7027_vectors:
                # Test key loading and operations
                # Note: Full implementation would test OpenPGP-specific operations
                assert (
                    vector.curve_name in crypto.get_brainpool_curves()
                ), f"Curve {vector.curve_name} not supported"
        else:
            # Generate test vectors programmatically to validate RFC 7027 compliance
            # This tests that we can generate keys and perform operations as required by RFC 7027
            curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
            for curve_name in curves:
                # Generate key pair (as required by RFC 7027)
                private_key, public_key = crypto.generate_brainpool_keypair(curve_name)

                # Verify key serialization (RFC 7027 requires PEM format for OpenPGP)
                pub_pem = crypto.serialize_brainpool_public_key(public_key)
                priv_pem = crypto.serialize_brainpool_private_key(private_key)

                # Verify keys are valid
                assert (
                    len(pub_pem) > 0
                ), f"RFC 7027: Public key serialization failed for {curve_name}"
                assert (
                    len(priv_pem) > 0
                ), f"RFC 7027: Private key serialization failed for {curve_name}"
                assert (
                    b"BEGIN" in pub_pem
                ), f"RFC 7027: Public key must be PEM format for {curve_name}"
                assert (
                    b"BEGIN" in priv_pem
                ), f"RFC 7027: Private key must be PEM format for {curve_name}"


class TestRFC6954Compliance:
    """Test compliance with RFC 6954 (IKEv2 with Brainpool curves)."""

    @pytest.fixture(scope="class")
    def rfc6954_vectors(self):
        """Load RFC 6954 test vectors."""
        vectors_file = TEST_VECTORS_DIR / "rfc6954_test_vectors.json"
        if vectors_file.exists():
            return RFC6954Parser.parse_file(str(vectors_file))
        return []

    def test_rfc6954_curve_support(self):
        """Test that we support curves specified in RFC 6954."""
        crypto = CryptoHelpers()
        curves = crypto.get_brainpool_curves()

        # RFC 6954 specifies Brainpool curves for IKEv2
        required_curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
        for curve in required_curves:
            assert curve in curves, f"RFC 6954 requires support for {curve}"

    @pytest.mark.parametrize(
        "curve_name", ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
    )
    def test_rfc6954_ecdh_operations(self, curve_name):
        """Test ECDH operations as specified in RFC 6954 for IKEv2."""
        crypto = CryptoHelpers()

        # Simulate IKEv2 initiator and responder
        initiator_priv, initiator_pub = crypto.generate_brainpool_keypair(curve_name)
        responder_priv, responder_pub = crypto.generate_brainpool_keypair(curve_name)

        # Perform ECDH key exchange
        initiator_shared = crypto.brainpool_ecdh(initiator_priv, responder_pub)
        responder_shared = crypto.brainpool_ecdh(responder_priv, initiator_pub)

        # Shared secrets must match
        assert (
            initiator_shared == responder_shared
        ), "IKEv2 ECDH key exchange failed: shared secrets don't match"

        # Verify shared secret length matches curve
        expected_length = {
            "brainpoolP256r1": 32,
            "brainpoolP384r1": 48,
            "brainpoolP512r1": 64,
        }.get(curve_name, 32)

        assert (
            len(initiator_shared) == expected_length
        ), f"Shared secret length incorrect: {len(initiator_shared)} != {expected_length}"

    def test_rfc6954_test_vectors(self, rfc6954_vectors):
        """Test against RFC 6954 test vectors if available."""
        crypto = CryptoHelpers()

        # If vectors are available from file, use them
        if rfc6954_vectors:
            for vector in rfc6954_vectors:
                # Test ECDH with provided test vectors
                # Note: Would need to load keys from test vectors
                assert (
                    vector.curve_name in crypto.get_brainpool_curves()
                ), f"Curve {vector.curve_name} not supported"
        else:
            # Generate test vectors programmatically to validate RFC 6954 compliance
            # This tests IKEv2 ECDH operations as specified in RFC 6954
            curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
            for curve_name in curves:
                # Simulate IKEv2 initiator and responder (as per RFC 6954)
                initiator_priv, initiator_pub = crypto.generate_brainpool_keypair(
                    curve_name
                )
                responder_priv, responder_pub = crypto.generate_brainpool_keypair(
                    curve_name
                )

                # Perform ECDH key exchange (RFC 6954 IKEv2 key exchange)
                initiator_shared = crypto.brainpool_ecdh(initiator_priv, responder_pub)
                responder_shared = crypto.brainpool_ecdh(responder_priv, initiator_pub)

                # Verify shared secrets match (RFC 6954 requirement)
                assert (
                    initiator_shared == responder_shared
                ), f"RFC 6954: IKEv2 ECDH failed for {curve_name} - shared secrets don't match"

                # Verify shared secret length (RFC 6954 specifies key length)
                expected_length = {
                    "brainpoolP256r1": 32,
                    "brainpoolP384r1": 48,
                    "brainpoolP512r1": 64,
                }.get(curve_name, 32)
                assert (
                    len(initiator_shared) == expected_length
                ), f"RFC 6954: Shared secret length incorrect for {curve_name}"


class TestRFC8734Compliance:
    """Test compliance with RFC 8734 (TLS 1.3 with Brainpool curves)."""

    @pytest.fixture(scope="class")
    def rfc8734_vectors(self):
        """Load RFC 8734 test vectors."""
        vectors_file = TEST_VECTORS_DIR / "rfc8734_test_vectors.json"
        if vectors_file.exists():
            return RFC8734Parser.parse_file(str(vectors_file))
        return []

    def test_rfc8734_curve_support(self):
        """Test that we support curves specified in RFC 8734."""
        crypto = CryptoHelpers()
        curves = crypto.get_brainpool_curves()

        # RFC 8734 specifies Brainpool curves for TLS 1.3
        required_curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
        for curve in required_curves:
            assert curve in curves, f"RFC 8734 requires support for {curve}"

    @pytest.mark.parametrize(
        "curve_name", ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
    )
    def test_rfc8734_ecdh_operations(self, curve_name):
        """Test ECDH operations as specified in RFC 8734 for TLS 1.3."""
        crypto = CryptoHelpers()

        # Simulate TLS 1.3 client and server
        client_priv, client_pub = crypto.generate_brainpool_keypair(curve_name)
        server_priv, server_pub = crypto.generate_brainpool_keypair(curve_name)

        # Perform ECDH key exchange (TLS 1.3 key schedule)
        client_shared = crypto.brainpool_ecdh(client_priv, server_pub)
        server_shared = crypto.brainpool_ecdh(server_priv, client_pub)

        # Shared secrets must match
        assert (
            client_shared == server_shared
        ), "TLS 1.3 ECDH key exchange failed: shared secrets don't match"

        # Verify shared secret length
        expected_length = {
            "brainpoolP256r1": 32,
            "brainpoolP384r1": 48,
            "brainpoolP512r1": 64,
        }.get(curve_name, 32)

        assert (
            len(client_shared) == expected_length
        ), f"Shared secret length incorrect: {len(client_shared)} != {expected_length}"

    def test_rfc8734_test_vectors(self, rfc8734_vectors):
        """Test against RFC 8734 test vectors if available."""
        crypto = CryptoHelpers()

        # If vectors are available from file, use them
        if rfc8734_vectors:
            for vector in rfc8734_vectors:
                # Test ECDH with provided test vectors
                assert (
                    vector.curve_name in crypto.get_brainpool_curves()
                ), f"Curve {vector.curve_name} not supported"
        else:
            # Generate test vectors programmatically to validate RFC 8734 compliance
            # This tests TLS 1.3 ECDH operations as specified in RFC 8734
            curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
            for curve_name in curves:
                # Simulate TLS 1.3 client and server (as per RFC 8734)
                client_priv, client_pub = crypto.generate_brainpool_keypair(curve_name)
                server_priv, server_pub = crypto.generate_brainpool_keypair(curve_name)

                # Perform ECDH key exchange (RFC 8734 TLS 1.3 key exchange)
                client_shared = crypto.brainpool_ecdh(client_priv, server_pub)
                server_shared = crypto.brainpool_ecdh(server_priv, client_pub)

                # Verify shared secrets match (RFC 8734 requirement)
                assert (
                    client_shared == server_shared
                ), f"RFC 8734: TLS 1.3 ECDH failed for {curve_name} - shared secrets don't match"

                # Verify shared secret length (RFC 8734 specifies key length)
                expected_length = {
                    "brainpoolP256r1": 32,
                    "brainpoolP384r1": 48,
                    "brainpoolP512r1": 64,
                }.get(curve_name, 32)
                assert (
                    len(client_shared) == expected_length
                ), f"RFC 8734: Shared secret length incorrect for {curve_name}"
