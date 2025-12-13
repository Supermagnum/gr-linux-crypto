#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for multi-recipient ECIES encryption/decryption.

Tests include:
- Known test vectors
- Encrypt/decrypt round-trips
- All recipient counts from 1 to 25
- Verification that each recipient can decrypt
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from callsign_key_store import CallsignKeyStore  # noqa: E402
from crypto_helpers import CryptoHelpers  # noqa: E402
from multi_recipient_ecies import MultiRecipientECIES  # noqa: E402


class TestMultiRecipientECIES(unittest.TestCase):
    """Test suite for multi-recipient ECIES."""

    def setUp(self):
        """Set up test fixtures."""
        self.crypto = CryptoHelpers()
        self.curve = "brainpoolP256r1"

        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()

        self.test_callsigns = []
        self.test_keypairs = []

        self.key_store = CallsignKeyStore(
            store_path=self.temp_file.name, use_keyring=False
        )
        self.ecies = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def _generate_test_recipients(self, count: int):
        """Generate test recipients with keypairs."""
        self.test_callsigns = []
        self.test_keypairs = []

        for i in range(count):
            callsign = f"W{i+1:02d}ABC"
            private_key, public_key = self.crypto.generate_brainpool_keypair(self.curve)
            public_key_pem = self.crypto.serialize_brainpool_public_key(public_key)
            private_key_pem = self.crypto.serialize_brainpool_private_key(private_key)

            self.test_callsigns.append(callsign)
            self.test_keypairs.append((callsign, private_key_pem, public_key_pem))

            self.key_store.add_public_key(callsign, public_key_pem.decode("ascii"))

        self.ecies = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )

    def test_single_recipient(self):
        """Test encryption/decryption with single recipient."""
        self._generate_test_recipients(1)

        plaintext = b"Hello, single recipient!"
        callsigns = [self.test_callsigns[0]]

        encrypted = self.ecies.encrypt(plaintext, callsigns)
        self.assertIsInstance(encrypted, bytes)
        self.assertGreater(len(encrypted), len(plaintext))

        callsign, private_key_pem, _ = self.test_keypairs[0]
        decrypted = self.ecies.decrypt(
            encrypted, callsign, private_key_pem.decode("ascii")
        )

        self.assertEqual(plaintext, decrypted)

    def test_multiple_recipients(self):
        """Test encryption/decryption with multiple recipients."""
        self._generate_test_recipients(5)

        plaintext = b"Hello, multiple recipients!"
        callsigns = self.test_callsigns

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        for callsign, private_key_pem, _ in self.test_keypairs:
            decrypted = self.ecies.decrypt(
                encrypted, callsign, private_key_pem.decode("ascii")
            )
            self.assertEqual(plaintext, decrypted, f"Decryption failed for {callsign}")

    def test_all_recipient_counts(self):
        """Test all recipient counts from 1 to 25."""
        plaintext = b"Test message for recipient count validation"

        for count in range(1, 26):
            with self.subTest(recipient_count=count):
                self._generate_test_recipients(count)
                callsigns = self.test_callsigns

                encrypted = self.ecies.encrypt(plaintext, callsigns)
                self.assertIsInstance(encrypted, bytes)

                for callsign, private_key_pem, _ in self.test_keypairs:
                    decrypted = self.ecies.decrypt(
                        encrypted, callsign, private_key_pem.decode("ascii")
                    )
                    self.assertEqual(
                        plaintext,
                        decrypted,
                        f"Decryption failed for {callsign} with {count} recipients",
                    )

    def test_max_recipients(self):
        """Test maximum number of recipients (25)."""
        self._generate_test_recipients(25)

        plaintext = b"Test message for maximum recipients"
        callsigns = self.test_callsigns

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        for callsign, private_key_pem, _ in self.test_keypairs:
            decrypted = self.ecies.decrypt(
                encrypted, callsign, private_key_pem.decode("ascii")
            )
            self.assertEqual(plaintext, decrypted)

    def test_recipient_not_in_list(self):
        """Test that recipient not in list cannot decrypt."""
        self._generate_test_recipients(3)

        plaintext = b"Secret message"
        callsigns = self.test_callsigns[:2]

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        excluded_callsign, excluded_private_key_pem, _ = self.test_keypairs[2]

        with self.assertRaises(ValueError):
            self.ecies.decrypt(
                encrypted, excluded_callsign, excluded_private_key_pem.decode("ascii")
            )

    def test_different_plaintext_sizes(self):
        """Test with different plaintext sizes."""
        self._generate_test_recipients(3)
        callsigns = self.test_callsigns

        test_sizes = [1, 16, 64, 256, 1024, 4096]

        for size in test_sizes:
            with self.subTest(plaintext_size=size):
                plaintext = b"X" * size

                encrypted = self.ecies.encrypt(plaintext, callsigns)

                for callsign, private_key_pem, _ in self.test_keypairs:
                    decrypted = self.ecies.decrypt(
                        encrypted, callsign, private_key_pem.decode("ascii")
                    )
                    self.assertEqual(plaintext, decrypted)

    def test_duplicate_callsigns_rejected(self):
        """Test that duplicate callsigns are rejected."""
        self._generate_test_recipients(2)

        plaintext = b"Test"
        callsigns = [self.test_callsigns[0], self.test_callsigns[0]]

        with self.assertRaises(ValueError):
            self.ecies.encrypt(plaintext, callsigns)

    def test_invalid_recipient_count(self):
        """Test that invalid recipient counts are rejected."""
        self._generate_test_recipients(1)

        plaintext = b"Test"

        with self.assertRaises(ValueError):
            self.ecies.encrypt(plaintext, [])

        self._generate_test_recipients(26)
        callsigns = self.test_callsigns

        with self.assertRaises(ValueError):
            self.ecies.encrypt(plaintext, callsigns)

    def test_missing_public_key(self):
        """Test that missing public keys are detected."""
        plaintext = b"Test"
        callsigns = ["UNKNOWN"]

        with self.assertRaises(ValueError):
            self.ecies.encrypt(plaintext, callsigns)

    def test_format_version(self):
        """Test format version in header."""
        self._generate_test_recipients(1)

        plaintext = b"Test"
        callsigns = [self.test_callsigns[0]]

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        version = encrypted[0]
        self.assertEqual(version, MultiRecipientECIES.FORMAT_VERSION)

    def test_curve_id(self):
        """Test curve ID in header."""
        self._generate_test_recipients(1)

        plaintext = b"Test"
        callsigns = [self.test_callsigns[0]]

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        curve_id = encrypted[1]
        self.assertEqual(curve_id, self.ecies.curve_id)

    def test_recipient_count_in_header(self):
        """Test recipient count in header."""
        for count in [1, 5, 10, 25]:
            with self.subTest(recipient_count=count):
                self._generate_test_recipients(count)

                plaintext = b"Test"
                callsigns = self.test_callsigns

                encrypted = self.ecies.encrypt(plaintext, callsigns)

                header_recipient_count = encrypted[2]
                self.assertEqual(header_recipient_count, count)

    def test_different_curves(self):
        """Test with different Brainpool curves."""
        plaintext = b"Test message"

        for curve in ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]:
            with self.subTest(curve=curve):
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
                temp_file.close()

                key_store = CallsignKeyStore(
                    store_path=temp_file.name, use_keyring=False
                )
                crypto = CryptoHelpers()

                callsigns = []
                keypairs = []

                for i in range(3):
                    callsign = f"W{i+1:02d}ABC"
                    private_key, public_key = crypto.generate_brainpool_keypair(curve)
                    public_key_pem = crypto.serialize_brainpool_public_key(public_key)
                    private_key_pem = crypto.serialize_brainpool_private_key(
                        private_key
                    )

                    callsigns.append(callsign)
                    keypairs.append((callsign, private_key_pem, public_key_pem))
                    key_store.add_public_key(callsign, public_key_pem.decode("ascii"))

                ecies = MultiRecipientECIES(curve=curve, key_store_path=temp_file.name)

                encrypted = ecies.encrypt(plaintext, callsigns)

                for callsign, private_key_pem, _ in keypairs:
                    decrypted = ecies.decrypt(
                        encrypted, callsign, private_key_pem.decode("ascii")
                    )
                    self.assertEqual(plaintext, decrypted)

                os.unlink(temp_file.name)

    def test_callsign_case_insensitive(self):
        """Test that callsigns are case-insensitive."""
        self._generate_test_recipients(1)

        plaintext = b"Test"
        callsigns = [self.test_callsigns[0].lower()]

        encrypted = self.ecies.encrypt(plaintext, callsigns)

        callsign, private_key_pem, _ = self.test_keypairs[0]
        decrypted = self.ecies.decrypt(
            encrypted, callsign.upper(), private_key_pem.decode("ascii")
        )

        self.assertEqual(plaintext, decrypted)


class TestKnownTestVectors(unittest.TestCase):
    """Test with known test vectors."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_known_plaintext(self):
        """Test with known plaintext."""
        crypto = CryptoHelpers()
        key_store = CallsignKeyStore(store_path=self.temp_file.name, use_keyring=False)

        callsign = "W1ABC"
        private_key, public_key = crypto.generate_brainpool_keypair()
        public_key_pem = crypto.serialize_brainpool_public_key(public_key)
        private_key_pem = crypto.serialize_brainpool_private_key(private_key)

        key_store.add_public_key(callsign, public_key_pem.decode("ascii"))

        ecies = MultiRecipientECIES(key_store_path=self.temp_file.name)

        known_plaintext = b"The quick brown fox jumps over the lazy dog"

        encrypted = ecies.encrypt(known_plaintext, [callsign])
        decrypted = ecies.decrypt(encrypted, callsign, private_key_pem.decode("ascii"))

        self.assertEqual(known_plaintext, decrypted)

    def test_empty_plaintext(self):
        """Test with empty plaintext."""
        crypto = CryptoHelpers()
        key_store = CallsignKeyStore(store_path=self.temp_file.name, use_keyring=False)

        callsign = "W1ABC"
        private_key, public_key = crypto.generate_brainpool_keypair()
        public_key_pem = crypto.serialize_brainpool_public_key(public_key)
        private_key_pem = crypto.serialize_brainpool_private_key(private_key)

        key_store.add_public_key(callsign, public_key_pem.decode("ascii"))

        ecies = MultiRecipientECIES(key_store_path=self.temp_file.name)

        plaintext = b""

        encrypted = ecies.encrypt(plaintext, [callsign])
        decrypted = ecies.decrypt(encrypted, callsign, private_key_pem.decode("ascii"))

        self.assertEqual(plaintext, decrypted)


class TestChaCha20Poly1305(unittest.TestCase):
    """Test suite for ChaCha20-Poly1305 cipher in ECIES."""

    def setUp(self):
        """Set up test fixtures."""
        self.crypto = CryptoHelpers()
        self.curve = "brainpoolP256r1"

        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()

        self.test_callsigns = []
        self.test_keypairs = []

        self.key_store = CallsignKeyStore(
            store_path=self.temp_file.name, use_keyring=False
        )

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def _generate_test_recipients(self, count: int):
        """Generate test recipients with keypairs."""
        self.test_callsigns = []
        self.test_keypairs = []

        for i in range(count):
            callsign = f"W{i+1:02d}ABC"
            private_key, public_key = self.crypto.generate_brainpool_keypair(self.curve)
            public_key_pem = self.crypto.serialize_brainpool_public_key(public_key)
            private_key_pem = self.crypto.serialize_brainpool_private_key(private_key)

            self.test_callsigns.append(callsign)
            self.test_keypairs.append((callsign, private_key_pem, public_key_pem))

            self.key_store.add_public_key(callsign, public_key_pem.decode("ascii"))

    def test_chacha20_poly1305_single_recipient(self):
        """Test ChaCha20-Poly1305 encryption/decryption with single recipient."""
        self._generate_test_recipients(1)

        ecies = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="chacha20-poly1305",
        )

        plaintext = b"Hello, ChaCha20-Poly1305!"
        callsigns = [self.test_callsigns[0]]

        encrypted = ecies.encrypt(plaintext, callsigns)
        self.assertIsInstance(encrypted, bytes)
        self.assertGreater(len(encrypted), len(plaintext))

        callsign, private_key_pem, _ = self.test_keypairs[0]
        decrypted = ecies.decrypt(encrypted, callsign, private_key_pem.decode("ascii"))

        self.assertEqual(plaintext, decrypted)

    def test_chacha20_poly1305_multiple_recipients(self):
        """Test ChaCha20-Poly1305 encryption/decryption with multiple recipients."""
        self._generate_test_recipients(5)

        ecies = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="chacha20-poly1305",
        )

        plaintext = b"Hello, multiple recipients with ChaCha20!"
        callsigns = self.test_callsigns

        encrypted = ecies.encrypt(plaintext, callsigns)

        for callsign, private_key_pem, _ in self.test_keypairs:
            decrypted = ecies.decrypt(
                encrypted, callsign, private_key_pem.decode("ascii")
            )
            self.assertEqual(plaintext, decrypted, f"Decryption failed for {callsign}")

    def test_cipher_interoperability(self):
        """Test that AES-GCM encrypted data can be decrypted and vice versa are separate."""
        self._generate_test_recipients(2)

        plaintext = b"Interoperability test"

        # Encrypt with AES-GCM
        ecies_aes = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )
        encrypted_aes = ecies_aes.encrypt(plaintext, [self.test_callsigns[0]])

        # Decrypt with AES-GCM (should work)
        decrypted_aes = ecies_aes.decrypt(
            encrypted_aes,
            self.test_callsigns[0],
            self.test_keypairs[0][1].decode("ascii"),
        )
        self.assertEqual(plaintext, decrypted_aes)

        # Encrypt with ChaCha20-Poly1305
        ecies_chacha = MultiRecipientECIES(
            curve=self.curve,
            key_store_path=self.temp_file.name,
            symmetric_cipher="chacha20-poly1305",
        )
        encrypted_chacha = ecies_chacha.encrypt(plaintext, [self.test_callsigns[0]])

        # Decrypt with ChaCha20-Poly1305 (should work)
        decrypted_chacha = ecies_chacha.decrypt(
            encrypted_chacha,
            self.test_callsigns[0],
            self.test_keypairs[0][1].decode("ascii"),
        )
        self.assertEqual(plaintext, decrypted_chacha)

        # Verify different ciphers produce different ciphertexts
        self.assertNotEqual(encrypted_aes, encrypted_chacha)

    def test_invalid_cipher(self):
        """Test that invalid cipher names raise ValueError."""
        with self.assertRaises(ValueError):
            MultiRecipientECIES(
                curve=self.curve,
                key_store_path=self.temp_file.name,
                symmetric_cipher="invalid-cipher",
            )


if __name__ == "__main__":
    unittest.main()
