#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Shamir secret sharing, HPKE-style wrapper, and Nitrokey bridge.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from shamir_secret_sharing import (  # noqa: E402
    split,
    reconstruct,
    create_shamir_backed_key,
    reconstruct_session_key,
    BRAINPOOL_P256R1_ORDER,
    get_curve_prime,
    get_max_secret_bytes,
    get_share_value_bytes,
    SUPPORTED_CURVES,
)
from callsign_key_store import CallsignKeyStore  # noqa: E402
from crypto_helpers import CryptoHelpers  # noqa: E402
from multi_recipient_ecies import MultiRecipientECIES  # noqa: E402
from hpke_brainpool import HPKEBrainpool  # noqa: E402
from nitrokey_bridge import decrypt_with_card, get_keygrip_from_key_id  # noqa: E402


class TestShamirSecretSharing(unittest.TestCase):
    """Tests for Shamir split/reconstruct and 32-byte key helpers."""

    def test_split_reconstruct_roundtrip(self):
        secret = b"31 bytes of secret data here!!!"  # 31 bytes
        self.assertEqual(len(secret), 31)
        shares = split(secret, threshold_k=2, num_shares_n=4)
        self.assertEqual(len(shares), 4)
        for i, (idx, val) in enumerate(shares):
            self.assertEqual(idx, i + 1)
            self.assertIsInstance(val, int)
        out = reconstruct([shares[0], shares[2]], secret_length=31)
        self.assertEqual(out[: len(secret)], secret)

    def test_threshold_k_of_n(self):
        secret = b"short" + b"\x00" * 26  # 31 bytes total
        self.assertEqual(len(secret), 31)
        shares = split(secret, threshold_k=3, num_shares_n=5)
        out = reconstruct(shares[:3], secret_length=31)
        self.assertEqual(out[:5], b"short")
        out2 = reconstruct([shares[1], shares[3], shares[4]], secret_length=31)
        self.assertEqual(out2[:5], b"short")

    def test_create_and_reconstruct_session_key(self):
        shares, key = create_shamir_backed_key(threshold_k=2, num_shares_n=3)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(shares), 3)
        recovered = reconstruct_session_key([shares[0], shares[1]])
        self.assertEqual(recovered, key)

    def test_shamir_invalid_args(self):
        with self.assertRaises(ValueError):
            split(b"x" * 32, 2, 4)
        with self.assertRaises(ValueError):
            split(b"ok", 3, 2)
        with self.assertRaises(ValueError):
            reconstruct([])

    def test_shamir_p384_roundtrip(self):
        # 31-byte secret fits in all curve fields; P384 uses 48-byte share encoding
        secret = b"31 bytes P384 secret data!!!!!!"
        self.assertEqual(len(secret), 31)
        shares = split(secret, 2, 4, curve="brainpoolP384r1")
        self.assertEqual(len(shares), 4)
        out = reconstruct(shares[:2], curve="brainpoolP384r1", secret_length=31)
        self.assertEqual(out[: len(secret)], secret)

    def test_shamir_p512_roundtrip(self):
        secret = b"63 bytes of secret for P512!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        self.assertEqual(len(secret), 63)
        shares = split(secret, 3, 5, curve="brainpoolP512r1")
        out = reconstruct(shares[:3], curve="brainpoolP512r1", secret_length=63)
        self.assertEqual(out[: len(secret)], secret)

    def test_create_reconstruct_session_key_all_curves(self):
        for curve in SUPPORTED_CURVES:
            shares, key = create_shamir_backed_key(2, 3, curve=curve)
            self.assertEqual(len(key), 32)
            recovered = reconstruct_session_key(shares[:2], curve=curve)
            self.assertEqual(recovered, key, f"curve={curve}")

    def test_get_curve_prime_and_share_bytes(self):
        self.assertEqual(get_share_value_bytes("brainpoolP256r1"), 32)
        self.assertEqual(get_share_value_bytes("brainpoolP384r1"), 48)
        self.assertEqual(get_share_value_bytes("brainpoolP512r1"), 64)
        self.assertGreater(get_curve_prime("brainpoolP384r1"), BRAINPOOL_P256R1_ORDER)
        self.assertGreater(get_curve_prime("brainpoolP512r1"), get_curve_prime("brainpoolP384r1"))
        self.assertEqual(get_max_secret_bytes(curve="brainpoolP256r1"), 31)
        self.assertEqual(get_max_secret_bytes(curve="brainpoolP384r1"), 47)
        self.assertEqual(get_max_secret_bytes(curve="brainpoolP512r1"), 63)


class TestShamirECIES(unittest.TestCase):
    """Tests for multi-recipient ECIES in Shamir mode."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()
        self.crypto = CryptoHelpers()
        self.key_store = CallsignKeyStore(
            store_path=self.temp_file.name, use_keyring=False
        )
        for i in range(4):
            callsign = f"W{i+1}ABC"
            _, pub = self.crypto.generate_brainpool_keypair("brainpoolP256r1")
            self.key_store.add_public_key(
                callsign, self.crypto.serialize_brainpool_public_key(pub).decode()
            )
        self.ecies = MultiRecipientECIES(
            curve="brainpoolP256r1",
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_encrypt_decrypt_shamir_roundtrip(self):
        callsigns = ["W1ABC", "W2ABC", "W3ABC", "W4ABC"]
        plain = b"Secret for K-of-N"
        ct = self.ecies.encrypt_shamir(plain, callsigns, threshold_k=3)
        self.assertEqual(ct[0], 0x02)
        my_share = self.ecies.get_share_from_shamir_block(ct, "W1ABC")
        other1 = self.ecies.get_share_from_shamir_block(ct, "W2ABC")
        other2 = self.ecies.get_share_from_shamir_block(ct, "W3ABC")
        dec = self.ecies.decrypt_shamir(ct, [my_share, other1, other2])
        self.assertEqual(dec, plain)

    def test_get_share_wrong_callsign(self):
        callsigns = ["W1ABC", "W2ABC"]
        ct = self.ecies.encrypt_shamir(b"x", callsigns, threshold_k=2)
        with self.assertRaises(ValueError):
            self.ecies.get_share_from_shamir_block(ct, "NOCALL")

    def test_encrypt_decrypt_shamir_p384(self):
        ecies384 = MultiRecipientECIES(
            curve="brainpoolP384r1",
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )
        callsigns = ["W1ABC", "W2ABC", "W3ABC"]
        plain = b"Shamir P384 quorum"
        ct = ecies384.encrypt_shamir(plain, callsigns, threshold_k=2, curve="brainpoolP384r1")
        self.assertEqual(ct[0], 0x02)
        self.assertEqual(ct[1], 0x02)  # curve_id for P384
        s1 = ecies384.get_share_from_shamir_block(ct, "W1ABC")
        s2 = ecies384.get_share_from_shamir_block(ct, "W2ABC")
        dec = ecies384.decrypt_shamir(ct, [s1, s2])
        self.assertEqual(dec, plain)

    def test_encrypt_decrypt_shamir_p512(self):
        ecies512 = MultiRecipientECIES(
            curve="brainpoolP512r1",
            key_store_path=self.temp_file.name,
            symmetric_cipher="aes-gcm",
        )
        callsigns = ["W1ABC", "W2ABC"]
        plain = b"Shamir P512"
        ct = ecies512.encrypt_shamir(plain, callsigns, threshold_k=2, curve="brainpoolP512r1")
        self.assertEqual(ct[0], 0x02)
        self.assertEqual(ct[1], 0x03)  # curve_id for P512
        s1 = ecies512.get_share_from_shamir_block(ct, "W1ABC")
        s2 = ecies512.get_share_from_shamir_block(ct, "W2ABC")
        dec = ecies512.decrypt_shamir(ct, [s1, s2])
        self.assertEqual(dec, plain)


class TestHPKEBrainpool(unittest.TestCase):
    """Tests for HPKE-style seal/open and authenticated variants."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()
        self.crypto = CryptoHelpers()
        self.key_store = CallsignKeyStore(
            store_path=self.temp_file.name, use_keyring=False
        )
        self.priv, self.pub = self.crypto.generate_brainpool_keypair("brainpoolP256r1")
        self.priv_pem = self.crypto.serialize_brainpool_private_key(self.priv)
        self.pub_pem = self.crypto.serialize_brainpool_public_key(self.pub)
        self.key_store.add_public_key("ALICE", self.pub_pem.decode())
        self.hpke = HPKEBrainpool(key_store_path=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_seal_open_roundtrip(self):
        plain = b"HPKE seal/open test"
        ct = self.hpke.seal(plain, ["ALICE"])
        dec = self.hpke.open(ct, "ALICE", self.priv_pem.decode())
        self.assertEqual(dec, plain)

    def test_seal_with_auth_open_with_auth_roundtrip(self):
        plain = b"Authenticated HPKE"
        sender_priv, sender_pub = self.crypto.generate_brainpool_keypair(
            "brainpoolP256r1"
        )
        sender_priv_pem = self.crypto.serialize_brainpool_private_key(sender_priv)
        sender_pub_pem = self.crypto.serialize_brainpool_public_key(sender_pub)
        ct, sig = self.hpke.seal_with_auth(
            plain, ["ALICE"], sender_priv_pem.decode()
        )
        dec = self.hpke.open_with_auth(
            ct, "ALICE", self.priv_pem.decode(), sig, sender_pub_pem.decode()
        )
        self.assertEqual(dec, plain)


class TestNitrokeyBridge(unittest.TestCase):
    """Tests for Nitrokey bridge (decrypt_with_card stub, get_keygrip_from_key_id)."""

    def test_decrypt_with_card_raises(self):
        with self.assertRaises(NotImplementedError) as ctx:
            decrypt_with_card(
                b"\x01\x01\x01\x01\x00\x00\x00\x00",
                "W1ABC",
                "A" * 40,
            )
        self.assertIn("opgp_card", str(ctx.exception))

    @unittest.skipUnless(
        os.environ.get("GR_LINUX_CRYPTO_TEST_GPG") == "1",
        "Set GR_LINUX_CRYPTO_TEST_GPG=1 and have gpg + test key to run",
    )
    def test_get_keygrip_from_key_id(self):
        keygrip = get_keygrip_from_key_id("test@example.com")
        self.assertEqual(len(keygrip), 40)
        self.assertTrue(all(c in "0123456789ABCDEFabcdef" for c in keygrip))


if __name__ == "__main__":
    unittest.main()
