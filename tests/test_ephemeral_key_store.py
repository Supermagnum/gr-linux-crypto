# -*- coding: utf-8 -*-
"""Tests for ephemeral key offer store and Galdralag offer validation helpers."""

import os
import unittest
from unittest.mock import MagicMock

import pytest

from cryptography.hazmat.primitives import serialization

from gr_linux_crypto.crypto_helpers import CryptoHelpers
from gr_linux_crypto.ephemeral_key_store import EphemeralKeyStore, OFFER_SCHEMA_VERSION
from gr_linux_crypto.galdralag_session_kdf import (
    derive_galdralag_session_keys,
    validate_offer_consumed,
    validate_offer_expiry,
)


class TestValidateOfferHelpers(unittest.TestCase):
    def test_validate_offer_expiry_future(self):
        o = {"expires_at": 2_000_000_000}
        self.assertTrue(validate_offer_expiry(o, now=1_000_000_000.0))

    def test_validate_offer_expiry_past(self):
        o = {"expires_at": 1_000_000_000}
        self.assertFalse(validate_offer_expiry(o, now=2_000_000_000.0))

    def test_validate_offer_consumed_false_means_ok(self):
        self.assertTrue(validate_offer_consumed({"consumed": False}))

    def test_validate_offer_consumed_true_rejected(self):
        self.assertFalse(validate_offer_consumed({"consumed": True}))


class TestEphemeralKeyStoreDerive(unittest.TestCase):
    def setUp(self):
        self.a_priv, self.a_pub = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        self.b_priv, self.b_pub = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        self.epk_a = self.a_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self.epk_b = self.b_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    def _minimal_offer(self, sid: str) -> dict:
        return {
            "schema_version": OFFER_SCHEMA_VERSION,
            "epk_hex": self.epk_a.hex(),
            "long_term_fingerprint": "aa" * 20,
            "signature_hex": "ab",
            "expires_at": 9_000_000_000,
            "created_at": 1_000_000_000,
            "session_id": sid,
            "consumed": False,
        }

    def test_derive_both_roles_same_gdss_mask(self):
        shared = CryptoHelpers.brainpool_ecdh(
            self.b_priv,
            CryptoHelpers.brainpool_public_key_from_sec1_uncompressed(self.epk_a),
        )
        k_i = derive_galdralag_session_keys(shared, self.epk_a, self.epk_b)
        shared2 = CryptoHelpers.brainpool_ecdh(
            self.a_priv,
            CryptoHelpers.brainpool_public_key_from_sec1_uncompressed(self.epk_b),
        )
        k_r = derive_galdralag_session_keys(shared2, self.epk_a, self.epk_b)
        self.assertEqual(k_i["gdss_mask_key"], k_r["gdss_mask_key"])
        self.assertEqual(len(k_i), 7)

    def test_derive_marks_consumed_and_rejects_second(self):
        sid = "01" * 16
        offer = self._minimal_offer(sid)
        store = EphemeralKeyStore(time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = dict(offer)
        keys = store.derive_session_keys(sid, self.b_priv, offer, peer_was_initiator=True)
        self.assertIn("gdss_mask_key", keys)
        with self.assertRaises(ValueError):
            store.derive_session_keys(sid, self.b_priv, offer, peer_was_initiator=True)

    def test_derive_rejects_expired(self):
        sid = "02" * 16
        offer = self._minimal_offer(sid)
        offer["expires_at"] = 1_000_000_000
        store = EphemeralKeyStore(time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = dict(offer)
        with self.assertRaises(ValueError):
            store.derive_session_keys(sid, self.b_priv, offer, peer_was_initiator=True)

    def test_derive_rejects_epk_mismatch(self):
        sid = "03" * 16
        offer = self._minimal_offer(sid)
        store = EphemeralKeyStore(time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = dict(offer)
        bad = dict(offer)
        bad["epk_hex"] = ("00" * 65)
        with self.assertRaises(ValueError):
            store.derive_session_keys(sid, self.b_priv, bad, peer_was_initiator=True)


class TestEphemeralKeyStoreImportMocks(unittest.TestCase):
    def test_store_with_timeout_calls_keyctl(self):
        kh = MagicMock()
        kh.store_with_timeout.return_value = "12345"
        store = EphemeralKeyStore(keyring_helper=kh)
        priv, _pub = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        kid = store.store_private_in_keyring(priv, "abcd" * 4, 3600)
        self.assertEqual(kid, "12345")
        kh.store_with_timeout.assert_called_once()


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("RUN_KEYRING_SLOW_TESTS") != "1",
    reason="Set RUN_KEYRING_SLOW_TESTS=1 to run keyctl timeout integration (sleeps ~11s).",
)
def test_offer_keyring_timeout_removes_key():
    import time as _time

    from gr_linux_crypto.keyring_helper import KeyringHelper

    kh = KeyringHelper()
    kid = kh.store_with_timeout(
        "gr_linux_crypto:slow_timeout_test_key",
        b"payload",
        10,
        "@s",
    )
    assert kid
    _time.sleep(11)
    try:
        kh.read_key_raw(kid)
        raise AssertionError("expected key to expire")
    except Exception:
        pass


if __name__ == "__main__":
    unittest.main()
