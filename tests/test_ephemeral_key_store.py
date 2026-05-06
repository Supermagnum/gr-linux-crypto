# -*- coding: utf-8 -*-
"""Tests for ephemeral key offer store and Galdralag offer validation helpers."""

import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cryptography.hazmat.primitives import serialization

from gr_linux_crypto.crypto_helpers import CryptoHelpers
from gr_linux_crypto.ephemeral_key_store import (
    EphemeralKeyStore,
    OFFER_SCHEMA_VERSION,
    PRIV_KEYRING_PREFIX,
)
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


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_epk_generate_script():
    spec = importlib.util.spec_from_file_location(
        "epk_generate_cli",
        REPO_ROOT / "scripts" / "epk_generate.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestRevokeOffer(unittest.TestCase):
    def _minimal_offer(self, sid: str, epk_hex: str) -> dict:
        return {
            "schema_version": OFFER_SCHEMA_VERSION,
            "epk_hex": epk_hex,
            "long_term_fingerprint": "aa" * 20,
            "signature_hex": "ab",
            "expires_at": 9_000_000_000,
            "created_at": 1_000_000_000,
            "session_id": sid,
            "consumed": False,
        }

    def test_revoke_unconsumed_then_derive_raises_keyerror(self):
        sid = "11" * 16
        kh = MagicMock()
        kh.search_key.return_value = None
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "_keyring_key_id": "offer_kid", "consumed": False}
        peer_offer = {k: v for k, v in store._offers[sid].items() if k != "_keyring_key_id"}
        _, priv_r = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        store.revoke_offer(sid)
        kh.unlink_key.assert_any_call("offer_kid", "@s")
        self.assertNotIn(sid, store._offers)
        with self.assertRaises(KeyError):
            store.derive_session_keys(sid, priv_r, peer_offer, peer_was_initiator=True)

    def test_revoke_consumed_offer_succeeds(self):
        sid = "22" * 16
        kh = MagicMock()
        kh.search_key.return_value = None
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "_keyring_key_id": "kid", "consumed": True}
        store.revoke_offer(sid)
        self.assertNotIn(sid, store._offers)

    def test_revoke_consumed_without_keyring_ids_succeeds(self):
        sid = "33" * 16
        kh = MagicMock()
        kh.search_key.return_value = None
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "consumed": True}
        store.revoke_offer(sid)
        kh.unlink_key.assert_not_called()
        self.assertNotIn(sid, store._offers)

    def test_revoke_unknown_session_raises_keyerror(self):
        store = EphemeralKeyStore(keyring_helper=MagicMock())
        store._kh.search_key.return_value = None
        with self.assertRaises(KeyError):
            store.revoke_offer("ff" * 16)

    def test_revoke_unlinks_private_when_search_finds_it(self):
        sid = "44" * 16
        kh = MagicMock()

        def _search(_typ, desc, _kr):
            if PRIV_KEYRING_PREFIX in desc:
                return "priv_kid"
            return None

        kh.search_key.side_effect = _search
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "_keyring_key_id": "offer_kid", "consumed": False}
        store.revoke_offer(sid)
        kh.unlink_key.assert_any_call("offer_kid", "@s")
        kh.unlink_key.assert_any_call("priv_kid", "@s")

    def test_revoke_second_call_raises_keyerror(self):
        sid = "55" * 16
        kh = MagicMock()
        kh.search_key.return_value = None
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "_keyring_key_id": "kid", "consumed": False}
        store.revoke_offer(sid)
        with self.assertRaises(KeyError):
            store.revoke_offer(sid)

    def test_status_omits_revoked_offer(self):
        sid = "66" * 16
        kh = MagicMock()
        kh.search_key.return_value = None
        kh.list_keys.return_value = []
        priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
        epk_hex = pub_i.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ).hex()
        offer = self._minimal_offer(sid, epk_hex)
        store = EphemeralKeyStore(keyring_helper=kh, time_fn=lambda: 2_000_000_000.0)
        store._offers[sid] = {**offer, "_keyring_key_id": "kid", "consumed": False}
        self.assertEqual(len(store.status()), 1)
        store.revoke_offer(sid)
        self.assertEqual(store.status(), [])


def test_revoke_writes_audit_manual_revoke(tmp_path):
    sid = "77" * 16
    log = tmp_path / "ephemeral_key_audit.log"
    kh = MagicMock()
    kh.search_key.return_value = None
    priv_i, pub_i = CryptoHelpers.generate_brainpool_keypair("brainpoolP256r1")
    epk_hex = pub_i.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex()
    offer = {
        "schema_version": OFFER_SCHEMA_VERSION,
        "epk_hex": epk_hex,
        "long_term_fingerprint": "aa" * 20,
        "signature_hex": "ab",
        "expires_at": 9_000_000_000,
        "created_at": 1_000_000_000,
        "session_id": sid,
        "consumed": False,
    }
    store = EphemeralKeyStore(
        keyring_helper=kh,
        audit_log_path=log,
        time_fn=lambda: 2_000_000_000.0,
    )
    store._offers[sid] = {**offer, "_keyring_key_id": "kid", "consumed": False}
    store.revoke_offer(sid)
    line = log.read_text(encoding="utf-8").strip().splitlines()[-1]
    rec = json.loads(line)
    assert rec["event"] == "reject"
    assert rec["reason"] == "manual_revoke"
    assert rec["session_id"] == sid
    assert rec["ts"] == 2_000_000_000


def test_cmd_expire_returns_zero():
    import argparse

    mod = _load_epk_generate_script()
    with patch("gr_linux_crypto.ephemeral_key_store.EphemeralKeyStore") as M:
        M.return_value.revoke_offer = MagicMock()
        rc = mod.cmd_expire(argparse.Namespace(session_id="aa" * 16))
    assert rc == 0


def test_cmd_expire_returns_one_on_keyerror():
    import argparse

    mod = _load_epk_generate_script()
    with patch("gr_linux_crypto.ephemeral_key_store.EphemeralKeyStore") as M:
        M.return_value.revoke_offer.side_effect = KeyError("no offer")
        rc = mod.cmd_expire(argparse.Namespace(session_id="bb" * 16))
    assert rc == 1


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="epk_generate expire subprocess test targets POSIX shell layout",
)
def test_epk_expire_cli_unknown_session_subprocess():
    env = dict(os.environ)
    env["GR_LINUX_CRYPTO_DIR"] = str(REPO_ROOT)
    r = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "epk_generate.py"),
            "expire",
            "00" * 16,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 1
    assert r.stdout.strip() == ""
    err = (r.stderr or "").lower()
    assert "session_id" in err or "no offer" in err or "keyerror" in err


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
