# -*- coding: utf-8 -*-
"""Tests for Galdralag-compatible session KDF and GDSS set_key source."""

import hashlib
import hmac
import unittest

try:
    from gnuradio.gr import pmt as gr_pmt
except ImportError:
    gr_pmt = None

from gr_linux_crypto.crypto_helpers import CryptoHelpers
from gr_linux_crypto.galdralag_session_kdf import (
    derive_galdralag_gdss_masking_key,
    derive_galdralag_session_keys,
    hkdf_extract_sha256,
    ordered_epk_salt,
)
from gr_linux_crypto.gdss_set_key_source import (
    _derive_gdss_key,
    gdss_set_key_source_block,
)


class TestGaldralagOrderedSalt(unittest.TestCase):
    def test_ordered_salt_min_max(self):
        a = b"\x01\x02"
        b = b"\x02\x01"
        self.assertEqual(ordered_epk_salt(a, b), a + b)
        self.assertEqual(ordered_epk_salt(b, a), a + b)

    def test_swap_epk_same_session_keys(self):
        ikm = bytes(range(32))
        epk_a = b"\x04" + b"\x03" * 64
        epk_b = b"\x04" + b"\xcc" * 64
        k1 = derive_galdralag_session_keys(ikm, epk_a, epk_b)
        k2 = derive_galdralag_session_keys(ikm, epk_b, epk_a)
        self.assertEqual(k1["gdss_mask_key"], k2["gdss_mask_key"])
        self.assertEqual(k1["payload_key_i2r"], k2["payload_key_i2r"])

    def test_epk_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            derive_galdralag_session_keys(b"\x00" * 32, b"\x00" * 10, b"\x00" * 11)

    def test_galdralag_keys_distinct(self):
        ikm = bytes(range(32))
        epk_i = b"\x04" + bytes(range(64))
        epk_r = b"\x04" + bytes(range(64, 128))
        k = derive_galdralag_session_keys(ikm, epk_i, epk_r)
        seen = set()
        for name, val in k.items():
            self.assertEqual(len(val), 32, name)
            seen.add(val)
        self.assertEqual(len(seen), 6)

    def test_galdralag_gdss_mask_differs_from_gr_k_gdss(self):
        ikm = bytes(range(32))
        epk_i = b"\x04" + b"\xaa" * 64
        epk_r = b"\x04" + b"\x55" * 64
        gal = derive_galdralag_gdss_masking_key(ikm, epk_i, epk_r)
        grk = _derive_gdss_key(ikm)
        self.assertNotEqual(gal, grk)

    def test_hkdf_extract_empty_salt_uses_zero_key(self):
        ikm = b"test-ikm-bytes"
        prk = hkdf_extract_sha256(b"", ikm)
        key = bytes(32)
        expect = hmac.new(key, ikm, hashlib.sha256).digest()
        self.assertEqual(prk, expect)


def _pmt_u8vector_to_bytes(msg, key_sym: str) -> bytes:
    assert gr_pmt is not None
    v = gr_pmt.dict_ref(msg, gr_pmt.intern(key_sym), gr_pmt.PMT_NIL)
    return bytes(gr_pmt.u8vector_elements(v))


@unittest.skipUnless(gr_pmt is not None, "GNU Radio not installed")
class TestGdssSetKeySourceBlock(unittest.TestCase):
    def test_default_gr_k_gdss_unchanged(self):
        sec = "00" * 32
        tb = gdss_set_key_source_block(
            shared_secret_hex=sec,
            session_id=1,
            tx_seq=0,
            key_derivation="gr_k_gdss",
        )
        self.assertIsNotNone(tb._msg)

    def test_galdralag_requires_epks(self):
        sec = "00" * 32
        tb = gdss_set_key_source_block(
            shared_secret_hex=sec,
            key_derivation="galdralag",
            epk_initiator_hex="",
            epk_responder_hex="",
        )
        self.assertIsNone(tb._msg)

    def test_galdralag_builds_message(self):
        sec = "00" * 32
        epk_a = "04" + "11" * 64
        epk_b = "04" + "22" * 64
        tb = gdss_set_key_source_block(
            shared_secret_hex=sec,
            session_id=2,
            tx_seq=3,
            key_derivation="galdralag",
            epk_initiator_hex=epk_a,
            epk_responder_hex=epk_b,
        )
        self.assertIsNotNone(tb._msg)
        key = _pmt_u8vector_to_bytes(tb._msg, "key")
        nonce = _pmt_u8vector_to_bytes(tb._msg, "nonce")
        self.assertEqual(len(key), 32)
        self.assertEqual(len(nonce), 12)

    def test_gr_k_gdss_matches_crypto_helpers_path(self):
        sec_hex = "ab" * 32
        tb = gdss_set_key_source_block(
            shared_secret_hex=sec_hex,
            key_derivation="gr_k_gdss",
        )
        self.assertIsNotNone(tb._msg)
        expected = CryptoHelpers.derive_key_hkdf(
            bytes.fromhex(sec_hex),
            salt=bytes(32),
            info=b"gdss-chacha20-masking-v1",
            length=32,
        )
        got = _pmt_u8vector_to_bytes(tb._msg, "key")
        self.assertEqual(got, expected)


if __name__ == "__main__":
    unittest.main()
