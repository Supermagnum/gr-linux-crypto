# -*- coding: utf-8 -*-
"""Tests for Galdralag-compatible session KDF and GDSS set_key source."""

import hashlib
import hmac
import json
import unittest
from pathlib import Path

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

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "galdralag_session_kdf_vectors.json"


try:
    import blake3 as _blake3_check  # noqa: F401

    _HAVE_BLAKE3 = True
except ImportError:
    _HAVE_BLAKE3 = False

if _HAVE_BLAKE3:
    from gr_linux_crypto.galdralag_session_kdf import (
        derive_galdralag_cess_k_outer_mode_a,
        hkdf_blake3_cess,
    )

try:
    from gnuradio import gr as _gr_check  # noqa: F401

    from gr_linux_crypto.gdss_set_key_source import gdss_set_key_source_block

    _HAVE_GDSS_BLOCK = True
except ImportError:
    _HAVE_GDSS_BLOCK = False
    gdss_set_key_source_block = None  # type: ignore[misc,assignment]


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

    def test_epk_different_lengths_allowed(self):
        """Rust ordered_epk_salt compares slices; lengths need not match."""
        ikm = b"\xab" * 32
        short = b"\x01\x02"
        long_epk = b"\x04" + b"\x03" * 64
        k = derive_galdralag_session_keys(ikm, short, long_epk)
        salt = ordered_epk_salt(short, long_epk)
        self.assertEqual(k["profile_prk"], hkdf_extract_sha256(salt, ikm))

    def test_profile_prk_is_extract_output(self):
        ikm = bytes(range(32))
        epk_i = b"\x04" + b"\xaa" * 64
        epk_r = b"\x04" + b"\x55" * 64
        salt = ordered_epk_salt(epk_i, epk_r)
        k = derive_galdralag_session_keys(ikm, epk_i, epk_r)
        self.assertEqual(k["profile_prk"], hkdf_extract_sha256(salt, ikm))

    def test_galdralag_keys_distinct(self):
        ikm = bytes(range(32))
        epk_i = b"\x04" + bytes(range(64))
        epk_r = b"\x04" + bytes(range(64, 128))
        k = derive_galdralag_session_keys(ikm, epk_i, epk_r)
        seen = set()
        for name, val in k.items():
            self.assertEqual(len(val), 32, name)
            seen.add(val)
        self.assertEqual(len(seen), 7)

    def test_galdralag_gdss_mask_differs_from_gr_k_gdss(self):
        ikm = bytes(range(32))
        epk_i = b"\x04" + b"\xaa" * 64
        epk_r = b"\x04" + b"\x55" * 64
        gal = derive_galdralag_gdss_masking_key(ikm, epk_i, epk_r)
        grk = CryptoHelpers.derive_key_hkdf(
            ikm,
            salt=bytes(32),
            info=b"gdss-chacha20-masking-v1",
            length=32,
        )
        self.assertNotEqual(gal, grk)

    def test_hkdf_extract_empty_salt_uses_zero_key(self):
        ikm = b"test-ikm-bytes"
        prk = hkdf_extract_sha256(b"", ikm)
        key = bytes(32)
        expect = hmac.new(key, ikm, hashlib.sha256).digest()
        self.assertEqual(prk, expect)


class TestGaldralagRustGoldenVectors(unittest.TestCase):
    """Cross-verify against Galdralag-firmware ephemeral-session export vectors."""

    @classmethod
    def setUpClass(cls):
        if not _FIXTURES.is_file():
            raise unittest.SkipTest(f"missing fixture {_FIXTURES}")
        with _FIXTURES.open(encoding="utf-8") as fh:
            cls._fixture = json.load(fh)

    def test_session_keys_match_rust_export(self):
        for vec in self._fixture["vectors"]:
            with self.subTest(description=vec["description"]):
                ikm = bytes.fromhex(vec["ecdh_ikm_hex"])
                epk_i = bytes.fromhex(vec["epk_initiator_hex"])
                epk_r = bytes.fromhex(vec["epk_responder_hex"])
                keys = derive_galdralag_session_keys(ikm, epk_i, epk_r)
                self.assertEqual(keys["profile_prk"].hex(), vec["profile_prk_hex"])
                self.assertEqual(keys["payload_key_i2r"].hex(), vec["payload_key_i2r_hex"])
                self.assertEqual(keys["payload_key_r2i"].hex(), vec["payload_key_r2i_hex"])
                self.assertEqual(keys["gdss_mask_key"].hex(), vec["gdss_mask_key_hex"])
                self.assertEqual(keys["gdss_sync_key"].hex(), vec["gdss_sync_key_hex"])
                self.assertEqual(keys["gdss_timing_key"].hex(), vec["gdss_timing_key_hex"])
                self.assertEqual(keys["mac_key"].hex(), vec["mac_key_hex"])

    def test_brainpool_ecdh_ikm_matches_rust(self):
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError:
            raise unittest.SkipTest("cryptography not installed")

        for vec in self._fixture["vectors"]:
            if vec.get("curve") != "brainpoolP256r1":
                continue
            scalar_a = vec.get("initiator_scalar_hex")
            scalar_b = vec.get("responder_scalar_hex")
            if not scalar_a or not scalar_b:
                raise unittest.SkipTest("fixture missing scalar hex for ECDH cross-check")
            with self.subTest(description=vec["description"]):
                sk_a = ec.derive_private_key(
                    int.from_bytes(bytes.fromhex(scalar_a), "big"),
                    ec.BrainpoolP256R1(),
                    default_backend(),
                )
                sk_b = ec.derive_private_key(
                    int.from_bytes(bytes.fromhex(scalar_b), "big"),
                    ec.BrainpoolP256R1(),
                    default_backend(),
                )
                shared = CryptoHelpers.brainpool_ecdh(sk_a, sk_b.public_key())
                self.assertEqual(shared.hex(), vec["ecdh_ikm_hex"])
                shared_ba = CryptoHelpers.brainpool_ecdh(sk_b, sk_a.public_key())
                self.assertEqual(shared_ba, shared)


@unittest.skipUnless(_HAVE_BLAKE3, "blake3 PyPI package not installed")
class TestGaldralagCessHkdfBlake3(unittest.TestCase):
    """Vectors from Galdralag-firmware crates/cess/src/hkdf_blake3.rs unit tests."""

    def test_hkdf_blake3_cess_kem_v1_vector(self):
        ikm = bytes.fromhex(
            "3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9"
        )
        okm = hkdf_blake3_cess(ikm, b"", b"cess-kem-v1", 32)
        self.assertEqual(
            okm.hex(),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c",
        )

    def test_hkdf_blake3_cess_pin_v1_vector(self):
        ikm = bytes.fromhex(
            "face1bf3a3261bb9ac71ce64c1f9719a70f208496b4acd98ad5955c45fdd6dfc"
        )
        okm = hkdf_blake3_cess(ikm, b"", b"cess-pin-v1", 32)
        self.assertEqual(
            okm.hex(),
            "cb3805b81c7be26fe8dcbbb8281b195984e8cd77d9f2f58fa7bd177e93dd4ca5",
        )

    def test_hkdf_blake3_cess_kem_v1_expand_64(self):
        ikm = bytes.fromhex(
            "3df646a590007b20e599678926543bad804f03c4cd15d8122813d97b08b657d9"
        )
        okm = hkdf_blake3_cess(ikm, b"", b"cess-kem-v1", 64)
        self.assertEqual(
            okm.hex(),
            "56c614e8527a62ffdf5dcd7e6f11514201a89016f125925019d81f81a9f5225c"
            "1dd33ac43d0e19a2f5d7e1fd2735c1d2a468be5ed0c63d4ce7a59f4230d1bf16",
        )

    def test_cess_k_outer_mode_a_zero_ikm_48(self):
        ikm = bytes(48)
        k = derive_galdralag_cess_k_outer_mode_a(ikm)
        self.assertEqual(
            k.hex(),
            "b30726d00add0e66d1de6c47b48fc4bd81a91605b2a727ef2b3f121594b79ed4",
        )


def _pmt_u8vector_to_bytes(msg, key_sym: str) -> bytes:
    assert gr_pmt is not None
    v = gr_pmt.dict_ref(msg, gr_pmt.intern(key_sym), gr_pmt.PMT_NIL)
    return bytes(gr_pmt.u8vector_elements(v))


@unittest.skipUnless(
    gr_pmt is not None and _HAVE_GDSS_BLOCK,
    "GNU Radio or gdss_set_key_source not available",
)
class TestGdssSetKeySourceBlock(unittest.TestCase):
    def test_default_gr_k_gdss_unchanged(self):
        sec = "00" * 32
        assert gdss_set_key_source_block is not None
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
