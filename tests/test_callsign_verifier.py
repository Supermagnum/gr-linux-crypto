# -*- coding: utf-8 -*-
"""Tests for callsign verification and QR payload helpers."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from callsign_verifier import CallsignVerifier, gpg_lookup_fingerprint  # noqa: E402
from gpg_qr_gen import _build_payload  # noqa: E402


class TestBuildPayload(unittest.TestCase):
    def test_openpgp4fpr_uri(self):
        fpr = "a" * 40
        self.assertEqual(
            _build_payload("openpgp4fpr", fpr, "W1ABC", None),
            f"openpgp4fpr:{fpr}",
        )

    def test_keyserver_url(self):
        fpr = "b" * 40
        self.assertEqual(
            _build_payload("keyserver", fpr, "W1ABC", None),
            f"https://keys.openpgp.org/search?q=0x{fpr}",
        )

    def test_callsign_url_from_callsign(self):
        fpr = "c" * 40
        self.assertEqual(
            _build_payload("callsign", fpr, "w1abc", None),
            "https://keys.openpgp.org/search?q=W1ABC",
        )

    def test_callsign_url_from_email_uses_hint(self):
        fpr = "d" * 40
        self.assertEqual(
            _build_payload("callsign", fpr, "ops@example.com", "K2XYZ"),
            "https://keys.openpgp.org/search?q=K2XYZ",
        )


class TestGpgLookupFingerprint(unittest.TestCase):
    @mock.patch("callsign_verifier.subprocess.run")
    def test_parses_fpr_line(self, run_mock):
        run_mock.return_value = mock.Mock(
            returncode=0,
            stdout="pub:u:...\nfpr:::::::::abc123:\n",
            stderr="",
        )
        self.assertEqual(
            gpg_lookup_fingerprint("gpg", "W1ABC"),
            "abc123",
        )


class TestCallsignVerifier(unittest.TestCase):
    @mock.patch.object(CallsignVerifier, "lookup_fingerprint", return_value="aa" * 20)
    @mock.patch("callsign_verifier.subprocess.run")
    def test_verify_signed_log_entry_valid(self, run_mock, _lookup):
        run_mock.return_value = mock.Mock(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {'aa' * 20} 1234567890 foo\n",
            stderr="",
        )
        verifier = CallsignVerifier(key_store=mock.Mock(has_callsign=mock.Mock(return_value=False)))
        ok = verifier.verify_signed_log_entry(b"qso data", b"sig bytes", "W1ABC")
        self.assertTrue(ok)
        run_mock.assert_called_once()
        args = run_mock.call_args[0][0]
        self.assertIn("--verify", args)

    @mock.patch.object(CallsignVerifier, "lookup_fingerprint", return_value="bb" * 20)
    @mock.patch("callsign_verifier.subprocess.run")
    def test_verify_signed_log_entry_wrong_signer(self, run_mock, _lookup):
        run_mock.return_value = mock.Mock(
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {'cc' * 20} 1234567890 foo\n",
            stderr="",
        )
        verifier = CallsignVerifier()
        self.assertFalse(
            verifier.verify_signed_log_entry(b"qso data", b"sig bytes", "W1ABC")
        )

    @mock.patch.object(
        CallsignVerifier, "lookup_fingerprint", side_effect=ValueError("missing")
    )
    def test_verify_unknown_callsign(self, _lookup):
        verifier = CallsignVerifier()
        self.assertFalse(
            verifier.verify_signed_log_entry(b"x", b"y", "NOBODY")
        )


if __name__ == "__main__":
    unittest.main()
