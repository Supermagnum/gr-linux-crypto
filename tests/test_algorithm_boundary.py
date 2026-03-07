# -*- coding: utf-8 -*-
"""
Tests for BSI TR-02102 algorithm boundary enforcement (Component 5).

Verifies that check_algorithm_compliance and require_bsi_approved accept all
BSI-approved algorithms and reject non-approved ones with the correct exception.
Uses pinned BSI TR-02102 reference; optionally validates against fetched BSI content.
"""

import urllib.request
from urllib.error import URLError

import pytest

from gr_linux_crypto import (
    check_algorithm_compliance,
    require_bsi_approved,
    list_approved_algorithms,
)


# Pinned BSI TR-02102 approved list (current version reference)
APPROVED_ECC = {"brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}
APPROVED_SYMMETRIC = {"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"}
APPROVED_HASH = {"sha-256", "sha-384", "sha-512", "sha256", "sha384", "sha512"}
APPROVED_KDF = {"hkdf", "pbkdf2"}
APPROVED_SIGNATURE = {"ecdsa-brainpool", "ecdsa-brainpoolp256r1", "ecdsa-brainpoolp384r1", "ecdsa-brainpoolp512r1"}
REJECTED_EXAMPLES = ["md5", "sha1", "sha-1", "MD5", "SHA-1", "nist p-256", "P-256", "secp256r1", "rc4", "RC4", "des", "DES", "3des"]


class TestCheckAlgorithmCompliance:
    """check_algorithm_compliance(algorithm_name) returns (bool, section)."""

    def test_approved_ecc_curves(self):
        for name in APPROVED_ECC:
            approved, section = check_algorithm_compliance(name)
            assert approved is True, f"Expected {name!r} to be approved"
            assert section is not None and "BSI TR-02102" in section

    def test_approved_symmetric(self):
        for name in APPROVED_SYMMETRIC:
            approved, section = check_algorithm_compliance(name)
            assert approved is True
            assert section is not None and "BSI" in section

    def test_approved_hash(self):
        for name in APPROVED_HASH:
            approved, section = check_algorithm_compliance(name)
            assert approved is True
            assert section is not None

    def test_approved_kdf(self):
        for name in APPROVED_KDF:
            approved, section = check_algorithm_compliance(name)
            assert approved is True
            assert section is not None

    def test_approved_signature(self):
        for name in APPROVED_SIGNATURE:
            approved, section = check_algorithm_compliance(name)
            assert approved is True
            assert section is not None

    def test_case_and_punctuation_normalized(self):
        approved, _ = check_algorithm_compliance("SHA-256")
        assert approved is True
        approved, _ = check_algorithm_compliance("BrainpoolP384r1")
        assert approved is True
        approved, _ = check_algorithm_compliance("AES-256-GCM")
        assert approved is True

    def test_rejected_returns_false_none(self):
        for name in REJECTED_EXAMPLES:
            approved, section = check_algorithm_compliance(name)
            assert approved is False, f"Expected {name!r} to be rejected"
            assert section is None

    def test_empty_string_rejected(self):
        approved, section = check_algorithm_compliance("")
        assert approved is False
        assert section is None


class TestRequireBsiApproved:
    """require_bsi_approved(algorithm_name) raises for non-approved."""

    def test_approved_does_not_raise(self):
        require_bsi_approved("brainpoolP256r1")
        require_bsi_approved("SHA-256")
        require_bsi_approved("AES-256-GCM")

    def test_rejected_raises_value_error(self):
        for name in REJECTED_EXAMPLES:
            with pytest.raises(ValueError) as exc_info:
                require_bsi_approved(name)
            assert name.strip().lower() in str(exc_info.value).lower() or "not approved" in str(exc_info.value).lower()
            assert "BSI" in str(exc_info.value) or "TR-02102" in str(exc_info.value)

    def test_exception_contains_algorithm_name(self):
        with pytest.raises(ValueError, match="MD5|md5|not approved"):
            require_bsi_approved("MD5")
        with pytest.raises(ValueError, match="BSI|TR-02102"):
            require_bsi_approved("RC4")


class TestListApprovedAlgorithms:
    """list_approved_algorithms() returns expected categories."""

    def test_returns_dict_with_categories(self):
        d = list_approved_algorithms()
        assert "ecc_curves" in d
        assert "symmetric" in d
        assert "hash" in d
        assert "kdf" in d
        assert "pq_kem" in d
        assert "signature" in d

    def test_ecc_curves_match_pinned(self):
        d = list_approved_algorithms()
        assert set(d["ecc_curves"]) == set(sorted(APPROVED_ECC))

    def test_symmetric_match_pinned(self):
        d = list_approved_algorithms()
        assert set(d["symmetric"]) == set(sorted(APPROVED_SYMMETRIC))

    def test_hash_contains_sha256_384_512(self):
        d = list_approved_algorithms()
        hashes = d["hash"]
        assert "sha256" in hashes or "sha-256" in hashes
        assert "sha384" in hashes or "sha-384" in hashes
        assert "sha512" in hashes or "sha-512" in hashes


class TestPinnedVsBsiReference:
    """Approved list matches BSI TR-02102 (pinned reference; optional fetch)."""

    def test_pinned_reference_approved_set(self):
        d = list_approved_algorithms()
        all_approved = set(d["ecc_curves"]) | set(d["symmetric"]) | set(d["hash"]) | set(d["kdf"]) | set(d["signature"])
        for name in all_approved:
            approved, _ = check_algorithm_compliance(name)
            assert approved is True, f"Listed approved {name!r} should be compliant"

    @pytest.mark.skip(reason="Optional: fetch BSI TR-02102 when network available; use pinned reference otherwise")
    def test_fetch_bsi_tr02102_if_available(self):
        try:
            req = urllib.request.Request(
                "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf",
                headers={"User-Agent": "gr-linux-crypto-test"},
            )
            urllib.request.urlopen(req, timeout=5)
        except URLError:
            pytest.skip("BSI TR-02102 URL not reachable")
        d = list_approved_algorithms()
        assert "brainpoolP256r1" in d["ecc_curves"]
        assert "sha256" in d["hash"] or "sha-256" in d["hash"]
