# -*- coding: utf-8 -*-
"""
BSI TR-02102 algorithm boundary enforcement for EUCC/BSZ evaluation.

Provides check_algorithm_compliance(algorithm_name) and require_bsi_approved()
so that only BSI TR-02102 approved algorithms can be used when strict mode
is required. Approved list matches BSI TR-02102 current version.
"""

from typing import Optional, Tuple

# BSI TR-02102-1 approved algorithms (pinned reference; see document for updates)
# https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr-02102.html

_BSI_ECC_CURVES = frozenset({
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
})
_BSI_ECC_SECTION = "BSI TR-02102-1 Section 2.3 (Elliptic curve cryptography)"

_BSI_SYMMETRIC = frozenset({
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
})
_BSI_SYMMETRIC_SECTION = "BSI TR-02102-1 Section 3 (Symmetric encryption)"

_BSI_HASH = frozenset({
    "sha-256",
    "sha-384",
    "sha-512",
    "sha256",
    "sha384",
    "sha512",
})
_BSI_HASH_SECTION = "BSI TR-02102-1 Section 2.1 (Hash functions)"

_BSI_KDF = frozenset({
    "hkdf",
    "pbkdf2",
})
_BSI_KDF_SECTION = "BSI TR-02102-1 Section 2.2 (Key derivation)"

_BSI_PQ_KEM = frozenset({
    "frodokem-640",
    "frodokem-976",
    "frodokem-1344",
    "ml-kem-768",
    "ml-kem-1024",
})
_BSI_PQ_KEM_SECTION = "BSI TR-02102-1 (Post-quantum key encapsulation)"

_BSI_SIGNATURE = frozenset({
    "ecdsa-brainpool",
    "ecdsa-brainpoolp256r1",
    "ecdsa-brainpoolp384r1",
    "ecdsa-brainpoolp512r1",
})
_BSI_SIGNATURE_SECTION = "BSI TR-02102-1 Section 2.3 (ECDSA over Brainpool only)"

# Normalized form for lookup: lowercase, minimal punctuation
def _normalize(name: str) -> str:
    return name.strip().lower().replace(" ", "").replace("-", "").replace("_", "")

# Map normalized names to (canonical_approved_name, section)
_APPROVED_MAP = {}
for _n in _BSI_ECC_CURVES:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_ECC_SECTION)
for _n in _BSI_SYMMETRIC:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_SYMMETRIC_SECTION)
for _n in _BSI_HASH:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_HASH_SECTION)
for _n in _BSI_KDF:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_KDF_SECTION)
for _n in _BSI_PQ_KEM:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_PQ_KEM_SECTION)
for _n in _BSI_SIGNATURE:
    _APPROVED_MAP[_normalize(_n)] = (_n, _BSI_SIGNATURE_SECTION)

# Well-known rejected algorithms (for clear error messages)
_REJECTED_REF = "BSI TR-02102-1 does not approve this algorithm for new applications."


def check_algorithm_compliance(algorithm_name: str) -> Tuple[bool, Optional[str]]:
    """
    Return whether an algorithm is BSI TR-02102 approved and cite the relevant section.

    Args:
        algorithm_name: Algorithm identifier (e.g. "SHA-256", "brainpoolP384r1",
            "AES-256-GCM", "ChaCha20-Poly1305", "HKDF", "PBKDF2", "ECDSA-Brainpool").
            Case and punctuation are normalized for matching.

    Returns:
        Tuple (approved, section_reference). approved is True if the algorithm
        is in the BSI TR-02102 approved list. section_reference is the BSI
        guideline section string (e.g. "BSI TR-02102-1 Section 2.3 ...") when
        approved, or None when not approved.
    """
    if not algorithm_name or not isinstance(algorithm_name, str):
        return False, None
    key = _normalize(algorithm_name)
    if key in _APPROVED_MAP:
        _, section = _APPROVED_MAP[key]
        return True, section
    return False, None


def require_bsi_approved(algorithm_name: str) -> None:
    """
    Raise if the algorithm is not BSI TR-02102 approved.

    Use this before performing a cryptographic operation when strict BSI
    boundary enforcement is required (e.g. EUCC/BSZ evaluation).

    Args:
        algorithm_name: Algorithm identifier to check.

    Raises:
        ValueError: If the algorithm is not in the BSI TR-02102 approved list.
            The message includes the algorithm name and a reference to the
            BSI guideline.
    """
    approved, section = check_algorithm_compliance(algorithm_name)
    if not approved:
        raise ValueError(
            f"Algorithm not approved for use: '{algorithm_name}'. "
            f"{_REJECTED_REF} See BSI TR-02102 (https://www.bsi.bund.de/tr02102)."
        )


def list_approved_algorithms() -> dict:
    """
    Return the current BSI TR-02102 approved algorithm sets by category.

    Useful for documentation and tests. PQ KEM entries are included
    (relevant when Component 2 / GR_LINUX_CRYPTO_PQ_KEM is enabled).
    """
    return {
        "ecc_curves": sorted(_BSI_ECC_CURVES),
        "symmetric": sorted(_BSI_SYMMETRIC),
        "hash": sorted(_BSI_HASH),
        "kdf": sorted(_BSI_KDF),
        "pq_kem": sorted(_BSI_PQ_KEM),
        "signature": sorted(_BSI_SIGNATURE),
    }
