# -*- coding: utf-8 -*-
"""
Session key derivation matching Galdralag ephemeral-session (Rust).

Implements the same HKDF-SHA256 pipeline as
Galdralag-firmware/crates/ephemeral-session/src/keys.rs::derive_session_keys:
salt = lexicographic min(epk_initiator, epk_responder) || max(...),
PRK = HKDF-Extract(salt, IKM), then HKDF-Expand per domain label.

Info strings match Galdralag crates/ephemeral-session/src/hkdf_labels.rs.
Changing labels or salt rules breaks interoperability with Galdralag tokens.

**Galdralag-firmware ``SessionKeys`` (current tree):** besides the six expanded
session keys, the token keeps the raw classical ECDH IKM (``x`` coordinate) for
built-in CESS cipher-profile cascades (HKDF-BLAKE3 in ``cipher-profile``) and
``profile_prk`` (HKDF-Extract output above) for **custom** profiles only. Host
code that calls ``derive_galdralag_session_keys`` already has the ECDH IKM; use
the same bytes where Galdra docs refer to ``cess_inner_cascade_ikm``. CESS
Mode A **K_outer** matches ``cess::derive_k_outer``; see
``derive_galdralag_cess_k_outer_mode_a`` (optional ``blake3`` PyPI package).

**gr-openssl / gr-nacl:** Galdralag ephemeral ECDH uses **Brainpool** curves
only (see ``ephemeral-session`` / ``SessionCurve``). Do not substitute an X25519
shared secret from gr-nacl for ``derive_galdralag_session_keys``. Derived
32-byte keys are opaque symmetric material; you may feed them into other GNU
Radio crypto blocks as appropriate for your protocol (gr-openssl for AES and
similar; gr-nacl remains the right module for Curve25519 / Ed25519 / NaCl-style
APIs on different key agreement paths).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

# Must match Galdralag hkdf_labels.rs domain::* (byte-for-byte).
GALDRALAG_PAYLOAD_KEY_I2R = b"galdralag/session/payload-i2r/v1"
GALDRALAG_PAYLOAD_KEY_R2I = b"galdralag/session/payload-r2i/v1"
GALDRALAG_GDSS_MASK_KEY = b"galdralag/session/gdss-mask/v1"
GALDRALAG_GDSS_SYNC_KEY = b"galdralag/session/gdss-sync/v1"
GALDRALAG_GDSS_TIMING_KEY = b"galdralag/session/gdss-timing/v1"
GALDRALAG_MAC_KEY = b"galdralag/session/mac/v1"


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract (RFC 5869) with SHA-256.
    Matches Galdralag keys.rs: empty salt uses a 32-byte zero HMAC key.
    """
    if not salt:
        key = bytes(32)
        return hmac.new(key, ikm, hashlib.sha256).digest()
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def ordered_epk_salt(epk_initiator: bytes, epk_responder: bytes) -> bytes:
    """Salt = min(epk_i, epk_r) || max(epk_i, epk_r) (lexicographic byte order)."""
    if epk_initiator <= epk_responder:
        return epk_initiator + epk_responder
    return epk_responder + epk_initiator


def _hkdf_expand_sha256(prk: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return hkdf.derive(prk)


def derive_galdralag_session_keys(
    ecdh_shared_secret: bytes,
    epk_initiator: bytes,
    epk_responder: bytes,
) -> Dict[str, bytes]:
    """
    Derive all Galdralag session subkeys (32 bytes each) plus the HKDF-Extract PRK.

    Parameter order matches Galdralag-firmware ``protocol.rs`` (initiator and responder
    both call ``derive_session_keys`` with ``InitMessage`` EPK first, then response EPK).
    Salt is ``min(epk_i, epk_r) || max(...)`` by lexicographic byte order; initiator and
    responder EPKs need not be the same length (same rule as Rust ``ordered_epk_salt``).

    Args:
        ecdh_shared_secret: Raw ECDH output (e.g. 32 / 48 / 64 bytes for Brainpool P256/P384/P512).
        epk_initiator: Initiator ephemeral public key (uncompressed SEC1 from the handshake).
        epk_responder: Responder ephemeral public key (uncompressed SEC1).

    Returns:
        Dict with keys: ``profile_prk`` (32 bytes, same as ``SessionKeys::profile_prk`` in
        Rust), ``payload_key_i2r``, ``payload_key_r2i``, ``gdss_mask_key``,
        ``gdss_sync_key``, ``gdss_timing_key``, ``mac_key``.
    """
    salt = ordered_epk_salt(epk_initiator, epk_responder)
    prk = hkdf_extract_sha256(salt, ecdh_shared_secret)
    return {
        "profile_prk": prk,
        "payload_key_i2r": _hkdf_expand_sha256(prk, GALDRALAG_PAYLOAD_KEY_I2R),
        "payload_key_r2i": _hkdf_expand_sha256(prk, GALDRALAG_PAYLOAD_KEY_R2I),
        "gdss_mask_key": _hkdf_expand_sha256(prk, GALDRALAG_GDSS_MASK_KEY),
        "gdss_sync_key": _hkdf_expand_sha256(prk, GALDRALAG_GDSS_SYNC_KEY),
        "gdss_timing_key": _hkdf_expand_sha256(prk, GALDRALAG_GDSS_TIMING_KEY),
        "mac_key": _hkdf_expand_sha256(prk, GALDRALAG_MAC_KEY),
    }


def derive_galdralag_gdss_masking_key(
    ecdh_shared_secret: bytes,
    epk_initiator: bytes,
    epk_responder: bytes,
) -> bytes:
    """32-byte GDSS ChaCha20 masking key for gr-k-gdss spreader/despreader."""
    keys = derive_galdralag_session_keys(
        ecdh_shared_secret, epk_initiator, epk_responder
    )
    return keys["gdss_mask_key"]


# --- CESS Mode A K_outer (Galdralag-firmware crates/cess, HKDF-BLAKE3) ---

CESS_OUTER_ENVELOPE_INFO = b"cess-outer-envelope-v1"
_HMAC_BLOCK = 64


def _import_blake3():
    try:
        import blake3 as _blake3  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised when blake3 missing
        raise ImportError(
            "derive_galdralag_cess_k_outer_mode_a and HKDF-BLAKE3 helpers require "
            "the optional PyPI package 'blake3'. Install with: pip install blake3"
        ) from exc
    return _blake3


def _normalize_hmac_key_blake3(key: bytes, blake3_mod) -> bytes:
    out = bytearray(_HMAC_BLOCK)
    if len(key) > _HMAC_BLOCK:
        h = blake3_mod.blake3(key).digest(length=32)
        out[:32] = h
    else:
        out[: len(key)] = key
    return bytes(out)


def _hmac_blake3(key: bytes, data: bytes, blake3_mod) -> bytes:
    k = _normalize_hmac_key_blake3(key, blake3_mod)
    ipad = bytes((b ^ 0x36) for b in k)
    opad = bytes((b ^ 0x5C) for b in k)
    inner = blake3_mod.blake3(ipad + data).digest(length=32)
    return blake3_mod.blake3(opad + inner).digest(length=32)


def hkdf_blake3_cess(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-BLAKE3 per Galdralag-firmware ``cess::hkdf_blake3`` (RFC 5869 structure).

    Empty ``salt`` uses 32 zero octets for Extract (CESS §6.2), matching Rust.
    Verified against ``cess`` unit test vectors (e.g. ``cess-kem-v1``).
    """
    blake3_mod = _import_blake3()
    if not salt:
        salt = bytes(32)
    prk = _hmac_blake3(salt, ikm, blake3_mod)
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = _hmac_blake3(prk, t + info + bytes([counter & 0xFF]), blake3_mod)
        okm.extend(t)
        counter = (counter + 1) & 0xFF
    return bytes(okm[:length])


def derive_galdralag_cess_k_outer_mode_a(classical_ecdh_ikm: bytes) -> bytes:
    """
    Derive CESS Mode A **K_outer** from the classical Brainpool ECDH shared secret.

    Matches Galdralag-firmware ``cess::derive_k_outer`` (HKDF-BLAKE3, empty salt,
    info ``cess-outer-envelope-v1`` UTF-8 bytes). Normative Mode A expects
    BrainpoolP384r1 handshake IKM length (see ``ephemeral-session`` crate docs).

    Requires PyPI package ``blake3`` (same BLAKE3 as the Rust ``blake3`` crate).
    """
    out = hkdf_blake3_cess(classical_ecdh_ikm, b"", CESS_OUTER_ENVELOPE_INFO, 32)
    if len(out) != 32:
        raise RuntimeError("internal: HKDF-BLAKE3 length")
    return out
