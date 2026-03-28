# -*- coding: utf-8 -*-
"""
Session key derivation matching Galdralag ephemeral-session (Rust).

Implements the same HKDF-SHA256 pipeline as
Galdralag-firmware/crates/ephemeral-session/src/keys.rs::derive_session_keys:
salt = lexicographic min(epk_initiator, epk_responder) || max(...),
PRK = HKDF-Extract(salt, IKM), then HKDF-Expand per domain label.

Info strings match Galdralag crates/ephemeral-session/src/hkdf_labels.rs.
Changing labels or salt rules breaks interoperability with Galdralag tokens.
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
