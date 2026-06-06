# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Module

This module provides GNU Radio blocks for Linux kernel crypto infrastructure
integration, hardware security modules, and cryptographic operations.
"""

from .crypto_helpers import CryptoHelpers, GNURadioCryptoUtils, secure_zero
from .keyring_helper import KeyringHelper
from .callsign_key_store import CallsignKeyStore
from .callsign_verifier import CallsignVerifier
from .multi_recipient_ecies import MultiRecipientECIES
from .hpke_brainpool import HPKEBrainpool
from .shamir_secret_sharing import (
    split,
    reconstruct,
    create_shamir_backed_key,
    reconstruct_session_key,
    BRAINPOOL_P256R1_ORDER,
    BRAINPOOL_P384R1_ORDER,
    BRAINPOOL_P512R1_ORDER,
    get_curve_prime,
    get_max_secret_bytes,
    get_share_value_bytes,
    SUPPORTED_CURVES,
)
from .nitrokey_bridge import decrypt_with_card, get_keygrip_from_key_id
from .fips_status import fips_status
from .bsi_algorithm_boundary import (
    check_algorithm_compliance,
    require_bsi_approved,
    list_approved_algorithms,
)

try:
    from .gdss_set_key_source import gdss_set_key_source_block
except ImportError:
    gdss_set_key_source_block = None

try:
    from .galdralag_session_kdf import (
        derive_galdralag_cess_k_outer_mode_a,
        derive_galdralag_gdss_masking_key,
        derive_galdralag_session_keys,
        hkdf_blake3_cess,
        validate_offer_consumed,
        validate_offer_expiry,
    )
except ImportError:
    derive_galdralag_session_keys = None
    derive_galdralag_gdss_masking_key = None
    derive_galdralag_cess_k_outer_mode_a = None
    hkdf_blake3_cess = None
    validate_offer_expiry = None
    validate_offer_consumed = None

try:
    from .ephemeral_key_store import EphemeralKeyStore
except ImportError:
    EphemeralKeyStore = None

__version__ = "1.0.0"
__all__ = [
    "KeyringHelper",
    "CryptoHelpers",
    "GNURadioCryptoUtils",
    "CallsignKeyStore",
    "CallsignVerifier",
    "MultiRecipientECIES",
    "HPKEBrainpool",
    "split",
    "reconstruct",
    "create_shamir_backed_key",
    "reconstruct_session_key",
    "BRAINPOOL_P256R1_ORDER",
    "BRAINPOOL_P384R1_ORDER",
    "BRAINPOOL_P512R1_ORDER",
    "get_curve_prime",
    "get_max_secret_bytes",
    "get_share_value_bytes",
    "SUPPORTED_CURVES",
    "decrypt_with_card",
    "get_keygrip_from_key_id",
    "fips_status",
    "gdss_set_key_source_block",
    "derive_galdralag_session_keys",
    "derive_galdralag_gdss_masking_key",
    "derive_galdralag_cess_k_outer_mode_a",
    "hkdf_blake3_cess",
    "validate_offer_expiry",
    "validate_offer_consumed",
    "EphemeralKeyStore",
    "secure_zero",
    "check_algorithm_compliance",
    "require_bsi_approved",
    "list_approved_algorithms",
]
