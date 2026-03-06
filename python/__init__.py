# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Module

This module provides GNU Radio blocks for Linux kernel crypto infrastructure
integration, hardware security modules, and cryptographic operations.
"""

from .crypto_helpers import CryptoHelpers, GNURadioCryptoUtils
from .keyring_helper import KeyringHelper
from .callsign_key_store import CallsignKeyStore
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

try:
    from .gdss_set_key_source import gdss_set_key_source_block
except ImportError:
    gdss_set_key_source_block = None

__version__ = "1.0.0"
__all__ = [
    "KeyringHelper",
    "CryptoHelpers",
    "GNURadioCryptoUtils",
    "CallsignKeyStore",
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
    "gdss_set_key_source_block",
]
