# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Module

This module provides GNU Radio blocks for Linux kernel crypto infrastructure
integration, hardware security modules, and cryptographic operations.
"""

from .crypto_helpers import CryptoHelpers, GNURadioCryptoUtils
from .keyring_helper import KeyringHelper

try:
    from .gdss_set_key_source import gdss_set_key_source_block
except ImportError:
    gdss_set_key_source_block = None

__version__ = "1.0.0"
__all__ = [
    "KeyringHelper",
    "CryptoHelpers",
    "GNURadioCryptoUtils",
    "gdss_set_key_source_block",
]
