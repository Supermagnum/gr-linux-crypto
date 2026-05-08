#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nitrokey / OpenPGP Card bridge for multi-recipient ECIES decryption.

When the recipient's private key lives on an OpenPGP Card (e.g. Nitrokey),
decryption can be performed with the key never leaving the device. This module
documents the supported flow and provides a Python API that delegates to the
GNU Radio C++ block when available.

In a GNU Radio flowgraph, use the brainpool_ecies_multi_decrypt block with:
  - key_source = "opgp_card"
  - recipient_key_identifier = keygrip (40 hex chars from gpg --list-secret-keys --with-keygrip)

Standalone Python: on-card decryption is only available via the C++ block or
a system helper that uses GnuPG/card for ECDH. This module exposes
decrypt_with_card() which raises NotImplementedError with instructions when
no such helper is available.
"""

from typing import Optional

try:
    from .multi_recipient_ecies import MultiRecipientECIES
except ImportError:
    MultiRecipientECIES = None  # type: ignore


def decrypt_with_card(
    encrypted_block: bytes,
    recipient_callsign: str,
    keygrip: str,
    key_store_path: Optional[str] = None,
) -> bytes:
    """
    Decrypt a multi-recipient ECIES block using a private key on an OpenPGP Card.

    The private key is identified by keygrip (40 hex characters). Decryption
    uses the card for ECDH; the symmetric key never leaves the card.

    In standalone Python this raises NotImplementedError: use the GNU Radio
    block brainpool_ecies_multi_decrypt with key_source="opgp_card" and
    recipient_key_identifier=<keygrip> for on-card decryption. When running
    inside a flowgraph, the block performs ECDH via GnuPG and the card.

    Args:
        encrypted_block: Multi-recipient ECIES ciphertext (version 0x01)
        recipient_callsign: Callsign for this recipient (must match block)
        keygrip: Keygrip of the card key (e.g. from gpg --list-secret-keys --with-keygrip)
        key_store_path: Optional path to key store (not used for card key)

    Returns:
            Decrypted plaintext (only when a helper/C++ path is available)

    Raises:
        NotImplementedError: In standalone Python; use the GR C++ block for on-card decrypt
    """
    _ = key_store_path
    # In the future: try to run a helper binary (e.g. gr-linux-crypto-decrypt-card)
    # that reads encrypted_block from stdin and keygrip/recipient_callsign from argv,
    # outputs plaintext to stdout. Until then, direct Python cannot perform ECDH
    # with the card without GPGME or a subprocess to a C++ helper.
    raise NotImplementedError(
        "On-card decryption from Python is not implemented. "
        "Use the GNU Radio block brainpool_ecies_multi_decrypt with "
        'key_source="opgp_card" and recipient_key_identifier=<keygrip> (40 hex chars). '
        "Ensure GnuPG and the OpenPGP Card are available; the block uses them for ECDH."
    )


def get_keygrip_from_key_id(key_identifier: str) -> str:
    """
    Resolve a GnuPG key ID or fingerprint to a keygrip (40 hex chars).

    Runs: gpg --list-secret-keys --with-keygrip <key_identifier>
    and parses the Keygrip line. Requires gpg on PATH.

    Args:
        key_identifier: Key ID, fingerprint, or email

    Returns:
        Keygrip string (40 hex characters)

    Raises:
        FileNotFoundError: If gpg is not found
        ValueError: If key or keygrip cannot be determined
    """
    import subprocess
    import re
    result = subprocess.run(
        [
            "gpg",
            "--list-secret-keys",
            "--with-keygrip",
            "--keyid-format=long",
            key_identifier,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise ValueError(
            f"gpg failed or key not found: {result.stderr or result.stdout}"
        )
    # Keygrip appears as "      Keygrip = XXXXX..."
    match = re.search(r"Keygrip\s*=\s*([A-Fa-f0-9]{40})", result.stdout)
    if not match:
        raise ValueError("Keygrip not found in gpg output")
    return match.group(1)
