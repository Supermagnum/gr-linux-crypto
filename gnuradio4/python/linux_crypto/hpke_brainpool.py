#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HPKE-style high-level wrapper for Brainpool multi-recipient ECIES.

Provides a single entry point (seal/open) to reduce misuse and simplify
flowgraph design. Uses MultiRecipientECIES under the hood with fixed
defaults; optional sender authentication (seal_with_auth / open_with_auth).
"""

from typing import List, Optional, Tuple

try:
    from .multi_recipient_ecies import MultiRecipientECIES
except ImportError:
    from multi_recipient_ecies import MultiRecipientECIES


class HPKEBrainpool:
    """
    HPKE-style API for Brainpool multi-recipient encryption.

    - seal(plaintext, recipient_callsigns) -> ciphertext
    - open(ciphertext, my_callsign, my_private_key_pem) -> plaintext
    - seal_with_auth / open_with_auth: same plus sender ECDSA authentication
    """

    def __init__(
        self,
        key_store_path: Optional[str] = None,
        curve: str = "brainpoolP256r1",
        symmetric_cipher: str = "aes-gcm",
    ):
        """
        Initialize the HPKE-style wrapper.

        Args:
            key_store_path: Path to JSON key store (optional; keys can be from keyring)
            curve: Brainpool curve name (default: brainpoolP256r1)
            symmetric_cipher: "aes-gcm" or "chacha20-poly1305"
        """
        self._ecies = MultiRecipientECIES(
            curve=curve,
            key_store_path=key_store_path,
            symmetric_cipher=symmetric_cipher,
        )

    def seal(
        self,
        plaintext: bytes,
        recipient_callsigns: List[str],
    ) -> bytes:
        """
        Encrypt for one or more recipients (unauthenticated).

        Args:
            plaintext: Data to encrypt
            recipient_callsigns: List of recipient callsigns (1-25)

        Returns:
            Ciphertext in multi-recipient ECIES format
        """
        return self._ecies.encrypt(plaintext, recipient_callsigns)

    def open(
        self,
        ciphertext: bytes,
        recipient_callsign: str,
        recipient_private_key_pem: str,
        private_key_password: str = "",
    ) -> bytes:
        """
        Decrypt as a recipient (unauthenticated).

        Args:
            ciphertext: Output from seal()
            recipient_callsign: This recipient's callsign
            recipient_private_key_pem: This recipient's private key (PEM)
            private_key_password: Optional password for the private key

        Returns:
            Decrypted plaintext
        """
        return self._ecies.decrypt(
            ciphertext,
            recipient_callsign,
            recipient_private_key_pem,
            private_key_password=private_key_password,
        )

    def seal_with_auth(
        self,
        plaintext: bytes,
        recipient_callsigns: List[str],
        sender_private_key_pem: str,
        sender_private_key_password: str = "",
        hash_algorithm: str = "sha256",
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt for recipients and sign with sender's key (authenticated).

        Args:
            plaintext: Data to encrypt
            recipient_callsigns: List of recipient callsigns
            sender_private_key_pem: Sender's Brainpool private key (PEM)
            sender_private_key_password: Optional password for sender key
            hash_algorithm: ECDSA hash ('sha256', 'sha384', 'sha512')

        Returns:
            (ciphertext, signature) - transport both together
        """
        return self._ecies.encrypt_and_sign(
            plaintext,
            recipient_callsigns,
            sender_private_key_pem,
            sender_private_key_password=sender_private_key_password,
            hash_algorithm=hash_algorithm,
        )

    def open_with_auth(
        self,
        ciphertext: bytes,
        recipient_callsign: str,
        recipient_private_key_pem: str,
        sender_signature: bytes,
        sender_public_key_pem: str,
        private_key_password: str = "",
        hash_algorithm: str = "sha256",
    ) -> bytes:
        """
        Verify sender signature and decrypt (authenticated).

        Args:
            ciphertext: Output from seal_with_auth()
            recipient_callsign: This recipient's callsign
            recipient_private_key_pem: This recipient's private key (PEM)
            sender_signature: Signature from seal_with_auth()
            sender_public_key_pem: Sender's public key (PEM)
            private_key_password: Optional password for recipient key
            hash_algorithm: ECDSA hash used when sealing

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If sender signature verification fails
        """
        return self._ecies.verify_and_decrypt(
            ciphertext,
            recipient_callsign,
            recipient_private_key_pem,
            sender_signature,
            sender_public_key_pem,
            private_key_password=private_key_password,
            hash_algorithm=hash_algorithm,
        )
