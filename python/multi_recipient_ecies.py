#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-recipient ECIES encryption/decryption implementation.

Implements the key block format and encryption/decryption logic
for up to 25 recipients using Brainpool ECIES.
"""

import struct
import secrets
from typing import List, Optional, Tuple

try:
    from .callsign_key_store import CallsignKeyStore
    from .crypto_helpers import CryptoHelpers
except ImportError:
    from callsign_key_store import CallsignKeyStore
    from crypto_helpers import CryptoHelpers


class MultiRecipientECIES:
    """
    Multi-recipient ECIES encryption/decryption.

    Supports up to 25 recipients using hybrid encryption:
    - Symmetric key encrypted for each recipient using ECIES
    - Payload encrypted with AES-GCM or ChaCha20-Poly1305 using the symmetric key
    """

    FORMAT_VERSION = 0x01
    MAX_RECIPIENTS = 25
    MAX_CALLSIGN_LEN = 14
    AES_KEY_SIZE = 32
    AES_IV_SIZE = 12
    AES_TAG_SIZE = 16
    HEADER_SIZE = 8

    CURVE_IDS = {
        "brainpoolP256r1": 0x01,
        "brainpoolP384r1": 0x02,
        "brainpoolP512r1": 0x03,
    }

    CURVE_NAMES = {v: k for k, v in CURVE_IDS.items()}

    CIPHER_IDS = {
        "aes-gcm": 0x01,
        "chacha20-poly1305": 0x02,
    }

    CIPHER_NAMES = {v: k for k, v in CIPHER_IDS.items()}

    def __init__(
        self,
        curve: str = "brainpoolP256r1",
        key_store_path: Optional[str] = None,
        symmetric_cipher: str = "aes-gcm",
    ):
        """
        Initialize multi-recipient ECIES.

        Args:
            curve: Brainpool curve name
            key_store_path: Path to key store (None for default)
            symmetric_cipher: Symmetric cipher for payload encryption
                             ("aes-gcm" or "chacha20-poly1305")
        """
        self.curve = curve
        self.curve_id = self.CURVE_IDS.get(curve, 0x01)
        self.symmetric_cipher = symmetric_cipher.lower()
        if self.symmetric_cipher not in self.CIPHER_IDS:
            raise ValueError(
                f"Unsupported cipher: {symmetric_cipher}. "
                f"Supported: {list(self.CIPHER_IDS.keys())}"
            )
        self.cipher_id = self.CIPHER_IDS[self.symmetric_cipher]
        self.crypto = CryptoHelpers()
        self.key_store = CallsignKeyStore(store_path=key_store_path)

    def encrypt(self, plaintext: bytes, callsigns: List[str]) -> bytes:
        """
        Encrypt data for multiple recipients.

        Args:
            plaintext: Data to encrypt
            callsigns: List of recipient callsigns (1-25)

        Returns:
            Encrypted block in multi-recipient format

        Raises:
            ValueError: If invalid number of recipients or missing keys
        """
        if not callsigns or len(callsigns) > self.MAX_RECIPIENTS:
            raise ValueError(f"Must have 1-{self.MAX_RECIPIENTS} recipients")

        if len(callsigns) != len(set(callsigns)):
            raise ValueError("Duplicate callsigns not allowed")

        callsigns = [c.upper().strip() for c in callsigns]

        for callsign in callsigns:
            if len(callsign) > self.MAX_CALLSIGN_LEN:
                raise ValueError(f"Callsign too long: {callsign}")
            if not self.key_store.has_callsign(callsign):
                raise ValueError(f"Public key not found for callsign: {callsign}")

        symmetric_key = secrets.token_bytes(self.AES_KEY_SIZE)
        iv = secrets.token_bytes(self.AES_IV_SIZE)

        if self.symmetric_cipher == "aes-gcm":
            ciphertext, tag = self._encrypt_aes_gcm(plaintext, symmetric_key, iv)
        elif self.symmetric_cipher == "chacha20-poly1305":
            ciphertext, tag = self._encrypt_chacha20_poly1305(
                plaintext, symmetric_key, iv
            )
        else:
            raise ValueError(f"Unsupported cipher: {self.symmetric_cipher}")

        recipient_blocks = []
        for callsign in callsigns:
            public_key_pem = self.key_store.get_public_key(callsign)
            if not public_key_pem:
                raise ValueError(f"Public key not found for callsign: {callsign}")

            encrypted_key_block = self._encrypt_symmetric_key_ecies(
                symmetric_key, public_key_pem
            )

            callsign_bytes = callsign.encode("ascii") + b"\x00"
            if len(callsign_bytes) > self.MAX_CALLSIGN_LEN + 1:
                raise ValueError(f"Callsign encoding too long: {callsign}")

            recipient_block = struct.pack("B", len(callsign_bytes) - 1)
            recipient_block += callsign_bytes
            recipient_block += struct.pack(">H", len(encrypted_key_block))
            recipient_block += encrypted_key_block

            recipient_blocks.append(recipient_block)

        header = self._build_header(
            len(callsigns), len(ciphertext) + self.AES_IV_SIZE, self.cipher_id
        )

        result = header
        for block in recipient_blocks:
            result += block
        result += iv
        result += ciphertext
        result += tag

        return result

    def decrypt(
        self,
        encrypted_block: bytes,
        recipient_callsign: str,
        recipient_private_key_pem: str,
        private_key_password: str = "",
    ) -> bytes:
        """
        Decrypt data for a specific recipient.

        Args:
            encrypted_block: Encrypted block in multi-recipient format
            recipient_callsign: Callsign of this recipient
            recipient_private_key_pem: Recipient's private key in PEM format
            private_key_password: Password for encrypted private key

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If format invalid or recipient not found
        """
        if len(encrypted_block) < self.HEADER_SIZE:
            raise ValueError("Encrypted block too short")

        version, curve_id, recipient_count, cipher_id, data_length = struct.unpack(
            ">BBBB I", encrypted_block[: self.HEADER_SIZE]
        )

        if version != self.FORMAT_VERSION:
            raise ValueError(f"Unsupported format version: {version}")

        if curve_id != self.curve_id:
            raise ValueError(
                f"Curve mismatch: expected {self.curve_id}, got {curve_id}"
            )

        if cipher_id not in self.CIPHER_NAMES:
            raise ValueError(f"Unsupported cipher ID: {cipher_id}")

        block_cipher = self.CIPHER_NAMES[cipher_id]

        if recipient_count == 0 or recipient_count > self.MAX_RECIPIENTS:
            raise ValueError(f"Invalid recipient count: {recipient_count}")

        recipient_callsign = recipient_callsign.upper().strip()
        offset = self.HEADER_SIZE

        encrypted_key_block = None

        for _ in range(recipient_count):
            if offset >= len(encrypted_block):
                raise ValueError("Invalid block format: premature end")

            callsign_len = encrypted_block[offset]
            offset += 1

            if callsign_len == 0 or callsign_len > self.MAX_CALLSIGN_LEN:
                raise ValueError(f"Invalid callsign length: {callsign_len}")

            if offset + callsign_len + 1 > len(encrypted_block):
                raise ValueError("Invalid block format: callsign out of bounds")

            callsign_bytes = encrypted_block[offset : offset + callsign_len + 1]
            if callsign_bytes[-1] != 0:
                raise ValueError("Callsign not null-terminated")

            callsign = callsign_bytes[:-1].decode("ascii")
            offset += callsign_len + 1

            if offset + 2 > len(encrypted_block):
                raise ValueError("Invalid block format: key length out of bounds")

            encrypted_key_len = struct.unpack(
                ">H", encrypted_block[offset : offset + 2]
            )[0]
            offset += 2

            if offset + encrypted_key_len > len(encrypted_block):
                raise ValueError("Invalid block format: encrypted key out of bounds")

            if callsign == recipient_callsign:
                encrypted_key_block = encrypted_block[
                    offset : offset + encrypted_key_len
                ]

            offset += encrypted_key_len

        if encrypted_key_block is None:
            raise ValueError(f"Recipient callsign not found: {recipient_callsign}")

        if (
            offset
            + self.AES_IV_SIZE
            + data_length
            - self.AES_IV_SIZE
            + self.AES_TAG_SIZE
            > len(encrypted_block)
        ):
            raise ValueError("Invalid block format: data out of bounds")

        iv = encrypted_block[offset : offset + self.AES_IV_SIZE]
        offset += self.AES_IV_SIZE

        ciphertext_length = data_length - self.AES_IV_SIZE
        if ciphertext_length < 0:
            raise ValueError("Invalid data length in header")

        ciphertext = encrypted_block[offset : offset + ciphertext_length]
        offset += ciphertext_length

        if offset + self.AES_TAG_SIZE > len(encrypted_block):
            raise ValueError("Invalid block format: tag out of bounds")

        tag = encrypted_block[offset : offset + self.AES_TAG_SIZE]

        symmetric_key = self._decrypt_symmetric_key_ecies(
            encrypted_key_block, recipient_private_key_pem, private_key_password
        )

        if block_cipher == "aes-gcm":
            plaintext = self._decrypt_aes_gcm(ciphertext, symmetric_key, iv, tag)
        elif block_cipher == "chacha20-poly1305":
            plaintext = self._decrypt_chacha20_poly1305(
                ciphertext, symmetric_key, iv, tag
            )
        else:
            raise ValueError(f"Unsupported cipher: {block_cipher}")

        return plaintext

    def _build_header(
        self, recipient_count: int, data_length: int, cipher_id: int
    ) -> bytes:
        """Build the block header."""
        return struct.pack(
            ">BBBB I",
            self.FORMAT_VERSION,
            self.curve_id,
            recipient_count,
            cipher_id,
            data_length,
        )

    def _encrypt_symmetric_key_ecies(
        self, symmetric_key: bytes, recipient_public_key_pem: str
    ) -> bytes:
        """
        Encrypt symmetric key using ECIES for a single recipient.

        Returns the ECIES encrypted block format:
        [2 bytes: pubkey_len][pubkey_PEM][12 bytes: IV][2 bytes: ciphertext_len][ciphertext][16 bytes: tag]
        """
        recipient_public_key = self.crypto.load_brainpool_public_key(
            recipient_public_key_pem.encode("ascii")
        )

        ephemeral_private_key, ephemeral_public_key = (
            self.crypto.generate_brainpool_keypair(self.curve)
        )

        shared_secret = self.crypto.brainpool_ecdh(
            ephemeral_private_key, recipient_public_key
        )

        salt = b""
        info = b"gr-linux-crypto-ecies-v1"
        derived_key = self.crypto.derive_key_hkdf(
            shared_secret,
            salt=salt,
            info=info,
            length=self.AES_KEY_SIZE + self.AES_IV_SIZE,
        )

        key = derived_key[: self.AES_KEY_SIZE]
        iv = derived_key[self.AES_KEY_SIZE :]

        encrypted_key, tag = self._encrypt_aes_gcm(symmetric_key, key, iv)

        ephemeral_public_key_pem = self.crypto.serialize_brainpool_public_key(
            ephemeral_public_key
        )

        result = struct.pack(">H", len(ephemeral_public_key_pem))
        result += ephemeral_public_key_pem
        result += iv
        result += struct.pack(">H", len(encrypted_key))
        result += encrypted_key
        result += tag

        return result

    def _decrypt_symmetric_key_ecies(
        self,
        encrypted_key_block: bytes,
        recipient_private_key_pem: str,
        private_key_password: str,
    ) -> bytes:
        """Decrypt symmetric key from ECIES block."""
        offset = 0
        pubkey_len = struct.unpack(">H", encrypted_key_block[offset : offset + 2])[0]
        offset += 2

        ephemeral_public_key_pem = encrypted_key_block[offset : offset + pubkey_len]
        offset += pubkey_len

        iv = encrypted_key_block[offset : offset + self.AES_IV_SIZE]
        offset += self.AES_IV_SIZE

        ciphertext_len = struct.unpack(">H", encrypted_key_block[offset : offset + 2])[
            0
        ]
        offset += 2

        ciphertext = encrypted_key_block[offset : offset + ciphertext_len]
        offset += ciphertext_len

        tag = encrypted_key_block[offset : offset + self.AES_TAG_SIZE]

        recipient_private_key = self.crypto.load_brainpool_private_key(
            recipient_private_key_pem.encode("ascii"),
            password=(
                private_key_password.encode("ascii") if private_key_password else None
            ),
        )

        ephemeral_public_key = self.crypto.load_brainpool_public_key(
            ephemeral_public_key_pem
        )

        shared_secret = self.crypto.brainpool_ecdh(
            recipient_private_key, ephemeral_public_key
        )

        salt = b""
        info = b"gr-linux-crypto-ecies-v1"
        derived_key = self.crypto.derive_key_hkdf(
            shared_secret,
            salt=salt,
            info=info,
            length=self.AES_KEY_SIZE + self.AES_IV_SIZE,
        )

        key = derived_key[: self.AES_KEY_SIZE]
        derived_iv = derived_key[self.AES_KEY_SIZE :]

        if derived_iv != iv:
            raise ValueError("IV mismatch in ECIES decryption")

        symmetric_key = self._decrypt_aes_gcm(ciphertext, key, iv, tag)

        return symmetric_key

    def _extract_iv_from_ecies_block(self, encrypted_key_block: bytes) -> bytes:
        """Extract IV from ECIES block."""
        offset = 2
        pubkey_len = struct.unpack(">H", encrypted_key_block[:2])[0]
        offset += pubkey_len
        return encrypted_key_block[offset : offset + self.AES_IV_SIZE]

    def _encrypt_aes_gcm(
        self, plaintext: bytes, key: bytes, iv: bytes
    ) -> Tuple[bytes, bytes]:
        """Encrypt using AES-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        tag = ciphertext[-self.AES_TAG_SIZE :]
        ciphertext_only = ciphertext[: -self.AES_TAG_SIZE]

        return ciphertext_only, tag

    def _decrypt_aes_gcm(
        self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes
    ) -> bytes:
        """Decrypt using AES-GCM."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        full_ciphertext = ciphertext + tag
        plaintext = aesgcm.decrypt(iv, full_ciphertext, None)

        return plaintext

    def _encrypt_chacha20_poly1305(
        self, plaintext: bytes, key: bytes, nonce: bytes
    ) -> Tuple[bytes, bytes]:
        """Encrypt using ChaCha20-Poly1305."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        if len(nonce) != self.AES_IV_SIZE:
            raise ValueError(f"Nonce must be {self.AES_IV_SIZE} bytes")

        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        tag = ciphertext[-self.AES_TAG_SIZE :]
        ciphertext_only = ciphertext[: -self.AES_TAG_SIZE]

        return ciphertext_only, tag

    def _decrypt_chacha20_poly1305(
        self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes
    ) -> bytes:
        """Decrypt using ChaCha20-Poly1305."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        if len(nonce) != self.AES_IV_SIZE:
            raise ValueError(f"Nonce must be {self.AES_IV_SIZE} bytes")

        cipher = ChaCha20Poly1305(key)
        full_ciphertext = ciphertext + tag
        plaintext = cipher.decrypt(nonce, full_ciphertext, None)

        return plaintext
