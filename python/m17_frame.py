#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M17 Protocol Frame Construction and Parsing.

M17 is a digital radio protocol. This module provides:
- M17 Link Setup Frame (LSF) construction
- Encryption metadata handling
- Codec2 payload encryption/decryption
- Frame synchronization
"""

import struct
from enum import IntEnum
from typing import Optional

try:
    from .linux_crypto import decrypt, encrypt
except ImportError:
    # Fallback for direct import
    from linux_crypto import decrypt, encrypt


class M17EncryptionType(IntEnum):
    """M17 encryption type codes."""

    NONE = 0x00
    AES_256 = 0x01
    AES_128 = 0x02
    CUSTOM = 0x03


class M17EncryptionSubtype(IntEnum):
    """M17 encryption subtype codes."""

    CHACHA20_POLY1305 = 0x01
    AES_GCM = 0x02


class M17Frame:
    """M17 frame structure with encryption support."""

    # M17 frame constants
    LSF_SIZE = 240  # bits = 30 bytes
    STREAM_FRAME_SIZE = 384  # bits = 48 bytes
    PAYLOAD_SIZE = 16  # bytes (Codec2 3200bps = 16 bytes per 40ms)
    SYNC_WORD_LSF = 0x5D5F
    SYNC_WORD_STREAM = 0xFF5D

    def __init__(self):
        self.sync_word = 0
        self.frame_type = 0  # 0 = LSF, 1 = Stream
        self.payload = b""
        self.encrypted_payload = b""
        self.encryption_type = M17EncryptionType.NONE
        self.encryption_subtype = 0
        self.key_fingerprint = b""
        self.nonce = b""
        self.auth_tag = b""
        self.frame_counter = 0
        self.meta = b""

    @staticmethod
    def create_lsf_frame(
        src: str,
        dst: str,
        meta: bytes = b"",
        encryption_type: M17EncryptionType = M17EncryptionType.NONE,
        encryption_subtype: int = 0,
        key_fingerprint: bytes = b"",
    ) -> "M17Frame":
        """
        Create M17 Link Setup Frame (LSF).

        Args:
            src: Source callsign (up to 9 chars)
            dst: Destination callsign (up to 9 chars)
            meta: Metadata (14 bytes)
            encryption_type: Encryption type code
            encryption_subtype: Encryption subtype code
            key_fingerprint: Key fingerprint (up to 8 bytes)
        """
        frame = M17Frame()
        frame.sync_word = M17Frame.SYNC_WORD_LSF
        frame.frame_type = 0
        frame.encryption_type = encryption_type
        frame.encryption_subtype = encryption_subtype
        frame.key_fingerprint = key_fingerprint[:8]  # Limit to 8 bytes
        frame.meta = meta[:14]  # Limit to 14 bytes

        # Build LSF payload
        # LSF structure: 240 bits (30 bytes)
        # Bits 0-47: Destination callsign (6 bytes, base40 encoded)
        # Bits 48-95: Source callsign (6 bytes, base40 encoded)
        # Bits 96-127: Frame type (4 bytes)
        # Bits 128-143: Encryption type/subtype (2 bytes)
        # Bits 144-207: Key fingerprint (8 bytes)
        # Bits 208-239: Metadata (4 bytes)

        dst_encoded = M17Frame._encode_callsign(dst)
        src_encoded = M17Frame._encode_callsign(src)

        # Build LSF payload: 30 bytes total
        # Bytes 0-5: Destination callsign (6 bytes)
        # Bytes 6-11: Source callsign (6 bytes)
        # Bytes 12-15: Frame type (4 bytes, LSF = 0)
        # Bytes 16-17: Encryption type/subtype (2 bytes)
        # Bytes 18-25: Key fingerprint (8 bytes)
        # Bytes 26-29: Metadata (4 bytes)
        frame.payload = (
            dst_encoded[:6].ljust(6, b"\x00")
            + src_encoded[:6].ljust(6, b"\x00")
            + struct.pack(">I", 0)[:4]  # Frame type (LSF = 0)
            + struct.pack(">BB", int(encryption_type), int(encryption_subtype))
            + frame.key_fingerprint[:8].ljust(8, b"\x00")
            + frame.meta[:4].ljust(4, b"\x00")
        )

        # Pad to 30 bytes
        frame.payload = frame.payload.ljust(30, b"\x00")

        return frame

    @staticmethod
    def create_stream_frame(
        payload: bytes,
        frame_counter: int,
        encryption_type: M17EncryptionType = M17EncryptionType.NONE,
        key: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> "M17Frame":
        """
        Create M17 stream frame with optional encryption.

        Args:
            payload: Codec2 payload (16 bytes for 3200bps)
            frame_counter: Frame counter (for nonce generation)
            encryption_type: Encryption type
            key: Encryption key (if None, no encryption)
            nonce: Nonce/IV (if None, generated from frame counter)
        """
        frame = M17Frame()
        frame.sync_word = M17Frame.SYNC_WORD_STREAM
        frame.frame_type = 1
        frame.frame_counter = frame_counter
        frame.encryption_type = encryption_type

        if encryption_type == M17EncryptionType.CUSTOM and key:
            # Use ChaCha20-Poly1305 for M17 custom encryption
            if nonce is None:
                # Generate nonce from frame counter (12 bytes)
                nonce = struct.pack(">Q", frame_counter).ljust(12, b"\x00")

            frame.nonce = nonce

            # Encrypt payload
            ciphertext, nonce_out, auth_tag = encrypt(
                "chacha20", key, payload, iv_mode=nonce, auth="poly1305"
            )

            frame.encrypted_payload = ciphertext
            frame.auth_tag = auth_tag
            frame.nonce = nonce_out
        else:
            frame.payload = payload

        return frame

    def encrypt_payload(self, key: bytes, algorithm: str = "chacha20") -> bool:
        """
        Encrypt frame payload.

        Args:
            key: Encryption key
            algorithm: 'chacha20' or 'aes-256'

        Returns:
            True if encryption successful
        """
        if not self.payload:
            return False

        try:
            if algorithm == "chacha20":
                self.encryption_type = M17EncryptionType.CUSTOM
                self.encryption_subtype = M17EncryptionSubtype.CHACHA20_POLY1305

                # Generate nonce from frame counter or random
                if self.frame_counter > 0:
                    self.nonce = struct.pack(">Q", self.frame_counter).ljust(
                        12, b"\x00"
                    )
                else:
                    import secrets

                    self.nonce = secrets.token_bytes(12)

                ciphertext, nonce_out, auth_tag = encrypt(
                    "chacha20", key, self.payload, iv_mode=self.nonce, auth="poly1305"
                )

                self.encrypted_payload = ciphertext
                self.auth_tag = auth_tag
                self.nonce = nonce_out
                return True

            elif algorithm == "aes-256":
                self.encryption_type = M17EncryptionType.AES_256
                self.encryption_subtype = M17EncryptionSubtype.AES_GCM

                import secrets

                iv = secrets.token_bytes(12)  # GCM uses 12-byte IV

                ciphertext, iv_out, auth_tag = encrypt(
                    "aes-256", key, self.payload, iv_mode=iv, auth="gcm"
                )

                self.encrypted_payload = ciphertext
                self.auth_tag = auth_tag
                self.nonce = iv_out
                return True

        except Exception as e:
            print(f"Encryption failed: {e}")
            return False

        return False

    def decrypt_payload(self, key: bytes) -> bool:
        """
        Decrypt frame payload.

        Args:
            key: Decryption key

        Returns:
            True if decryption successful
        """
        if not self.encrypted_payload:
            return False

        try:
            if self.encryption_type == M17EncryptionType.CUSTOM:
                algorithm = "chacha20"
                auth = "poly1305"
            elif self.encryption_type == M17EncryptionType.AES_256:
                algorithm = "aes-256"
                auth = "gcm"
            else:
                return False

            self.payload = decrypt(
                algorithm,
                key,
                self.encrypted_payload,
                self.nonce,
                auth=auth,
                auth_tag=self.auth_tag,
            )

            self.encrypted_payload = b""
            return True

        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

    def to_bytes(self) -> bytes:
        """Serialize frame to bytes."""
        frame_data = b""

        # Sync word (2 bytes)
        frame_data += struct.pack(">H", self.sync_word)

        if self.frame_type == 0:
            # LSF frame
            frame_data += self.payload
        else:
            # Stream frame
            # Frame structure: sync(2) + payload(16) + encryption metadata
            if self.encrypted_payload:
                frame_data += self.encrypted_payload
                frame_data += self.nonce
                frame_data += self.auth_tag
            else:
                frame_data += self.payload.ljust(16, b"\x00")

            # Frame counter (optional, in header)
            frame_data += struct.pack(">I", self.frame_counter)[:2]  # 2 bytes

        return frame_data

    @staticmethod
    def from_bytes(data: bytes) -> Optional["M17Frame"]:
        """Parse frame from bytes."""
        if len(data) < 2:
            return None

        frame = M17Frame()
        frame.sync_word = struct.unpack(">H", data[0:2])[0]

        if frame.sync_word == M17Frame.SYNC_WORD_LSF:
            # LSF frame
            frame.frame_type = 0
            if len(data) >= 32:
                frame.payload = data[2:32]
                # Parse LSF fields
                if len(frame.payload) >= 16:
                    # LSF structure:
                    # payload[0:6] = dst callsign
                    # payload[6:12] = src callsign
                    # payload[12:16] = frame type (4 bytes)
                    # Actually: After callsigns (12 bytes), we have frame type (4 bytes), then encryption fields
                    # So encryption_type is at offset 16, not 12
                    if len(frame.payload) > 17:
                        # Frame type is at 12-16, encryption_type at 16, encryption_subtype at 17
                        frame.encryption_type = M17EncryptionType(frame.payload[16])
                        frame.encryption_subtype = frame.payload[17]
                    elif len(frame.payload) > 13:
                        # Fallback: try offset 12 (for backwards compatibility)
                        frame.encryption_type = M17EncryptionType(frame.payload[12])
                        frame.encryption_subtype = frame.payload[13]
                    if len(frame.payload) >= 22:
                        frame.key_fingerprint = frame.payload[14:22]
                    if len(frame.payload) >= 26:
                        frame.meta = frame.payload[22:26]

        elif frame.sync_word == M17Frame.SYNC_WORD_STREAM:
            # Stream frame
            frame.frame_type = 1
            if len(data) >= 18:
                frame.payload = data[2:18]
                if len(data) >= 34:
                    # May have encryption metadata
                    frame.frame_counter = struct.unpack(">H", data[16:18])[0]
                    # Check if encrypted (would need encryption flags)

        return frame

    @staticmethod
    def _encode_callsign(callsign: str) -> bytes:
        """
        Encode callsign using M17 base40 encoding.

        Simplified version - converts to 6 bytes.
        """
        # Base40 encoding: A-Z, 0-9, space, hyphen, slash
        # For testing, use simplified encoding
        callsign_bytes = callsign.encode("ascii", errors="ignore").upper()[:9]
        # Pad to 6 bytes
        encoded = callsign_bytes.ljust(6, b"\x00")
        return encoded

    @staticmethod
    def _decode_callsign(encoded: bytes) -> str:
        """Decode callsign from base40 encoding."""
        # Simplified decoding
        return encoded.rstrip(b"\x00").decode("ascii", errors="ignore")


class M17SessionKeyExchange:
    """M17 session key exchange protocol using GnuPG."""

    @staticmethod
    def generate_session_key() -> bytes:
        """Generate a random session key."""
        import secrets

        return secrets.token_bytes(32)  # 256-bit key

    @staticmethod
    def encrypt_key_for_recipient(
        session_key: bytes, recipient_key_id: str
    ) -> Optional[bytes]:
        """
        Encrypt session key using GnuPG for recipient.

        Args:
            session_key: Session key to encrypt
            recipient_key_id: GnuPG key ID or fingerprint

        Returns:
            Encrypted key as bytes, or None on failure
        """
        import subprocess

        try:
            # Use GnuPG to encrypt
            result = subprocess.run(
                ["gpg", "--encrypt", "--recipient", recipient_key_id, "--armor"],
                input=session_key,
                capture_output=True,
                timeout=5,
            )

            if result.returncode == 0:
                return result.stdout
            else:
                print(f"GnuPG encryption failed: {result.stderr.decode()}")
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"GnuPG not available: {e}")
            return None

    @staticmethod
    def decrypt_key(encrypted_key: bytes) -> Optional[bytes]:
        """Decrypt session key using GnuPG."""
        import subprocess

        try:
            result = subprocess.run(
                ["gpg", "--decrypt"],
                input=encrypted_key,
                capture_output=True,
                timeout=5,
            )

            if result.returncode == 0:
                return result.stdout
            else:
                print(f"GnuPG decryption failed: {result.stderr.decode()}")
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"GnuPG not available: {e}")
            return None

    @staticmethod
    def sign_key_offer(session_key: bytes, sender_key_id: str) -> Optional[bytes]:
        """Sign a key offer with sender's GnuPG key."""
        import subprocess

        try:
            result = subprocess.run(
                ["gpg", "--sign", "--local-user", sender_key_id],
                input=session_key,
                capture_output=True,
                timeout=5,
            )

            if result.returncode == 0:
                return result.stdout
            else:
                return None

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    @staticmethod
    def verify_key_offer_signature(signed_data: bytes) -> bool:
        """Verify signature on key offer."""
        import subprocess

        try:
            result = subprocess.run(
                ["gpg", "--verify"], input=signed_data, capture_output=True, timeout=5
            )

            return result.returncode == 0

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
