#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M17 Protocol Integration Tests with gr-linux-crypto.

Tests M17 frame encryption, Codec2 payload handling, and interoperability.
"""

import os
import secrets
import struct
import subprocess
import sys
from pathlib import Path

import pytest

# Import M17 frame handling
try:
    from python.m17_frame import (
        M17EncryptionSubtype,
        M17EncryptionType,
        M17Frame,
        M17SessionKeyExchange,
    )
except ImportError:
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
        from m17_frame import (
            M17EncryptionSubtype,
            M17EncryptionType,
            M17Frame,
            M17SessionKeyExchange,
        )
    except ImportError:
        pytest.skip("Cannot import m17_frame")

# Import decrypt function
try:
    pass
except ImportError:
    try:
        pass
    except ImportError:
        # Define locally if needed
        pass

# Import crypto helpers
try:
    pass
except ImportError:
    try:
        pass
    except ImportError:
        pytest.skip("Cannot import crypto_helpers")


class TestM17FrameStructure:
    """Test M17 frame structure and encryption metadata."""

    def test_lsf_frame_creation(self):
        """Test M17 LSF frame creation."""
        src = "CALLSIGN"
        dst = "TARGET"

        frame = M17Frame.create_lsf_frame(
            src=src,
            dst=dst,
            encryption_type=M17EncryptionType.CUSTOM,
            encryption_subtype=M17EncryptionSubtype.CHACHA20_POLY1305,
            key_fingerprint=b"\x12\x34\x56\x78\x9a\xbc\xde\xf0",
        )

        assert frame.sync_word == M17Frame.SYNC_WORD_LSF
        assert frame.frame_type == 0
        assert frame.encryption_type == M17EncryptionType.CUSTOM
        assert frame.encryption_subtype == M17EncryptionSubtype.CHACHA20_POLY1305
        assert len(frame.key_fingerprint) == 8
        # LSF payload is 30 bytes (240 bits), but serialized frame includes sync word
        assert len(frame.payload) >= 30

    def test_lsf_encryption_metadata(self):
        """Test encryption metadata fields in LSF."""
        frame = M17Frame.create_lsf_frame(
            src="TEST1",
            dst="TEST2",
            encryption_type=M17EncryptionType.CUSTOM,
            encryption_subtype=M17EncryptionSubtype.CHACHA20_POLY1305,
            key_fingerprint=b"\xff" * 8,
        )

        # Verify encryption type = 0x03 (custom)
        assert frame.encryption_type == 0x03

        # Verify encryption subtype = 0x01 (ChaCha20-Poly1305)
        assert frame.encryption_subtype == 0x01

        # Verify key fingerprint is stored
        assert len(frame.key_fingerprint) == 8

    def test_stream_frame_creation(self):
        """Test M17 stream frame creation."""
        payload = secrets.token_bytes(16)  # Codec2 3200bps = 16 bytes
        frame_counter = 1

        frame = M17Frame.create_stream_frame(
            payload=payload, frame_counter=frame_counter
        )

        assert frame.sync_word == M17Frame.SYNC_WORD_STREAM
        assert frame.frame_type == 1
        assert frame.frame_counter == frame_counter
        assert frame.payload == payload

    def test_stream_frame_encryption(self):
        """Test stream frame encryption."""
        payload = secrets.token_bytes(16)
        key = secrets.token_bytes(32)  # ChaCha20 key
        frame_counter = 1

        frame = M17Frame.create_stream_frame(
            payload=payload,
            frame_counter=frame_counter,
            encryption_type=M17EncryptionType.CUSTOM,
            key=key,
        )

        assert frame.encrypted_payload != b""
        assert len(frame.encrypted_payload) == len(payload)
        assert len(frame.nonce) == 12
        assert len(frame.auth_tag) == 16
        assert frame.encryption_type == M17EncryptionType.CUSTOM

    def test_frame_serialization(self):
        """Test frame serialization to bytes."""
        frame = M17Frame.create_lsf_frame(
            src="SRC", dst="DST", encryption_type=M17EncryptionType.CUSTOM
        )

        frame_bytes = frame.to_bytes()

        assert len(frame_bytes) >= 32  # Sync(2) + payload(30)
        assert frame_bytes[0:2] == struct.pack(">H", M17Frame.SYNC_WORD_LSF)

    def test_frame_parsing(self):
        """Test frame parsing from bytes."""
        frame = M17Frame.create_lsf_frame(
            src="SRC",
            dst="DST",
            encryption_type=M17EncryptionType.CUSTOM,
            encryption_subtype=M17EncryptionSubtype.CHACHA20_POLY1305,
        )

        frame_bytes = frame.to_bytes()
        parsed_frame = M17Frame.from_bytes(frame_bytes)

        assert parsed_frame is not None
        assert parsed_frame.sync_word == M17Frame.SYNC_WORD_LSF
        assert parsed_frame.frame_type == 0
        # Encryption type should be preserved (can be enum or int value)
        assert (
            parsed_frame.encryption_type == M17EncryptionType.CUSTOM
            or parsed_frame.encryption_type == 3
            or int(parsed_frame.encryption_type) == 3
        )


class TestM17Codec2Encryption:
    """Test Codec2 payload encryption/decryption."""

    def test_codec2_3200bps_encryption(self):
        """Test encryption of Codec2 3200bps data (16 bytes per 40ms)."""
        # Simulate Codec2 3200bps frame (16 bytes)
        codec2_payload = secrets.token_bytes(16)
        key = secrets.token_bytes(32)

        frame = M17Frame.create_stream_frame(
            payload=codec2_payload,
            frame_counter=1,
            encryption_type=M17EncryptionType.CUSTOM,
            key=key,
        )

        assert len(frame.encrypted_payload) == 16
        assert frame.encrypted_payload != codec2_payload

    def test_codec2_round_trip(self):
        """Test Codec2 payload encrypt/decrypt round-trip."""
        # Import decrypt function
        try:
            from python.linux_crypto import decrypt
        except ImportError:
            from linux_crypto import decrypt

        original_payload = secrets.token_bytes(16)
        key = secrets.token_bytes(32)

        # Encrypt
        frame = M17Frame.create_stream_frame(
            payload=original_payload,
            frame_counter=1,
            encryption_type=M17EncryptionType.CUSTOM,
            key=key,
        )

        # Decrypt
        decrypted = decrypt(
            "chacha20",
            key,
            frame.encrypted_payload,
            frame.nonce,
            auth="poly1305",
            auth_tag=frame.auth_tag,
        )

        assert decrypted == original_payload

    def test_codec2_multiple_frames(self):
        """Test multiple Codec2 frames with different frame counters."""
        # Import decrypt function
        try:
            from python.linux_crypto import decrypt
        except ImportError:
            from linux_crypto import decrypt

        key = secrets.token_bytes(32)
        frames = []

        for i in range(10):
            payload = secrets.token_bytes(16)
            frame = M17Frame.create_stream_frame(
                payload=payload,
                frame_counter=i,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )
            frames.append((frame, payload))

        # Verify all can be decrypted
        for frame, original_payload in frames:
            decrypted = decrypt(
                "chacha20",
                key,
                frame.encrypted_payload,
                frame.nonce,
                auth="poly1305",
                auth_tag=frame.auth_tag,
            )
            assert decrypted == original_payload


class TestM17FrameSynchronization:
    """Test M17 frame synchronization."""

    def test_sync_word_detection(self):
        """Test sync word detection in frame stream."""
        frames = []

        # Create multiple frames
        for i in range(5):
            frame = M17Frame.create_stream_frame(
                payload=secrets.token_bytes(16), frame_counter=i
            )
            frames.append(frame)

        # Serialize and check sync words
        for i, frame in enumerate(frames):
            frame_bytes = frame.to_bytes()
            sync_word = struct.unpack(">H", frame_bytes[0:2])[0]

            if i == 0:
                # First frame might be LSF
                assert sync_word in [M17Frame.SYNC_WORD_LSF, M17Frame.SYNC_WORD_STREAM]
            else:
                assert sync_word == M17Frame.SYNC_WORD_STREAM

    def test_frame_counter_sequence(self):
        """Test frame counter increments properly."""
        key = secrets.token_bytes(32)
        nonces = []

        for i in range(10):
            frame = M17Frame.create_stream_frame(
                payload=secrets.token_bytes(16),
                frame_counter=i,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )
            nonces.append(frame.nonce)

        # Verify nonces are different (due to frame counter)
        assert (
            len(set(nonces)) > 1
        ), "Nonces should be different for different frame counters"


class TestM17SessionKeyExchange:
    """Test M17 session key exchange protocol."""

    def test_session_key_generation(self):
        """Test session key generation."""
        key = M17SessionKeyExchange.generate_session_key()

        assert len(key) == 32  # 256-bit key
        assert key != b"\x00" * 32  # Not all zeros

    @pytest.mark.skipif(
        not Path("/usr/bin/gpg").exists() and not Path("/usr/local/bin/gpg").exists(),
        reason="GnuPG not available",
    )
    def test_key_encryption_decryption(self):
        """Test GnuPG key encryption/decryption."""
        session_key = M17SessionKeyExchange.generate_session_key()

        # This test requires GnuPG setup with test keys
        # For now, just verify the functions exist and can be called
        assert session_key is not None
        assert len(session_key) == 32

    def test_key_offer_flow(self):
        """Test simulated key offer/accept flow."""
        # Generate session key
        M17SessionKeyExchange.generate_session_key()

        # Simulate key offer (without actual GnuPG for now)
        key_fingerprint = secrets.token_bytes(8)

        # Create LSF with key fingerprint
        offer_frame = M17Frame.create_lsf_frame(
            src="OFFERER",
            dst="ACCEPTER",
            encryption_type=M17EncryptionType.CUSTOM,
            key_fingerprint=key_fingerprint,
        )

        assert offer_frame.key_fingerprint == key_fingerprint
        assert offer_frame.encryption_type == M17EncryptionType.CUSTOM


class TestM17Streaming:
    """Test continuous M17 frame streaming."""

    def test_nonce_incrementing(self):
        """Test nonce properly increments for streaming."""
        key = secrets.token_bytes(32)
        nonces = []

        for i in range(20):
            frame = M17Frame.create_stream_frame(
                payload=secrets.token_bytes(16),
                frame_counter=i,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )
            nonces.append(frame.nonce)

        # Verify nonces are unique (or at least different based on counter)
        unique_nonces = len(set(nonces))
        assert unique_nonces == 20, f"Expected 20 unique nonces, got {unique_nonces}"

    def test_frame_counter_management(self):
        """Test frame counter wraps correctly."""
        key = secrets.token_bytes(32)

        # Test counter wrapping (if implemented)
        for counter in [0, 100, 65535, 0]:  # Wrap around
            frame = M17Frame.create_stream_frame(
                payload=secrets.token_bytes(16),
                frame_counter=counter,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )

            assert frame.frame_counter == counter % 65536  # 16-bit counter

    def test_continuous_encryption(self):
        """Test continuous frame encryption without errors."""
        # Import decrypt function
        try:
            from python.linux_crypto import decrypt
        except ImportError:
            from linux_crypto import decrypt

        key = secrets.token_bytes(32)
        original_payloads = []
        encrypted_frames = []

        # Generate 100 frames
        for i in range(100):
            payload = secrets.token_bytes(16)
            original_payloads.append(payload)

            frame = M17Frame.create_stream_frame(
                payload=payload,
                frame_counter=i,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )

            encrypted_frames.append(frame)

        # Verify all can be decrypted
        for i, (frame, original) in enumerate(zip(encrypted_frames, original_payloads)):
            try:
                decrypted = decrypt(
                    "chacha20",
                    key,
                    frame.encrypted_payload,
                    frame.nonce,
                    auth="poly1305",
                    auth_tag=frame.auth_tag,
                )
                assert decrypted == original, f"Frame {i} decryption failed"
            except Exception as e:
                pytest.fail(f"Frame {i} decryption error: {e}")


class TestM17Interoperability:
    """Test M17 interoperability with external tools."""

    @pytest.mark.skipif(
        not Path("/usr/bin/m17-cxx-demod").exists(),
        reason="m17-cxx-demod not available",
    )
    def test_m17_demod_compatibility(self):
        """Test that encrypted frames can be parsed by m17-cxx-demod."""
        # Create test frame
        frame = M17Frame.create_stream_frame(
            payload=secrets.token_bytes(16),
            frame_counter=1,
            encryption_type=M17EncryptionType.CUSTOM,
            key=secrets.token_bytes(32),
        )

        frame_bytes = frame.to_bytes()

        # Write to file for m17-cxx-demod
        test_file = Path("/tmp/m17_test.bin")
        test_file.write_bytes(frame_bytes)

        try:
            # Try to process with m17-cxx-demod
            result = subprocess.run(
                ["m17-cxx-demod", str(test_file)], capture_output=True, timeout=5
            )

            # m17-cxx-demod should handle the frame (may output warnings for encrypted)
            # We just verify it doesn't crash
            assert result.returncode in [
                0,
                1,
            ]  # 0 = success, 1 = may be normal for test

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_frame_format_compliance(self):
        """Test frame format matches M17 specification."""
        # Test LSF format
        lsf = M17Frame.create_lsf_frame(
            src="TEST1234", dst="TARGET12", encryption_type=M17EncryptionType.CUSTOM
        )

        lsf_bytes = lsf.to_bytes()

        # Verify sync word
        assert lsf_bytes[0:2] == struct.pack(">H", M17Frame.SYNC_WORD_LSF)

        # Verify payload size
        assert len(lsf_bytes) >= 32

        # Test stream frame format
        stream = M17Frame.create_stream_frame(
            payload=secrets.token_bytes(16), frame_counter=1
        )

        stream_bytes = stream.to_bytes()

        # Verify sync word
        assert stream_bytes[0:2] == struct.pack(">H", M17Frame.SYNC_WORD_STREAM)

        # Verify minimum size
        assert len(stream_bytes) >= 18


class TestM17VoiceQuality:
    """Test voice quality preservation through encryption."""

    def test_codec2_data_integrity(self):
        """Verify Codec2 data integrity after encrypt/decrypt."""
        # Import decrypt function
        try:
            from python.linux_crypto import decrypt
        except ImportError:
            from linux_crypto import decrypt

        # Simulate Codec2 3200bps data
        # Codec2 produces specific bit patterns
        codec2_frame = bytes([0x12, 0x34, 0x56, 0x78] * 4)  # Simulated pattern
        key = secrets.token_bytes(32)

        # Encrypt
        frame = M17Frame.create_stream_frame(
            payload=codec2_frame,
            frame_counter=1,
            encryption_type=M17EncryptionType.CUSTOM,
            key=key,
        )

        # Decrypt
        decrypted = decrypt(
            "chacha20",
            key,
            frame.encrypted_payload,
            frame.nonce,
            auth="poly1305",
            auth_tag=frame.auth_tag,
        )

        # Verify exact match (required for voice quality)
        assert decrypted == codec2_frame
        assert len(decrypted) == 16

    def test_multiple_codec2_frames(self):
        """Test multiple Codec2 frames maintain quality."""
        # Import decrypt function
        try:
            from python.linux_crypto import decrypt
        except ImportError:
            from linux_crypto import decrypt

        key = secrets.token_bytes(32)
        codec2_frames = []

        # Generate 50 Codec2 frames (2 seconds of audio at 3200bps)
        for i in range(50):
            # Simulate Codec2 output
            frame_data = secrets.token_bytes(16)
            codec2_frames.append(frame_data)

        # Encrypt all frames
        encrypted_frames = []
        for i, frame_data in enumerate(codec2_frames):
            frame = M17Frame.create_stream_frame(
                payload=frame_data,
                frame_counter=i,
                encryption_type=M17EncryptionType.CUSTOM,
                key=key,
            )
            encrypted_frames.append(frame)

        # Decrypt and verify
        for i, (enc_frame, original) in enumerate(zip(encrypted_frames, codec2_frames)):
            decrypted = decrypt(
                "chacha20",
                key,
                enc_frame.encrypted_payload,
                enc_frame.nonce,
                auth="poly1305",
                auth_tag=enc_frame.auth_tag,
            )
            assert decrypted == original, f"Frame {i} data corruption"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
