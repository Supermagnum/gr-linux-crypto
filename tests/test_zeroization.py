# -*- coding: utf-8 -*-
"""
Tests for key zeroization (Component 4): secure_zero and key lifecycle.

Verifies that secure_zero correctly clears Python bytearray and that
key material is not left in buffers after use.
"""

import pytest

from gr_linux_crypto import secure_zero


class TestSecureZero:
    """Test secure_zero() Python helper."""

    def test_secure_zero_clears_bytearray(self):
        data = bytearray(b"secret key material here")
        secure_zero(data)
        assert data == bytearray(len(data))
        assert all(b == 0 for b in data)

    def test_secure_zero_empty_bytearray(self):
        data = bytearray()
        secure_zero(data)
        assert data == bytearray()

    def test_secure_zero_rejects_bytes(self):
        with pytest.raises(TypeError, match="bytearray"):
            secure_zero(b"immutable")

    def test_secure_zero_rejects_non_buffer(self):
        with pytest.raises(TypeError, match="bytearray"):
            secure_zero([1, 2, 3])

    def test_secure_zero_length_unchanged(self):
        data = bytearray(32)
        data[0] = 0xFF
        secure_zero(data)
        assert len(data) == 32
        assert all(b == 0 for b in data)
