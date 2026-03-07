# -*- coding: utf-8 -*-
"""
Tests for post-quantum hybrid KEM (Component 2).

When GR_LINUX_CRYPTO_PQ_KEM=ON and oqs-provider is available, hybrid_kem_encapsulate
and hybrid_kem_decapsulate are implemented. Otherwise they raise NotImplementedError.
"""

import pytest

from gr_linux_crypto import CryptoHelpers


class TestHybridKemStub:
    """Test hybrid KEM API when not built with PQ_KEM (stub raises)."""

    def test_hybrid_kem_encapsulate_raises_without_pq_build(self):
        with pytest.raises(NotImplementedError, match="GR_LINUX_CRYPTO_PQ_KEM"):
            CryptoHelpers.hybrid_kem_encapsulate(b"-----BEGIN PUBLIC KEY-----", curve="brainpoolP384r1")

    def test_hybrid_kem_decapsulate_raises_without_pq_build(self):
        with pytest.raises(NotImplementedError, match="GR_LINUX_CRYPTO_PQ_KEM"):
            CryptoHelpers.hybrid_kem_decapsulate(b"fake_ct", b"-----BEGIN PRIVATE KEY-----", curve="brainpoolP384r1")
