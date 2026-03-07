# -*- coding: utf-8 -*-
"""
Tests for OpenSSL FIPS provider mode (Component 1).

When GR_LINUX_CRYPTO_FIPS=ON, the FIPS provider is loaded at module init.
These tests verify fips_status() and that FIPS-related behavior is consistent.
"""

import pytest

from gr_linux_crypto import fips_status


class TestFipsStatus:
    """Test fips_status() helper."""

    def test_fips_status_returns_dict(self):
        status = fips_status()
        assert isinstance(status, dict)
        assert "fips_active" in status
        assert "provider_loaded" in status
        assert "openssl_version" in status
        assert "certificate_info" in status or "error" in status

    def test_fips_status_fips_active_is_bool(self):
        status = fips_status()
        assert isinstance(status["fips_active"], bool)

    def test_fips_status_provider_loaded_is_bool(self):
        status = fips_status()
        assert isinstance(status["provider_loaded"], bool)

    def test_fips_status_openssl_version_string_or_none(self):
        status = fips_status()
        v = status.get("openssl_version")
        assert v is None or isinstance(v, str)

    def test_fips_status_error_string_or_none(self):
        status = fips_status()
        e = status.get("error")
        assert e is None or isinstance(e, str)

    def test_fips_status_when_provider_loaded_fips_active_consistent(self):
        status = fips_status()
        if status["provider_loaded"] and status.get("error") is None:
            assert status["fips_active"] is True
