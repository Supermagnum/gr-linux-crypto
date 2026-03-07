# -*- coding: utf-8 -*-
"""
OpenSSL FIPS provider status helper.

Returns provider status and certificate information when the module is built
with GR_LINUX_CRYPTO_FIPS=ON and the FIPS provider is available.
"""

import ctypes
from typing import Any, Dict, Optional


def fips_status() -> Dict[str, Any]:
    """
    Return OpenSSL FIPS provider status and certificate information.

    Uses ctypes to query libcrypto. When the FIPS provider is not available
    or the module was not built with FIPS support, returns a dict with
    fips_active=False and an optional error message.

    Returns:
        Dict with at least:
        - fips_active (bool): True if FIPS mode is enabled and active
        - provider_loaded (bool): True if the FIPS provider loaded successfully
        - openssl_version (str): OpenSSL version string if available
        - certificate_info (str or None): FIPS certificate/validation info if available
        - error (str or None): Error message if status could not be determined
    """
    result: Dict[str, Any] = {
        "fips_active": False,
        "provider_loaded": False,
        "openssl_version": None,
        "certificate_info": None,
        "error": None,
    }
    try:
        libcrypto = _load_libcrypto()
        if libcrypto is None:
            result["error"] = "libcrypto not found"
            return result
        version = _get_openssl_version(libcrypto)
        if version:
            result["openssl_version"] = version
        # OpenSSL 3.x: load FIPS provider and enable FIPS mode
        try:
            OSSL_PROVIDER_load = getattr(libcrypto, "OSSL_PROVIDER_load", None)
            OSSL_PROVIDER_unload = getattr(libcrypto, "OSSL_PROVIDER_unload", None)
            EVP_default_properties_enable_fips = getattr(
                libcrypto, "EVP_default_properties_enable_fips", None
            )
            EVP_default_properties_is_fips_enabled = getattr(
                libcrypto, "EVP_default_properties_is_fips_enabled", None
            )
        except AttributeError:
            result["error"] = "OpenSSL 3 FIPS API not found"
            return result
        if (
            OSSL_PROVIDER_load is None
            or EVP_default_properties_enable_fips is None
        ):
            result["error"] = "OpenSSL 3 provider API not available"
            return result
        # OSSL_PROVIDER_load(ctx, name) - ctx is void* (NULL)
        OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        OSSL_PROVIDER_load.restype = ctypes.c_void_p
        EVP_default_properties_enable_fips.argtypes = [ctypes.c_void_p, ctypes.c_int]
        EVP_default_properties_enable_fips.restype = ctypes.c_int
        provider = OSSL_PROVIDER_load(None, b"fips")
        if provider is None or provider == 0:
            result["error"] = "FIPS provider could not be loaded"
            return result
        result["provider_loaded"] = True
        if EVP_default_properties_enable_fips(None, 1) != 1:
            if OSSL_PROVIDER_unload:
                OSSL_PROVIDER_unload.argtypes = [ctypes.c_void_p]
                OSSL_PROVIDER_unload.restype = ctypes.c_int
                OSSL_PROVIDER_unload(provider)
            result["error"] = "FIPS mode could not be enabled"
            return result
        if EVP_default_properties_is_fips_enabled:
            EVP_default_properties_is_fips_enabled.argtypes = [ctypes.c_void_p]
            EVP_default_properties_is_fips_enabled.restype = ctypes.c_int
            result["fips_active"] = (
                EVP_default_properties_is_fips_enabled(None) == 1
            )
        else:
            result["fips_active"] = True
        # Certificate info: FIPS 140-2/3 validation; OpenSSL does not expose
        # this easily via a single API; document that it comes from the build
        result["certificate_info"] = (
            "FIPS provider loaded; validation status depends on OpenSSL build. "
            "See OpenSSL FIPS documentation and your distribution."
        )
        return result
    except Exception as e:  # pylint: disable=broad-except
        result["error"] = str(e)
        return result


def _load_libcrypto() -> Optional[Any]:
    for name in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    return None


def _get_openssl_version(libcrypto: Any) -> Optional[str]:
    OpenSSL_version = getattr(libcrypto, "OpenSSL_version", None) or getattr(
        libcrypto, "SSLeay_version", None
    )
    if OpenSSL_version is None:
        return None
    OpenSSL_version.argtypes = [ctypes.c_int]
    OpenSSL_version.restype = ctypes.c_char_p
    # OPENSSL_VERSION (0)
    try:
        return OpenSSL_version(0).decode("utf-8", errors="replace")
    except Exception:  # pylint: disable=broad-except
        return None
