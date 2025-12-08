# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Python Module Wrapper

This module imports the pybind11 bindings and exposes them as gnuradio.linux_crypto
"""

# Import GNU Radio base classes first to ensure types are registered
# This must happen before importing the pybind11 module
try:
    import gnuradio.gr  # noqa: F401
except ImportError:
    pass  # Will fail later if GNU Radio is not available

# Try to import the pybind11 module
# If linking issues occur (undefined symbols), fall back to Python implementation
_CPP_MODULE_AVAILABLE = False
_LINKING_ERROR = None

try:
    # Import the compiled pybind11 module
    import linux_crypto_python

    _CPP_MODULE_AVAILABLE = True

    # Expose all the classes and functions from the pybind11 module
    kernel_keyring_source = linux_crypto_python.kernel_keyring_source
    nitrokey_interface = linux_crypto_python.nitrokey_interface
    kernel_crypto_aes = linux_crypto_python.kernel_crypto_aes

    # Expose ECIES blocks if available (requires OpenSSL)
    if hasattr(linux_crypto_python, "brainpool_ecies_encrypt"):
        brainpool_ecies_encrypt = linux_crypto_python.brainpool_ecies_encrypt
    if hasattr(linux_crypto_python, "brainpool_ecies_decrypt"):
        brainpool_ecies_decrypt = linux_crypto_python.brainpool_ecies_decrypt
    if hasattr(linux_crypto_python, "brainpool_ecies_multi_encrypt"):
        brainpool_ecies_multi_encrypt = (
            linux_crypto_python.brainpool_ecies_multi_encrypt
        )
    if hasattr(linux_crypto_python, "brainpool_ecies_multi_decrypt"):
        brainpool_ecies_multi_decrypt = (
            linux_crypto_python.brainpool_ecies_multi_decrypt
        )

    # Expose any module-level functions
    if hasattr(linux_crypto_python, "get_integration_status"):
        get_integration_status = linux_crypto_python.get_integration_status

    # Build __all__ list dynamically
    __all__ = ["kernel_keyring_source", "nitrokey_interface", "kernel_crypto_aes"]
    if hasattr(linux_crypto_python, "brainpool_ecies_encrypt"):
        __all__.extend(["brainpool_ecies_encrypt", "brainpool_ecies_decrypt"])
    if hasattr(linux_crypto_python, "brainpool_ecies_multi_encrypt"):
        __all__.extend(
            ["brainpool_ecies_multi_encrypt", "brainpool_ecies_multi_decrypt"]
        )

except ImportError as e:
    error_msg = str(e)
    _LINKING_ERROR = error_msg

    # Check if this is a linking issue (undefined symbol or unknown base type)
    is_linking_error = (
        "undefined symbol" in error_msg.lower()
        or "unknown base type" in error_msg.lower()
        or "gr::block" in error_msg
        or "gr::sync_block" in error_msg
    )

    if is_linking_error:
        # Detected linking issue - provide clear error message
        import warnings

        warnings.warn(
            f"gr-linux-crypto: Detected linking issues (undefined symbol error)\n"
            f"Error: {error_msg}\n"
            f"\n"
            f"The C++ module cannot be loaded due to missing symbols.\n"
            f"This usually means:\n"
            f"  1. The module needs to be rebuilt with proper library linking\n"
            f"  2. GNU Radio libraries are not properly linked\n"
            f"  3. The module was built against a different GNU Radio version\n"
            f"\n"
            f"Falling back to Python implementation.\n"
            f"To fix: Rebuild and reinstall the module from the build directory.",
            ImportWarning,
            stacklevel=2,
        )

        # Fall back to Python implementation
        # Python implementations are available via direct import:
        # from python.multi_recipient_ecies import MultiRecipientECIES
        # from python.callsign_key_store import CallsignKeyStore

        # Set flag for other code to check
        _CPP_MODULE_AVAILABLE = False

        # Build minimal __all__ for Python fallback
        __all__ = []
    else:
        # Other import error (not linking-related)
        raise ImportError(
            f"Failed to import linux_crypto_python module: {e}\n"
            "Make sure the module is built and installed correctly.\n"
            "Run 'sudo make install' from the build directory."
        ) from e


# Export availability flag
def is_cpp_module_available():
    """Check if C++ module is available (not just Python fallback)"""
    return _CPP_MODULE_AVAILABLE


def get_linking_error():
    """Get the linking error message if C++ module failed to load"""
    return _LINKING_ERROR
