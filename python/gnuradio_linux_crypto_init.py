# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Python Module Wrapper

This module imports the pybind11 bindings and exposes them as gnuradio.linux_crypto
"""

# Import GNU Radio base classes first to ensure types are registered
# This must happen before importing the pybind11 module
try:
    from gnuradio import gr
except ImportError:
    pass  # Will fail later if GNU Radio is not available

# Try to import the pybind11 module
try:
    # Import the compiled pybind11 module
    import linux_crypto_python

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
        brainpool_ecies_multi_encrypt = linux_crypto_python.brainpool_ecies_multi_encrypt
    if hasattr(linux_crypto_python, "brainpool_ecies_multi_decrypt"):
        brainpool_ecies_multi_decrypt = linux_crypto_python.brainpool_ecies_multi_decrypt

    # Expose any module-level functions
    if hasattr(linux_crypto_python, "get_integration_status"):
        get_integration_status = linux_crypto_python.get_integration_status

    # Build __all__ list dynamically
    __all__ = ["kernel_keyring_source", "nitrokey_interface", "kernel_crypto_aes"]
    if hasattr(linux_crypto_python, "brainpool_ecies_encrypt"):
        __all__.extend(["brainpool_ecies_encrypt", "brainpool_ecies_decrypt"])
    if hasattr(linux_crypto_python, "brainpool_ecies_multi_encrypt"):
        __all__.extend(["brainpool_ecies_multi_encrypt", "brainpool_ecies_multi_decrypt"])

except ImportError as e:
    # If pybind11 module not found, provide helpful error
    raise ImportError(
        f"Failed to import linux_crypto_python module: {e}\n"
        "Make sure the module is built and installed correctly.\n"
        "Run 'sudo make install' from the build directory."
    ) from e
