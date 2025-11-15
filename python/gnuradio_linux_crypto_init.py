# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Python Module Wrapper

This module imports the pybind11 bindings and exposes them as gnuradio.linux_crypto
"""

# Try to import the pybind11 module
try:
    # Import the compiled pybind11 module
    import linux_crypto_python

    # Expose all the classes and functions from the pybind11 module
    kernel_keyring_source = linux_crypto_python.kernel_keyring_source
    nitrokey_interface = linux_crypto_python.nitrokey_interface
    kernel_crypto_aes = linux_crypto_python.kernel_crypto_aes

    # Expose any module-level functions
    if hasattr(linux_crypto_python, "get_integration_status"):
        get_integration_status = linux_crypto_python.get_integration_status

    __all__ = ["kernel_keyring_source", "nitrokey_interface", "kernel_crypto_aes"]

except ImportError as e:
    # If pybind11 module not found, provide helpful error
    raise ImportError(
        f"Failed to import linux_crypto_python module: {e}\n"
        "Make sure the module is built and installed correctly.\n"
        "Run 'sudo make install' from the build directory."
    ) from e
