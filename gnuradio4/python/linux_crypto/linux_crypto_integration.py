#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GNU Radio Linux Crypto Integration Helpers

This module provides integration utilities for gr-linux-crypto with
existing GNU Radio crypto modules (gr-openssl, gr-nacl).

The focus is on providing Linux-specific key sources and hardware
security module integration that complements existing crypto modules
rather than duplicating their functionality.
"""

import subprocess
import time
from typing import Any, Dict, List, Optional

# GNU Radio imports
try:
    from gnuradio import blocks, gr, linux_crypto
except ImportError:
    print("Warning: GNU Radio not available. Some functions may not work.")
    gr = None
    blocks = None
    linux_crypto = None

# Optional imports for integration
try:
    from gnuradio import crypto

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    crypto = None

try:
    from gnuradio import nacl

    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    nacl = None


class KernelKeyringManager:
    """
    Manager for Linux kernel keyring operations.

    This class provides a high-level interface for managing keys
    in the Linux kernel keyring, which can then be used with
    existing crypto modules.
    """

    def __init__(self):
        self._keys = {}
        self._keyring_id = None

    def add_key(
        self, key_name: str, key_data: bytes, key_type: str = "user"
    ) -> Optional[int]:
        """
        Add a key to the kernel keyring.

        Args:
            key_name: Name/description of the key
            key_data: The key data
            key_type: Type of key (user, logon, keyring, big_key)

        Returns:
            Key ID if successful, None if failed
        """
        try:
            # Use keyctl to add the key
            result = subprocess.run(
                ["keyctl", "add", key_type, key_name, key_data.decode("latin-1"), "@u"],
                capture_output=True,
                text=True,
                check=True,
            )

            key_id = int(result.stdout.strip())
            self._keys[key_name] = key_id
            return key_id

        except subprocess.CalledProcessError as e:
            print(f"Failed to add key '{key_name}': {e}")
            return None
        except ValueError:
            print(f"Invalid key ID returned for '{key_name}'")
            return None

    def get_key(self, key_name: str) -> Optional[bytes]:
        """
        Get key data from the kernel keyring.

        Args:
            key_name: Name of the key to retrieve

        Returns:
            Key data if found, None if not found
        """
        if key_name not in self._keys:
            return None

        try:
            key_id = self._keys[key_name]
            result = subprocess.run(
                ["keyctl", "pipe", str(key_id)], capture_output=True, check=True
            )

            return result.stdout

        except subprocess.CalledProcessError:
            return None

    def delete_key(self, key_name: str) -> bool:
        """
        Delete a key from the kernel keyring.

        Args:
            key_name: Name of the key to delete

        Returns:
            True if successful, False if failed
        """
        if key_name not in self._keys:
            return False

        try:
            key_id = self._keys[key_name]
            subprocess.run(
                ["keyctl", "unlink", str(key_id), "@u"], capture_output=True, check=True
            )

            del self._keys[key_name]
            return True

        except subprocess.CalledProcessError:
            return False

    def list_keys(self) -> List[str]:
        """
        List all keys in the keyring.

        Returns:
            List of key names
        """
        return list(self._keys.keys())

    def clear_all_keys(self) -> bool:
        """
        Clear all keys from the keyring.

        Returns:
            True if successful, False if failed
        """
        try:
            subprocess.run(["keyctl", "clear", "@u"], capture_output=True, check=True)
            self._keys.clear()
            return True
        except subprocess.CalledProcessError:
            return False


class NitrokeyManager:
    """
    Manager for Nitrokey hardware security module operations.

    This class provides a high-level interface for Nitrokey devices,
    which can then be used with existing crypto modules.

    Uses the real C++ nitrokey_interface block for device communication.
    """

    def __init__(self):
        self._device = None
        self._available = False
        self._nitrokey_block = None
        self._cached_slots = None

    def connect(self) -> bool:
        """
        Connect to Nitrokey device.

        Returns:
            True if connected successfully, False otherwise
        """
        if linux_crypto is None:
            print("GNU Radio linux_crypto module not available")
            return False

        try:
            # Create a nitrokey_interface block to check availability
            # Use slot 0 as a test - we'll check if device is available
            self._nitrokey_block = linux_crypto.nitrokey_interface(
                slot=0, auto_repeat=False
            )

            # Check if Nitrokey is available
            self._available = self._nitrokey_block.is_nitrokey_available()

            if self._available:
                self._device = self._nitrokey_block.get_device_info()
            else:
                self._device = "Nitrokey not available"
                self._nitrokey_block = None

            return self._available

        except Exception as e:
            print(f"Failed to connect to Nitrokey: {e}")
            self._available = False
            self._device = "Nitrokey connection failed"
            self._nitrokey_block = None
            return False

    def is_available(self) -> bool:
        """
        Check if Nitrokey is available.

        Returns:
            True if Nitrokey is available, False otherwise
        """
        if self._nitrokey_block is None:
            return False

        # Re-check availability in case device was disconnected
        try:
            self._available = self._nitrokey_block.is_nitrokey_available()
            if not self._available:
                self._nitrokey_block = None
        except Exception:
            self._available = False
            self._nitrokey_block = None

        return self._available

    def get_device_info(self) -> str:
        """
        Get device information.

        Returns:
            Device information string
        """
        if not self.is_available() or self._nitrokey_block is None:
            return "Nitrokey not available"

        try:
            return self._nitrokey_block.get_device_info()
        except Exception:
            return "Nitrokey not available"

    def get_available_slots(self) -> List[int]:
        """
        Get available slots on the device that contain data.

        Returns:
            List of available slot numbers that contain keys
        """
        if not self.is_available() or self._nitrokey_block is None:
            return []

        try:
            # Get available slots from the block
            slots = self._nitrokey_block.get_available_slots()
            self._cached_slots = slots
            return slots
        except Exception as e:
            print(f"Error getting available slots: {e}")
            return []

    def load_key_from_slot(self, slot: int) -> Optional[bytes]:
        """
        Load key from a specific slot.

        Args:
            slot: Slot number to load from (0-15)

        Returns:
            Key data if successful, None if failed
        """
        if not self.is_available() or linux_crypto is None or gr is None:
            return None

        if slot < 0 or slot > 15:
            return None

        try:
            # Create a nitrokey_interface block for the specific slot
            # Use auto_repeat=False to get the key data exactly once
            nitrokey_block = linux_crypto.nitrokey_interface(
                slot=slot, auto_repeat=False
            )

            # Check if key is loaded
            if not nitrokey_block.is_key_loaded():
                return None

            key_size = nitrokey_block.get_key_size()
            if key_size == 0:
                return None

            # Create a flowgraph to read the key data
            # Use a vector sink to collect the output
            tb = gr.top_block()
            sink = blocks.vector_sink_b()

            tb.connect(nitrokey_block, sink)

            # Run the flowgraph to read exactly key_size bytes
            # With auto_repeat=False, the block outputs key once then zeros
            # We need to read exactly key_size bytes
            tb.start()

            # Keep running until we have at least key_size bytes
            max_wait = 1.0  # Maximum wait time in seconds
            start_time = time.time()
            while len(sink.data()) < key_size and (time.time() - start_time) < max_wait:
                time.sleep(0.01)  # Small delay to allow data flow

            tb.stop()
            tb.wait()  # Wait for cleanup

            # Get the key data from the sink
            key_data = bytes(sink.data())

            # Extract exactly key_size bytes (ignore any trailing zeros)
            if len(key_data) >= key_size:
                key_data = key_data[:key_size]
            elif len(key_data) == 0:
                # No data received
                return None
            # If we got less than key_size, return what we have (might be partial)

            return key_data if key_data else None

        except Exception as e:
            print(f"Error loading key from slot {slot}: {e}")
            return None

    def store_key_to_slot(self, slot: int, key_data: bytes) -> bool:
        """
        Store key to a specific slot.

        Note: This requires password safe to be enabled and authentication.
        The nitrokey_interface block is read-only. To write keys, use:
        - Nitrokey App (GUI)
        - libnitrokey C++ API directly
        - Nitrokey CLI tools

        Args:
            slot: Slot number to store to (0-15)
            key_data: Key data to store

        Returns:
            False - write operations not supported via this interface
        """
        # The nitrokey_interface block is read-only
        # Writing requires libnitrokey API or Nitrokey App
        print("store_key_to_slot() is not supported via nitrokey_interface block.")
        print(
            "Use Nitrokey App or libnitrokey C++ API to write keys to password safe slots."
        )
        return False


class CryptoIntegration:
    """
    Integration layer between gr-linux-crypto and existing crypto modules.

    This class provides utilities for integrating Linux-specific
    key sources with existing GNU Radio crypto modules.
    """

    def __init__(self):
        self.keyring_manager = KernelKeyringManager()
        self.nitrokey_manager = NitrokeyManager()

    def create_keyring_to_openssl_flowgraph(
        self, key_name: str, cipher_desc_params: Dict[str, Any]
    ) -> Optional[gr.top_block]:
        """
        Create a flowgraph that uses kernel keyring keys with gr-openssl.

        Args:
            key_name: Name of the key in kernel keyring
            cipher_desc_params: Parameters for gr-openssl cipher descriptor

        Returns:
            GNU Radio top block if successful, None if failed
        """
        if not CRYPTO_AVAILABLE:
            print("gr-openssl not available")
            return None

        if gr is None:
            print("GNU Radio not available")
            return None

        # Get key from keyring
        key_data = self.keyring_manager.get_key(key_name)
        if key_data is None:
            print(f"Key '{key_name}' not found in keyring")
            return None

        # Create flowgraph
        tb = gr.top_block()

        # Create kernel keyring source
        key_source = linux_crypto.kernel_keyring_source(
            self.keyring_manager._keys[key_name], auto_repeat=True
        )

        # Create OpenSSL cipher descriptor
        cipher_desc = crypto.sym_ciph_desc(
            cipher_desc_params.get("cipher", "aes-256-cbc"),
            key_data,
            cipher_desc_params.get("iv", b""),
        )

        # Create OpenSSL encryptor
        encryptor = crypto.sym_enc(cipher_desc)

        # Create file sink
        output_sink = blocks.file_sink(gr.sizeof_char, "keyring_encrypted_output.bin")

        # Connect flowgraph
        tb.connect(key_source, encryptor)
        tb.connect(encryptor, output_sink)

        return tb

    def create_nitrokey_to_nacl_flowgraph(self, slot: int) -> Optional[gr.top_block]:
        """
        Create a flowgraph that uses Nitrokey keys with gr-nacl.

        Args:
            slot: Nitrokey slot number

        Returns:
            GNU Radio top block if successful, None if failed
        """
        if not NACL_AVAILABLE:
            print("gr-nacl not available")
            return None

        if gr is None:
            print("GNU Radio not available")
            return None

        # Connect to Nitrokey
        if not self.nitrokey_manager.connect():
            print("Failed to connect to Nitrokey")
            return None

        # Load key from Nitrokey
        key_data = self.nitrokey_manager.load_key_from_slot(slot)
        if key_data is None:
            print(f"Failed to load key from slot {slot}")
            return None

        # Create flowgraph
        tb = gr.top_block()

        # Create Nitrokey interface
        nitrokey_source = linux_crypto.nitrokey_interface(slot, auto_repeat=True)

        # Create NaCl encryptor
        encryptor = nacl.encrypt_secret("nitrokey_key")

        # Create file sink
        output_sink = blocks.file_sink(gr.sizeof_char, "nitrokey_encrypted_output.bin")

        # Connect flowgraph
        tb.connect(nitrokey_source, encryptor)
        tb.connect(encryptor, output_sink)

        return tb

    def get_integration_status(self) -> Dict[str, bool]:
        """
        Get the status of available integrations.

        Returns:
            Dictionary with integration status
        """
        return {
            "gnuradio_available": gr is not None,
            "gr_openssl_available": CRYPTO_AVAILABLE,
            "gr_nacl_available": NACL_AVAILABLE,
            "gr_linux_crypto_available": linux_crypto is not None,
            "keyring_available": self.keyring_manager is not None,
            "nitrokey_available": self.nitrokey_manager.is_available(),
        }


def demonstrate_integration():
    """
    Demonstrate the integration capabilities.
    """
    print("=== GNU Radio Linux Crypto Integration Demo ===")
    print()

    # Create integration instance
    integration = CryptoIntegration()

    # Show integration status
    status = integration.get_integration_status()
    print("Integration Status:")
    for component, available in status.items():
        status_str = "[OK]" if available else "[FAIL]"
        print(f"  {status_str} {component}")
    print()

    # Demonstrate keyring operations
    print("Demonstrating kernel keyring operations...")
    keyring = integration.keyring_manager

    # Add a test key
    test_key = b"This is a test key for integration"
    key_id = keyring.add_key("test_integration_key", test_key)
    if key_id:
        print(f"[OK] Added key to kernel keyring with ID: {key_id}")

        # Retrieve the key
        retrieved_key = keyring.get_key("test_integration_key")
        if retrieved_key:
            print(f"[OK] Retrieved key from kernel keyring: {len(retrieved_key)} bytes")
        else:
            print("[FAIL] Failed to retrieve key from kernel keyring")

        # Clean up
        if keyring.delete_key("test_integration_key"):
            print("[OK] Cleaned up key from kernel keyring")
        else:
            print("[FAIL] Failed to clean up key from kernel keyring")
    else:
        print("[FAIL] Failed to add key to kernel keyring")

    print()

    # Demonstrate Nitrokey operations
    print("Demonstrating Nitrokey operations...")
    nitrokey = integration.nitrokey_manager

    if nitrokey.connect():
        print("[OK] Connected to Nitrokey device")
        print(f"  Device info: {nitrokey.get_device_info()}")

        available_slots = nitrokey.get_available_slots()
        print(f"  Available slots: {available_slots}")

        if available_slots:
            test_slot = available_slots[0]
            key_data = nitrokey.load_key_from_slot(test_slot)
            if key_data:
                print(f"[OK] Loaded key from slot {test_slot}: {len(key_data)} bytes")
            else:
                print(f"[FAIL] Failed to load key from slot {test_slot}")
    else:
        print("[FAIL] Failed to connect to Nitrokey device")

    print()
    print("Integration demonstration completed!")


if __name__ == "__main__":
    demonstrate_integration()
