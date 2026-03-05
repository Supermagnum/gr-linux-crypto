#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Public key store for radio amateur callsigns.

Provides a simple interface for storing and retrieving public keys
associated with radio amateur callsigns. Uses the kernel keyring
for secure storage when available, with file-based fallback.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

try:
    from .keyring_helper import KeyringHelper

    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False


class CallsignKeyStore:
    """
    Key store for mapping radio amateur callsigns to public keys.

    Supports both kernel keyring storage (preferred) and file-based
    storage (fallback). Keys are stored in PEM format.

    When generating keys (e.g. with GnuPG or on Nitrokey), use the callsign
    as the key's name or as the comment so the same callsign is used when
    adding keys here and in the keyring (callsign:CALLSIGN).

    Key groups (add_group, get_group, list_groups, remove_group) let you
    define named groups of callsigns in the JSON file. The multi-recipient
    encrypt block expands a group name in **callsigns** to all members.
    """

    def __init__(self, store_path: Optional[str] = None, use_keyring: bool = True):
        """
        Initialize the callsign key store.

        Args:
            store_path: Path to file-based store (default: ~/.gnuradio/callsign_keys.json)
            use_keyring: Whether to use kernel keyring (default: True)
        """
        self.use_keyring = use_keyring and KEYRING_AVAILABLE
        self.keyring_helper = None

        if self.use_keyring:
            try:
                self.keyring_helper = KeyringHelper()
            except Exception:
                self.use_keyring = False

        if store_path is None:
            default_dir = Path.home() / ".gnuradio"
            default_dir.mkdir(parents=True, exist_ok=True)
            store_path = str(default_dir / "callsign_keys.json")

        self.store_path = store_path
        self._cache: Dict[str, str] = {}
        self._groups: Dict[str, List[str]] = {}
        self._load_from_file()

    def _load_from_file(self):
        """Load keys and groups from file-based store."""
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "r") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self._cache = {}
                    self._groups = {}
                    for k, v in data.items():
                        if isinstance(v, list):
                            self._groups[k] = [str(x).upper().strip() for x in v]
                        else:
                            self._cache[k] = str(v)
                else:
                    self._cache = {}
                    self._groups = {}
            except Exception:
                self._cache = {}
                self._groups = {}
        else:
            self._cache = {}
            self._groups = {}

    def _save_to_file(self):
        """Save keys and groups to file-based store."""
        try:
            os.makedirs(os.path.dirname(self.store_path) or ".", exist_ok=True)
            merged = dict(self._cache)
            merged.update(self._groups)
            with open(self.store_path, "w") as f:
                json.dump(merged, f, indent=2)
        except Exception:
            pass

    def add_public_key(self, callsign: str, public_key_pem: str) -> bool:
        """
        Add a public key for a callsign.

        Args:
            callsign: Radio amateur callsign (e.g., "W1ABC")
            public_key_pem: Public key in PEM format

        Returns:
            True if successful, False otherwise
        """
        callsign = callsign.upper().strip()

        if not callsign or len(callsign) > 14:
            return False

        if self.use_keyring and self.keyring_helper:
            try:
                key_description = f"callsign:{callsign}"
                self.keyring_helper.add_key(
                    "user", key_description, public_key_pem.encode("utf-8")
                )
            except Exception:
                pass

        self._cache[callsign] = public_key_pem
        self._save_to_file()
        return True

    def add_keygrip(self, callsign: str, keygrip: str) -> bool:
        """
        Add a keygrip for a callsign (hardware key on OpenPGP Card / Nitrokey).

        The multi-recipient encrypt block will fetch the public key from the
        device when it sees a 40-character hex keygrip. Use this when the
        recipient's key is on a hardware device (multiple keys per device
        are supported by storing one keygrip per callsign).

        Args:
            callsign: Radio amateur callsign (e.g., "W1ABC")
            keygrip: 40-character hex keygrip (e.g. from gpg --list-secret-keys --with-keygrip)

        Returns:
            True if successful, False otherwise
        """
        callsign = callsign.upper().strip()
        keygrip = keygrip.strip().replace(" ", "").lower()
        if len(keygrip) != 40 or not all(c in "0123456789abcdef" for c in keygrip):
            return False
        if not callsign or len(callsign) > 14:
            return False

        if self.use_keyring and self.keyring_helper:
            try:
                key_description = f"callsign:{callsign}"
                self.keyring_helper.add_key(
                    "user", key_description, keygrip.encode("ascii")
                )
            except Exception:
                pass

        self._cache[callsign] = keygrip
        self._save_to_file()
        return True

    def get_public_key(self, callsign: str) -> Optional[str]:
        """
        Get public key for a callsign.

        Args:
            callsign: Radio amateur callsign (e.g., "W1ABC")

        Returns:
            Public key in PEM format, or None if not found
        """
        callsign = callsign.upper().strip()

        if self.use_keyring and self.keyring_helper:
            try:
                key_description = f"callsign:{callsign}"
                key_id = self.keyring_helper.search_key("user", key_description)
                if key_id:
                    key_data = self.keyring_helper.read_key(key_id)
                    return key_data.decode("utf-8")
            except Exception:
                pass

        return self._cache.get(callsign)

    def remove_public_key(self, callsign: str) -> bool:
        """
        Remove a public key for a callsign.

        Args:
            callsign: Radio amateur callsign

        Returns:
            True if successful, False otherwise
        """
        callsign = callsign.upper().strip()

        if self.use_keyring and self.keyring_helper:
            try:
                key_description = f"callsign:{callsign}"
                key_id = self.keyring_helper.search_key("user", key_description)
                if key_id:
                    self.keyring_helper.unlink_key(key_id)
            except Exception:
                pass

        if callsign in self._cache:
            del self._cache[callsign]
            self._save_to_file()
            return True

        return False

    def add_group(self, group_name: str, callsigns: List[str]) -> bool:
        """
        Add or replace a key group: a named list of callsigns.

        The multi-recipient encrypt block can use the group name in the
        **callsigns** parameter; it will be expanded to all members.
        Stored in the JSON file only (not in the keyring).

        Args:
            group_name: Name of the group (e.g. "net_control")
            callsigns: List of callsigns in the group (e.g. ["W1ABC", "K2XYZ"])

        Returns:
            True if successful, False otherwise
        """
        group_name = group_name.strip()
        if not group_name or len(group_name) > 32:
            return False
        normalized = [str(c).upper().strip() for c in callsigns if c and str(c).strip()]
        self._groups[group_name] = normalized
        self._save_to_file()
        return True

    def get_group(self, group_name: str) -> Optional[List[str]]:
        """
        Get the list of callsigns for a key group.

        Args:
            group_name: Name of the group

        Returns:
            List of callsigns, or None if the group does not exist
        """
        return self._groups.get(group_name.strip())

    def list_groups(self) -> List[str]:
        """
        List all key group names in the store.

        Returns:
            Sorted list of group names
        """
        return sorted(self._groups.keys())

    def remove_group(self, group_name: str) -> bool:
        """
        Remove a key group.

        Args:
            group_name: Name of the group

        Returns:
            True if the group existed and was removed, False otherwise
        """
        group_name = group_name.strip()
        if group_name in self._groups:
            del self._groups[group_name]
            self._save_to_file()
            return True
        return False

    def list_callsigns(self) -> list:
        """
        List all callsigns in the store (keys and keygrips, not group names).

        Returns:
            List of callsigns
        """
        callsigns = set(self._cache.keys())

        if self.use_keyring and self.keyring_helper:
            try:
                keys = self.keyring_helper.list_keys()
                for key in keys:
                    desc = key.get("description", "")
                    if desc.startswith("callsign:"):
                        callsign = desc.split(":", 1)[1]
                        callsigns.add(callsign.upper())
            except Exception:
                pass

        return sorted(list(callsigns))

    def has_callsign(self, callsign: str) -> bool:
        """
        Check if a callsign exists in the store.

        Args:
            callsign: Radio amateur callsign

        Returns:
            True if callsign exists, False otherwise
        """
        return self.get_public_key(callsign) is not None


def create_test_key_store() -> CallsignKeyStore:
    """
    Create a test key store for unit testing.

    Returns:
        CallsignKeyStore instance using temporary file
    """
    import tempfile

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_file.close()
    return CallsignKeyStore(store_path=temp_file.name, use_keyring=False)


if __name__ == "__main__":
    store = CallsignKeyStore()

    print("Callsign Key Store Test")
    print("=" * 50)

    test_callsign = "W1ABC"
    test_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
-----END PUBLIC KEY-----"""

    print(f"Adding key for {test_callsign}")
    store.add_public_key(test_callsign, test_key)

    print(f"Retrieving key for {test_callsign}")
    retrieved = store.get_public_key(test_callsign)
    print(f"Found: {retrieved is not None}")

    print(f"Listing callsigns: {store.list_callsigns()}")
