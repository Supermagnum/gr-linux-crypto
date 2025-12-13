#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick validation script for multi-recipient ECIES.

Tests basic functionality to ensure implementation is working.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from python.callsign_key_store import CallsignKeyStore
    from python.crypto_helpers import CryptoHelpers
    from python.multi_recipient_ecies import MultiRecipientECIES
except ImportError:
    try:
        from gr_linux_crypto.callsign_key_store import CallsignKeyStore
        from gr_linux_crypto.crypto_helpers import CryptoHelpers
        from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
    except ImportError:
        print("Error: Could not import required modules")
        sys.exit(1)


def main():
    """Run basic validation tests."""
    print("Multi-Recipient ECIES Validation")
    print("=" * 50)

    crypto = CryptoHelpers()
    ecies = MultiRecipientECIES(curve="brainpoolP256r1")

    fd, store_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    try:
        store = CallsignKeyStore(store_path=store_path)

        print("\n1. Generating test keys...")
        recipients = ["W1ABC", "K2XYZ", "N3DEF"]
        test_keys = {}

        for callsign in recipients:
            private_key, public_key = crypto.generate_brainpool_keypair(
                "brainpoolP256r1"
            )
            public_pem = crypto.serialize_brainpool_public_key(public_key)
            private_pem = crypto.serialize_brainpool_private_key(private_key)

            store.add_key(callsign, public_pem.decode("utf-8"))
            test_keys[callsign] = private_pem.decode("utf-8")
            print(f"   Generated keys for {callsign}")

        print("\n2. Testing encryption...")
        plaintext = b"Hello, multi-recipient ECIES!"
        encrypted = ecies.encrypt(plaintext, recipients, store)
        print(f"   Encrypted: {len(plaintext)} bytes -> {len(encrypted)} bytes")

        print("\n3. Testing decryption for each recipient...")
        for callsign in recipients:
            decrypted = ecies.decrypt(encrypted, callsign, test_keys[callsign])
            if decrypted == plaintext:
                print(f"   {callsign}: SUCCESS")
            else:
                print(f"   {callsign}: FAILED")
                return 1

        print("\n4. Testing all recipient counts (1-25)...")
        all_passed = True
        for num_recipients in range(1, 26):
            test_recipients = [f"W{i:02d}ABC" for i in range(1, num_recipients + 1)]

            for callsign in test_recipients:
                if not store.has_key(callsign):
                    private_key, public_key = crypto.generate_brainpool_keypair(
                        "brainpoolP256r1"
                    )
                    public_pem = crypto.serialize_brainpool_public_key(public_key)
                    private_pem = crypto.serialize_brainpool_private_key(private_key)
                    store.add_key(callsign, public_pem.decode("utf-8"))
                    test_keys[callsign] = private_pem.decode("utf-8")

            test_plaintext = f"Test for {num_recipients} recipients".encode("utf-8")
            test_encrypted = ecies.encrypt(test_plaintext, test_recipients, store)

            success_count = 0
            for callsign in test_recipients:
                try:
                    test_decrypted = ecies.decrypt(
                        test_encrypted, callsign, test_keys[callsign]
                    )
                    if test_decrypted == test_plaintext:
                        success_count += 1
                except Exception:
                    pass

            if success_count == num_recipients:
                if num_recipients % 5 == 0:
                    print(f"   {num_recipients} recipients: OK")
            else:
                print(
                    f"   {num_recipients} recipients: FAILED ({success_count}/{num_recipients})"
                )
                all_passed = False

        if all_passed:
            print("\n" + "=" * 50)
            print("All validation tests PASSED")
            print("=" * 50)
            return 0
        else:
            print("\n" + "=" * 50)
            print("Some validation tests FAILED")
            print("=" * 50)
            return 1

    finally:
        if os.path.exists(store_path):
            os.unlink(store_path)


if __name__ == "__main__":
    sys.exit(main())
