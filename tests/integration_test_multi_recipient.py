#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration tests for multi-recipient ECIES.

Validates complete encrypt/decrypt round-trips for all recipient counts.
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from python.multi_recipient_ecies import MultiRecipientECIES
    from python.callsign_key_store import CallsignKeyStore
    from python.crypto_helpers import CryptoHelpers
except ImportError:
    try:
        from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
        from gr_linux_crypto.callsign_key_store import CallsignKeyStore
        from gr_linux_crypto.crypto_helpers import CryptoHelpers
    except ImportError:
        print("Error: Could not import required modules")
        sys.exit(1)


def test_recipient_count(num_recipients: int, curve: str = "brainpoolP256r1"):
    """
    Test encryption/decryption for a specific number of recipients.
    
    Args:
        num_recipients: Number of recipients (1-25)
        curve: Brainpool curve to use
        
    Returns:
        True if all tests passed, False otherwise
    """
    print(f"\nTesting {num_recipients} recipient(s) with {curve}...")
    
    crypto = CryptoHelpers()
    ecies = MultiRecipientECIES(curve=curve)
    
    fd, store_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    try:
        store = CallsignKeyStore(store_path=store_path)
        test_keys = {}
        callsigns = [f"W{i:02d}ABC" for i in range(1, num_recipients + 1)]
        
        for callsign in callsigns:
            private_key, public_key = crypto.generate_brainpool_keypair(curve)
            public_pem = crypto.serialize_brainpool_public_key(public_key)
            private_pem = crypto.serialize_brainpool_private_key(private_key)
            
            store.add_key(callsign, public_pem)
            test_keys[callsign] = private_pem
        
        plaintext = f"Test message for {num_recipients} recipient(s)".encode('utf-8')
        
        encrypted = ecies.encrypt(plaintext, callsigns, store)
        print(f"  Encrypted: {len(encrypted)} bytes")
        
        success_count = 0
        for callsign in callsigns:
            try:
                decrypted = ecies.decrypt(encrypted, callsign, test_keys[callsign])
                if decrypted == plaintext:
                    success_count += 1
                    print(f"  {callsign}: SUCCESS")
                else:
                    print(f"  {callsign}: FAILED (decryption mismatch)")
            except Exception as e:
                print(f"  {callsign}: FAILED ({e})")
        
        if success_count == num_recipients:
            print(f"  Result: ALL {num_recipients} recipients decrypted successfully")
            return True
        else:
            print(f"  Result: Only {success_count}/{num_recipients} recipients succeeded")
            return False
    
    finally:
        if os.path.exists(store_path):
            os.unlink(store_path)


def main():
    """Run integration tests for all recipient counts."""
    print("=" * 60)
    print("Multi-Recipient ECIES Integration Tests")
    print("=" * 60)
    
    curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
    results = {}
    
    for curve in curves:
        print(f"\n{'=' * 60}")
        print(f"Testing curve: {curve}")
        print(f"{'=' * 60}")
        
        curve_results = []
        for num_recipients in range(1, 26):
            success = test_recipient_count(num_recipients, curve)
            curve_results.append(success)
        
        results[curve] = curve_results
        
        passed = sum(curve_results)
        total = len(curve_results)
        print(f"\n{curve}: {passed}/{total} recipient count tests passed")
    
    print(f"\n{'=' * 60}")
    print("Summary")
    print(f"{'=' * 60}")
    
    all_passed = True
    for curve, curve_results in results.items():
        passed = sum(curve_results)
        total = len(curve_results)
        status = "PASS" if passed == total else "FAIL"
        print(f"{curve}: {passed}/{total} ({status})")
        if passed != total:
            all_passed = False
    
    if all_passed:
        print("\nAll tests PASSED")
        return 0
    else:
        print("\nSome tests FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())

