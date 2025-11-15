#!/usr/bin/env python3
"""
Brainpool elliptic curve cryptography example.
Demonstrates Brainpool curve operations including key generation,
ECDH key exchange, and ECDSA signing/verification.
"""

from gr_linux_crypto.crypto_helpers import CryptoHelpers


def main():
    print("GNU Radio Linux Crypto - Brainpool Example")
    print("=" * 60)

    crypto = CryptoHelpers()

    # Display supported Brainpool curves
    print("\nSupported Brainpool curves:")
    curves = crypto.get_brainpool_curves()
    for curve in curves:
        print(f"  - {curve}")

    # Example 1: Generate key pairs for different Brainpool curves
    print("\n" + "=" * 60)
    print("Example 1: Key Pair Generation")
    print("=" * 60)

    for curve_name in curves:
        print(f"\nGenerating key pair for {curve_name}...")
        private_key, public_key = crypto.generate_brainpool_keypair(curve_name)
        print(f"  Successfully generated {curve_name} key pair")

        # Serialize keys
        public_pem = crypto.serialize_brainpool_public_key(public_key)
        private_pem = crypto.serialize_brainpool_private_key(private_key)
        print(f"  Public key size: {len(public_pem)} bytes")
        print(f"  Private key size: {len(private_pem)} bytes")

    # Example 2: ECDH Key Exchange
    print("\n" + "=" * 60)
    print("Example 2: ECDH Key Exchange")
    print("=" * 60)

    print("\nSimulating key exchange between Alice and Bob...")
    print("Using brainpoolP256r1 curve")

    # Alice generates her key pair
    alice_private, alice_public = crypto.generate_brainpool_keypair("brainpoolP256r1")
    print("  Alice generated her key pair")

    # Bob generates his key pair
    bob_private, bob_public = crypto.generate_brainpool_keypair("brainpoolP256r1")
    print("  Bob generated his key pair")

    # Alice computes shared secret using Bob's public key
    alice_shared = crypto.brainpool_ecdh(alice_private, bob_public)
    print(
        f"  Alice computed shared secret: {crypto.bytes_to_hex(alice_shared[:16])}..."
    )

    # Bob computes shared secret using Alice's public key
    bob_shared = crypto.brainpool_ecdh(bob_private, alice_public)
    print(f"  Bob computed shared secret: {crypto.bytes_to_hex(bob_shared[:16])}...")

    # Verify they computed the same secret
    if alice_shared == bob_shared:
        print("  SUCCESS: Both parties computed the same shared secret!")
    else:
        print("  ERROR: Shared secrets do not match!")

    # Example 3: ECDSA Signing and Verification
    print("\n" + "=" * 60)
    print("Example 3: ECDSA Signing and Verification")
    print("=" * 60)

    # Generate key pair for signing
    sign_private, sign_public = crypto.generate_brainpool_keypair("brainpoolP384r1")
    print("  Generated key pair for signing (brainpoolP384r1)")

    # Message to sign
    message = "This is a message to sign using Brainpool ECDSA"
    print(f"  Message: {message}")

    # Sign the message
    signature = crypto.brainpool_sign(message, sign_private, hash_algorithm="sha384")
    print(f"  Signature (hex): {crypto.bytes_to_hex(signature)}")
    print(f"  Signature length: {len(signature)} bytes")

    # Verify the signature
    is_valid = crypto.brainpool_verify(
        message, signature, sign_public, hash_algorithm="sha384"
    )
    if is_valid:
        print("  SUCCESS: Signature verification passed!")
    else:
        print("  ERROR: Signature verification failed!")

    # Try to verify with wrong message
    wrong_message = "This is a different message"
    is_valid_wrong = crypto.brainpool_verify(
        wrong_message, signature, sign_public, hash_algorithm="sha384"
    )
    if not is_valid_wrong:
        print("  SUCCESS: Correctly rejected signature for wrong message!")
    else:
        print("  ERROR: Should have rejected signature for wrong message!")

    # Example 4: Key Serialization and Deserialization
    print("\n" + "=" * 60)
    print("Example 4: Key Serialization and Deserialization")
    print("=" * 60)

    # Generate a key pair
    original_private, original_public = crypto.generate_brainpool_keypair(
        "brainpoolP512r1"
    )
    print("  Generated original key pair (brainpoolP512r1)")

    # Serialize keys
    public_pem = crypto.serialize_brainpool_public_key(original_public)
    private_pem = crypto.serialize_brainpool_private_key(original_private)
    print("  Serialized keys to PEM format")

    # Deserialize keys
    loaded_public = crypto.load_brainpool_public_key(public_pem)
    loaded_private = crypto.load_brainpool_private_key(private_pem)
    print("  Deserialized keys from PEM format")

    # Test that loaded keys work
    test_message = "Test message for serialization verification"
    test_signature = crypto.brainpool_sign(
        test_message, loaded_private, hash_algorithm="sha512"
    )
    test_verified = crypto.brainpool_verify(
        test_message, test_signature, loaded_public, hash_algorithm="sha512"
    )

    if test_verified:
        print("  SUCCESS: Serialized/deserialized keys work correctly!")
    else:
        print("  ERROR: Serialized/deserialized keys do not work!")

    # Example 5: Password-protected private key
    print("\n" + "=" * 60)
    print("Example 5: Password-Protected Private Key")
    print("=" * 60)

    password = b"my_secret_password"
    private_key, _ = crypto.generate_brainpool_keypair("brainpoolP256r1")
    print("  Generated key pair")

    # Serialize with password
    encrypted_pem = crypto.serialize_brainpool_private_key(
        private_key, password=password
    )
    print("  Serialized private key with password protection")

    # Deserialize with correct password
    try:
        # Load key (result not stored, just verified)
        crypto.load_brainpool_private_key(encrypted_pem, password=password)
        print("  SUCCESS: Successfully loaded password-protected key!")
    except Exception as e:
        print(f"  ERROR: Failed to load password-protected key: {e}")

    # Try with wrong password
    try:
        # Try loading with wrong password (should fail)
        crypto.load_brainpool_private_key(encrypted_pem, password=b"wrong_password")
        print("  ERROR: Should not have loaded key with wrong password!")
    except Exception:
        print("  SUCCESS: Correctly rejected wrong password!")

    print("\n" + "=" * 60)
    print("All Brainpool examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
