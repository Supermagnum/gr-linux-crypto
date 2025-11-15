#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python helper functions for cryptographic operations.

Provides utilities for GNU Radio crypto operations.
"""

import base64
import hashlib
import hmac
import secrets
from typing import List, Optional, Tuple, Union

import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoHelpers:
    """Helper class for cryptographic operations."""

    @staticmethod
    def generate_random_key(key_size: int = 32) -> bytes:
        """Generate a random key of specified size."""
        return secrets.token_bytes(key_size)

    @staticmethod
    def generate_random_iv(iv_size: int = 16) -> bytes:
        """Generate a random IV of specified size."""
        return secrets.token_bytes(iv_size)

    @staticmethod
    def hash_data(data: Union[str, bytes], algorithm: str = "sha256") -> bytes:
        """
        Hash data using specified algorithm.

        Args:
            data: Data to hash
            algorithm: Hash algorithm ('sha1', 'sha256', 'sha512')

        Returns:
            Hash digest as bytes
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if algorithm == "sha1":
            return hashlib.sha1(data).digest()
        elif algorithm == "sha256":
            return hashlib.sha256(data).digest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    @staticmethod
    def hmac_sign(
        data: Union[str, bytes], key: bytes, algorithm: str = "sha256"
    ) -> bytes:
        """
        Create HMAC signature.

        Args:
            data: Data to sign
            key: HMAC key
            algorithm: Hash algorithm for HMAC

        Returns:
            HMAC signature as bytes
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        if algorithm == "sha1":
            return hmac.new(key, data, hashlib.sha1).digest()
        elif algorithm == "sha256":
            return hmac.new(key, data, hashlib.sha256).digest()
        elif algorithm == "sha512":
            return hmac.new(key, data, hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")

    @staticmethod
    def aes_encrypt(data: bytes, key: bytes, iv: bytes, mode: str = "cbc") -> bytes:
        """
        Encrypt data using AES.

        Args:
            data: Data to encrypt
            key: AES key (16, 24, or 32 bytes)
            iv: Initialization vector
            mode: AES mode ('cbc', 'ecb', 'cfb', 'ofb')

        Returns:
            Encrypted data as bytes
        """
        if mode == "cbc":
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
        elif mode == "ecb":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif mode == "cfb":
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
        elif mode == "ofb":
            cipher = Cipher(
                algorithms.AES(key), modes.OFB(iv), backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported AES mode: {mode}")

        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def aes_decrypt(data: bytes, key: bytes, iv: bytes, mode: str = "cbc") -> bytes:
        """
        Decrypt data using AES.

        Args:
            data: Data to decrypt
            key: AES key (16, 24, or 32 bytes)
            iv: Initialization vector
            mode: AES mode ('cbc', 'ecb', 'cfb', 'ofb')

        Returns:
            Decrypted data as bytes
        """
        if mode == "cbc":
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
        elif mode == "ecb":
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif mode == "cfb":
            cipher = Cipher(
                algorithms.AES(key), modes.CFB(iv), backend=default_backend()
            )
        elif mode == "ofb":
            cipher = Cipher(
                algorithms.AES(key), modes.OFB(iv), backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported AES mode: {mode}")

        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    @staticmethod
    def derive_key_from_password(
        password: Union[str, bytes],
        salt: bytes,
        length: int = 32,
        iterations: int = 100000,
    ) -> bytes:
        """
        Derive a key from a password using PBKDF2.

        Args:
            password: Password to derive key from
            salt: Salt for key derivation
            length: Desired key length in bytes
            iterations: Number of PBKDF2 iterations

        Returns:
            Derived key as bytes
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return kdf.derive(password)

    @staticmethod
    def derive_key_hkdf(
        ikm: Union[str, bytes],
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
        length: int = 32,
        algorithm: str = "sha256",
    ) -> bytes:
        """
        Derive a key using HKDF (HMAC-based Key Derivation Function).

        HKDF is specified in RFC 5869 and is designed for key derivation
        from shared secrets (e.g., from ECDH key exchange). It is more
        efficient than PBKDF2 but should not be used for password-based
        key derivation.

        Args:
            ikm: Input Key Material (shared secret, typically from ECDH)
            salt: Optional salt (should be random or fixed application-specific value)
            info: Optional context/application-specific information
            length: Desired key length in bytes (max depends on hash algorithm)
            algorithm: Hash algorithm ('sha256', 'sha384', 'sha512')

        Returns:
            Derived key as bytes

        Raises:
            ValueError: If algorithm is unsupported or length is invalid
        """
        if isinstance(ikm, str):
            ikm = ikm.encode("utf-8")

        hash_algo = None
        if algorithm == "sha256":
            hash_algo = hashes.SHA256()
            max_length = 32 * 255  # 255 * hash_length
        elif algorithm == "sha384":
            hash_algo = hashes.SHA384()
            max_length = 48 * 255
        elif algorithm == "sha512":
            hash_algo = hashes.SHA512()
            max_length = 64 * 255
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        if length > max_length:
            raise ValueError(
                f"Requested length {length} exceeds maximum {max_length} for {algorithm}"
            )

        if salt is None:
            salt = b""

        if info is None:
            info = b""

        kdf = HKDF(
            algorithm=hash_algo,
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return kdf.derive(ikm)

    @staticmethod
    def generate_rsa_keypair(
        key_size: int = 2048,
    ) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate RSA key pair.

        Args:
            key_size: Key size in bits

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def rsa_encrypt(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """
        Encrypt data using RSA public key.

        Args:
            data: Data to encrypt
            public_key: RSA public key

        Returns:
            Encrypted data as bytes
        """
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def rsa_decrypt(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decrypt data using RSA private key.

        Args:
            data: Data to decrypt
            private_key: RSA private key

        Returns:
            Decrypted data as bytes
        """
        return private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def rsa_sign(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Sign data using RSA private key.

        Args:
            data: Data to sign
            private_key: RSA private key

        Returns:
            Signature as bytes
        """
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

    @staticmethod
    def rsa_verify(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verify RSA signature.

        Args:
            data: Original data
            signature: Signature to verify
            public_key: RSA public key

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """Serialize RSA public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def serialize_private_key(
        private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None
    ) -> bytes:
        """Serialize RSA private key to PEM format."""
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """Load RSA public key from PEM format."""
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    @staticmethod
    def load_private_key(
        pem_data: bytes, password: Optional[bytes] = None
    ) -> rsa.RSAPrivateKey:
        """Load RSA private key from PEM format."""
        return serialization.load_pem_private_key(
            pem_data, password=password, backend=default_backend()
        )

    @staticmethod
    def get_brainpool_curves() -> List[str]:
        """
        Get list of supported Brainpool curve names.

        Returns:
            List of supported Brainpool curve names
        """
        return ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]

    @staticmethod
    def _get_brainpool_curve(curve_name: str):
        """
        Get Brainpool curve object by name.

        Args:
            curve_name: Name of the curve ('brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1')

        Returns:
            Curve object
        """
        if curve_name == "brainpoolP256r1":
            return ec.BrainpoolP256R1()
        elif curve_name == "brainpoolP384r1":
            return ec.BrainpoolP384R1()
        elif curve_name == "brainpoolP512r1":
            return ec.BrainpoolP512R1()
        else:
            raise ValueError(
                f"Unsupported Brainpool curve: {curve_name}. "
                f"Supported curves: {CryptoHelpers.get_brainpool_curves()}"
            )

    @staticmethod
    def generate_brainpool_keypair(
        curve_name: str = "brainpoolP256r1",
    ) -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
        Generate Brainpool elliptic curve key pair.

        Args:
            curve_name: Name of the Brainpool curve ('brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1')

        Returns:
            Tuple of (private_key, public_key)
        """
        curve = CryptoHelpers._get_brainpool_curve(curve_name)
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def brainpool_ecdh(
        private_key: EllipticCurvePrivateKey, peer_public_key: EllipticCurvePublicKey
    ) -> bytes:
        """
        Perform ECDH (Elliptic Curve Diffie-Hellman) key exchange using Brainpool curves.

        Args:
            private_key: Local private key
            peer_public_key: Peer's public key

        Returns:
            Shared secret as bytes
        """
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret

    @staticmethod
    def brainpool_sign(
        data: Union[str, bytes],
        private_key: EllipticCurvePrivateKey,
        hash_algorithm: str = "sha256",
    ) -> bytes:
        """
        Sign data using Brainpool ECDSA.

        Args:
            data: Data to sign
            private_key: Brainpool private key
            hash_algorithm: Hash algorithm for signing ('sha256', 'sha384', 'sha512')

        Returns:
            Signature as bytes
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        hash_algo = None
        if hash_algorithm == "sha256":
            hash_algo = hashes.SHA256()
        elif hash_algorithm == "sha384":
            hash_algo = hashes.SHA384()
        elif hash_algorithm == "sha512":
            hash_algo = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        signature = private_key.sign(data, ec.ECDSA(hash_algo))
        return signature

    @staticmethod
    def brainpool_verify(
        data: Union[str, bytes],
        signature: bytes,
        public_key: EllipticCurvePublicKey,
        hash_algorithm: str = "sha256",
    ) -> bool:
        """
        Verify Brainpool ECDSA signature.

        Args:
            data: Original data
            signature: Signature to verify
            public_key: Brainpool public key
            hash_algorithm: Hash algorithm used for signing ('sha256', 'sha384', 'sha512')

        Returns:
            True if signature is valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        hash_algo = None
        if hash_algorithm == "sha256":
            hash_algo = hashes.SHA256()
        elif hash_algorithm == "sha384":
            hash_algo = hashes.SHA384()
        elif hash_algorithm == "sha512":
            hash_algo = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        try:
            public_key.verify(signature, data, ec.ECDSA(hash_algo))
            return True
        except Exception:
            return False

    @staticmethod
    def brainpool_ecgdsa_sign(
        data: Union[str, bytes],
        private_key: EllipticCurvePrivateKey,
        hash_algorithm: str = "sha256",
    ) -> bytes:
        """
        Sign data using Brainpool ECGDSA (Elliptic Curve German Digital Signature Algorithm).

        ECGDSA is a variant of ECDSA standardized by BSI (German Federal Office).
        The main difference is in hash processing - ECGDSA uses a different method.

        Note: Python cryptography library doesn't have native ECGDSA support.
        This implementation uses OpenSSL via subprocess if available, otherwise falls back
        to a manual implementation.

        Args:
            data: Data to sign
            private_key: Brainpool private key
            hash_algorithm: Hash algorithm for signing ('sha256', 'sha384', 'sha512')

        Returns:
            Signature as bytes (DER encoded)
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        # ECGDSA implementation requires lower-level crypto operations
        # For now, we'll use OpenSSL if available, otherwise note that it's not fully supported

        try:
            # Serialize private key to PEM (not stored, just serialized)
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Get curve name
            curve_name = (
                private_key.curve.name if hasattr(private_key.curve, "name") else None
            )
            if not curve_name or "brainpool" not in curve_name.lower():
                raise ValueError("ECGDSA requires Brainpool curves")

            # Map hash algorithm
            hash_map = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
            hash_map.get(hash_algorithm.lower(), "sha256")

            # Use OpenSSL for ECGDSA (if supported)
            # Note: OpenSSL may not have native ECGDSA support, this is a placeholder
            # In practice, you may need a specialized library or manual implementation

            # For now, we'll note that full ECGDSA requires additional implementation
            # This is a framework that can be extended
            raise NotImplementedError(
                "ECGDSA requires specialized implementation. "
                "Python cryptography library doesn't support ECGDSA natively. "
                "Consider using OpenSSL directly or a specialized ECGDSA library."
            )

        except NotImplementedError:
            raise
        except Exception as e:
            raise ValueError(f"ECGDSA signing failed: {e}")

    @staticmethod
    def brainpool_ecgdsa_verify(
        data: Union[str, bytes],
        signature: bytes,
        public_key: EllipticCurvePublicKey,
        hash_algorithm: str = "sha256",
    ) -> bool:
        """
        Verify Brainpool ECGDSA signature.

        Args:
            data: Original data
            signature: Signature to verify
            public_key: Brainpool public key
            hash_algorithm: Hash algorithm used for signing ('sha256', 'sha384', 'sha512')

        Returns:
            True if signature is valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode("utf-8")

        # ECGDSA verification requires specialized implementation
        raise NotImplementedError(
            "ECGDSA verification requires specialized implementation. "
            "Python cryptography library doesn't support ECGDSA natively."
        )

    @staticmethod
    def serialize_brainpool_public_key(public_key: EllipticCurvePublicKey) -> bytes:
        """
        Serialize Brainpool public key to PEM format.

        Args:
            public_key: Brainpool public key

        Returns:
            PEM-encoded public key as bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def serialize_brainpool_private_key(
        private_key: EllipticCurvePrivateKey, password: Optional[bytes] = None
    ) -> bytes:
        """
        Serialize Brainpool private key to PEM format.

        Args:
            private_key: Brainpool private key
            password: Optional password for encryption

        Returns:
            PEM-encoded private key as bytes
        """
        if password:
            encryption = serialization.BestAvailableEncryption(password)
        else:
            encryption = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    @staticmethod
    def load_brainpool_public_key(pem_data: bytes) -> EllipticCurvePublicKey:
        """
        Load Brainpool public key from PEM format.

        Args:
            pem_data: PEM-encoded public key

        Returns:
            Brainpool public key object

        Raises:
            ValueError: If the key is not a valid EC key
        """
        key = serialization.load_pem_public_key(pem_data, backend=default_backend())
        if not isinstance(key, EllipticCurvePublicKey):
            raise ValueError("Loaded key is not an elliptic curve public key")
        return key

    @staticmethod
    def load_brainpool_private_key(
        pem_data: bytes, password: Optional[bytes] = None
    ) -> EllipticCurvePrivateKey:
        """
        Load Brainpool private key from PEM format.

        Args:
            pem_data: PEM-encoded private key
            password: Optional password for decryption

        Returns:
            Brainpool private key object

        Raises:
            ValueError: If the key is not a valid EC key
        """
        key = serialization.load_pem_private_key(
            pem_data, password=password, backend=default_backend()
        )
        if not isinstance(key, EllipticCurvePrivateKey):
            raise ValueError("Loaded key is not an elliptic curve private key")
        return key

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Convert bytes to hex string."""
        return data.hex()

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        return bytes.fromhex(hex_str)

    @staticmethod
    def base64_encode(data: bytes) -> str:
        """Encode bytes to base64 string."""
        return base64.b64encode(data).decode("utf-8")

    @staticmethod
    def base64_decode(b64_str: str) -> bytes:
        """Decode base64 string to bytes."""
        return base64.b64decode(b64_str)

    @staticmethod
    def xor_data(data1: bytes, data2: bytes) -> bytes:
        """XOR two byte sequences."""
        return bytes(a ^ b for a, b in zip(data1, data2))

    @staticmethod
    def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
        """Pad data using PKCS#7 padding."""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    @staticmethod
    def unpad_pkcs7(data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]


# GNU Radio specific utilities
class GNURadioCryptoUtils:
    """Utilities specifically for GNU Radio crypto operations."""

    @staticmethod
    def numpy_to_bytes(data: np.ndarray) -> bytes:
        """Convert numpy array to bytes."""
        return data.tobytes()

    @staticmethod
    def bytes_to_numpy(data: bytes, dtype: np.dtype = np.uint8) -> np.ndarray:
        """Convert bytes to numpy array."""
        return np.frombuffer(data, dtype=dtype)

    @staticmethod
    def encrypt_stream_data(
        data: np.ndarray, key: bytes, iv: bytes, mode: str = "cbc"
    ) -> np.ndarray:
        """Encrypt numpy array data."""
        data_bytes = data.tobytes()
        encrypted = CryptoHelpers.aes_encrypt(data_bytes, key, iv, mode)
        return np.frombuffer(encrypted, dtype=data.dtype)

    @staticmethod
    def decrypt_stream_data(
        data: np.ndarray, key: bytes, iv: bytes, mode: str = "cbc"
    ) -> np.ndarray:
        """Decrypt numpy array data."""
        data_bytes = data.tobytes()
        decrypted = CryptoHelpers.aes_decrypt(data_bytes, key, iv, mode)
        return np.frombuffer(decrypted, dtype=data.dtype)


if __name__ == "__main__":
    # Example usage
    crypto = CryptoHelpers()

    # Generate random key and IV
    key = crypto.generate_random_key(32)
    iv = crypto.generate_random_iv(16)

    # Encrypt some data
    data = b"Hello, GNU Radio Crypto!"
    encrypted = crypto.aes_encrypt(data, key, iv)
    print(f"Encrypted: {crypto.bytes_to_hex(encrypted)}")

    # Decrypt the data
    decrypted = crypto.aes_decrypt(encrypted, key, iv)
    print(f"Decrypted: {decrypted}")

    # Hash the data
    hash_digest = crypto.hash_data(data)
    print(f"Hash: {crypto.bytes_to_hex(hash_digest)}")

    # Create HMAC
    hmac_sig = crypto.hmac_sign(data, key)
    print(f"HMAC: {crypto.bytes_to_hex(hmac_sig)}")

    # HKDF key derivation (typical use: derive key from ECDH shared secret)
    shared_secret = crypto.generate_random_key(32)  # Simulated ECDH shared secret
    salt = crypto.generate_random_key(16)
    info = b"gnuradio-crypto-v1"
    derived_key = crypto.derive_key_hkdf(shared_secret, salt=salt, info=info, length=32)
    print(f"HKDF derived key: {crypto.bytes_to_hex(derived_key)}")
