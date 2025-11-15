#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux Crypto encryption/decryption interface.

Provides high-level encrypt/decrypt functions matching GNU Radio blocks API.
"""

import secrets
from typing import Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt(
    algorithm: str,
    key: bytes,
    data: bytes = b"",
    iv_mode: Union[str, bytes] = "random",
    auth: Optional[str] = None,
    aad: Optional[bytes] = None,
) -> Tuple[bytes, bytes, Optional[bytes]]:
    """
    Encrypt data using specified algorithm.

    Args:
        algorithm: Encryption algorithm ('aes-128', 'aes-256', 'chacha20')
        key: Encryption key (must match algorithm requirements)
        data: Plaintext data to encrypt (optional, can be provided via stream)
        iv_mode: IV mode ('random', 'fixed', or provide IV bytes)
        auth: Authentication mode ('gcm', 'poly1305', or None)
        aad: Additional Authenticated Data (optional, for AEAD modes like GCM/Poly1305)

    Returns:
        Tuple of (ciphertext, iv, auth_tag)
        - For authenticated encryption, auth_tag is provided
        - For non-authenticated modes, auth_tag is None
    """
    if algorithm.startswith("aes-"):
        key_size = int(algorithm.split("-")[1])
        if len(key) != key_size // 8:
            raise ValueError(
                f"Key size mismatch: {algorithm} requires {key_size // 8} bytes, got {len(key)}"
            )

        if auth == "gcm":
            return _aes_gcm_encrypt(key, data, iv_mode, aad)
        else:
            return _aes_encrypt(key, data, key_size, iv_mode)

    elif algorithm == "chacha20":
        if len(key) != 32:
            raise ValueError(f"ChaCha20 requires 32-byte key, got {len(key)}")

        if auth == "poly1305":
            return _chacha20_poly1305_encrypt(key, data, iv_mode, aad)
        else:
            raise ValueError("ChaCha20 requires Poly1305 authentication")

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def decrypt(
    algorithm: str,
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    auth: Optional[str] = None,
    auth_tag: Optional[bytes] = None,
    aad: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt data using specified algorithm.

    Args:
        algorithm: Encryption algorithm ('aes-128', 'aes-256', 'chacha20')
        key: Decryption key
        ciphertext: Encrypted data
        iv: Initialization vector
        auth: Authentication mode ('gcm', 'poly1305', or None)
        auth_tag: Authentication tag (required for authenticated modes)
        aad: Additional Authenticated Data (optional, for AEAD modes like GCM/Poly1305)

    Returns:
        Decrypted plaintext
    """
    if algorithm.startswith("aes-"):
        key_size = int(algorithm.split("-")[1])
        if len(key) != key_size // 8:
            raise ValueError(
                f"Key size mismatch: {algorithm} requires {key_size // 8} bytes, got {len(key)}"
            )

        if auth == "gcm":
            if auth_tag is None:
                raise ValueError("GCM mode requires auth_tag")
            return _aes_gcm_decrypt(key, ciphertext, iv, auth_tag, aad)
        else:
            return _aes_decrypt(key, ciphertext, iv, key_size)

    elif algorithm == "chacha20":
        if len(key) != 32:
            raise ValueError(f"ChaCha20 requires 32-byte key, got {len(key)}")

        if auth == "poly1305":
            if auth_tag is None:
                raise ValueError("Poly1305 authentication requires auth_tag")
            return _chacha20_poly1305_decrypt(key, ciphertext, iv, auth_tag, aad)
        else:
            raise ValueError("ChaCha20 requires Poly1305 authentication")

    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def _aes_gcm_encrypt(
    key: bytes, data: bytes, iv_mode: Union[str, bytes], aad: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """AES-GCM encryption with authentication."""
    if iv_mode == "random":
        iv = secrets.token_bytes(12)  # 96-bit IV for GCM
    elif isinstance(iv_mode, bytes):
        iv = iv_mode
        if len(iv) != 12:
            raise ValueError("GCM requires 12-byte IV")
    else:
        iv = iv_mode.encode() if len(iv_mode) == 12 else secrets.token_bytes(12)

    # Handle AAD: use empty bytes if None, otherwise use provided AAD
    associated_data = aad if aad is not None else b""

    cipher = AESGCM(key)
    ciphertext_with_tag = cipher.encrypt(iv, data, associated_data)

    # Extract tag (16 bytes at the end)
    tag_size = 16
    auth_tag = ciphertext_with_tag[-tag_size:]
    ciphertext_only = ciphertext_with_tag[:-tag_size]

    return ciphertext_only, iv, auth_tag


def _aes_gcm_decrypt(
    key: bytes,
    ciphertext: bytes,
    iv: bytes,
    auth_tag: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """AES-GCM decryption with authentication verification."""
    cipher = AESGCM(key)
    # Combine ciphertext and tag
    encrypted_data = ciphertext + auth_tag

    # Handle AAD: use empty bytes if None, otherwise use provided AAD
    associated_data = aad if aad is not None else b""

    try:
        plaintext = cipher.decrypt(iv, encrypted_data, associated_data)
        return plaintext
    except Exception as e:
        raise ValueError(f"GCM authentication failed: {e}")


def _aes_encrypt(
    key: bytes, data: bytes, key_size: int, iv_mode: Union[str, bytes]
) -> Tuple[bytes, bytes, None]:
    """AES encryption (non-authenticated, CBC mode)."""
    if iv_mode == "random":
        iv = secrets.token_bytes(16)
    elif isinstance(iv_mode, bytes):
        iv = iv_mode
        if len(iv) != 16:
            raise ValueError("AES-CBC requires 16-byte IV")
    else:
        iv = (
            iv_mode.encode()
            if isinstance(iv_mode, str) and len(iv_mode) == 16
            else secrets.token_bytes(16)
        )

    # Pad data to block size using PKCS#7
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padded_data = data + bytes([padding_length] * padding_length)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv, None


def _aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes, key_size: int) -> bytes:
    """AES decryption (non-authenticated, CBC mode)."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS#7 padding
    if len(padded_plaintext) == 0:
        return b""

    padding_length = padded_plaintext[-1]
    if padding_length > 16 or padding_length == 0:
        raise ValueError("Invalid padding")
    if padding_length > len(padded_plaintext):
        raise ValueError("Invalid padding length")
    plaintext = padded_plaintext[:-padding_length]
    return plaintext


def _chacha20_poly1305_encrypt(
    key: bytes, data: bytes, iv_mode: Union[str, bytes], aad: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """ChaCha20-Poly1305 encryption."""
    if iv_mode == "random":
        nonce = secrets.token_bytes(12)  # 96-bit nonce
    elif isinstance(iv_mode, bytes):
        nonce = iv_mode
        if len(nonce) != 12:
            raise ValueError("ChaCha20-Poly1305 requires 12-byte nonce")
    else:
        nonce = (
            iv_mode.encode()
            if isinstance(iv_mode, str) and len(iv_mode) == 12
            else secrets.token_bytes(12)
        )

    # Handle AAD: use empty bytes if None, otherwise use provided AAD
    associated_data = aad if aad is not None else b""

    cipher = ChaCha20Poly1305(key)
    ciphertext_with_tag = cipher.encrypt(nonce, data, associated_data)

    tag_size = 16
    auth_tag = ciphertext_with_tag[-tag_size:]
    ciphertext_only = ciphertext_with_tag[:-tag_size]

    return ciphertext_only, nonce, auth_tag


def _chacha20_poly1305_decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    auth_tag: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """ChaCha20-Poly1305 decryption."""
    cipher = ChaCha20Poly1305(key)
    encrypted_data = ciphertext + auth_tag

    # Handle AAD: use empty bytes if None, otherwise use provided AAD
    associated_data = aad if aad is not None else b""

    try:
        plaintext = cipher.decrypt(nonce, encrypted_data, associated_data)
        return plaintext
    except Exception as e:
        raise ValueError(f"Poly1305 authentication failed: {e}")
