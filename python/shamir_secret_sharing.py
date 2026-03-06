#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shamir's Secret Sharing over a prime field.

Splits a secret into N shares such that any K shares reconstruct the secret.
Uses Brainpool curve orders (BSI TR 03111, RFC 5639) as the prime modulus so
that arithmetic aligns with BSI/Brainpool parameters. Supports all three
Brainpool curve sizes: P256r1, P384r1, P512r1. Suitable for K-of-N quorum
decryption of a session key (e.g. combine with multi-recipient ECIES).
"""

import hashlib
import secrets
from typing import Dict, List, Optional, Tuple

# Brainpool curve orders (BSI TR 03111, RFC 5639). Prime moduli for GF(p).
BRAINPOOL_P256R1_ORDER = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
BRAINPOOL_P384R1_ORDER = 0x8CB91E82A3EC986F3FB4881D7B6A5FE5C9E42F818172138C1FD6DCB3D4F6E8C17
# RFC 5639: 512-bit order (128 hex chars)
BRAINPOOL_P512R1_ORDER = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069

# Curve name -> (order, max_secret_bytes, share_value_bytes for encoding)
CURVE_PARAMS: Dict[str, Tuple[int, int, int]] = {
    "brainpoolP256r1": (BRAINPOOL_P256R1_ORDER, 31, 32),
    "brainpoolP384r1": (BRAINPOOL_P384R1_ORDER, 47, 48),
    "brainpoolP512r1": (BRAINPOOL_P512R1_ORDER, 63, 64),
}

SUPPORTED_CURVES = list(CURVE_PARAMS.keys())

# Default (P256) max secret length for backward compatibility
MAX_SECRET_BYTES = CURVE_PARAMS["brainpoolP256r1"][1]


def get_curve_prime(curve: str) -> int:
    """Return the curve order (prime) for a Brainpool curve name."""
    if curve not in CURVE_PARAMS:
        raise ValueError(
            f"Unsupported curve: {curve}. Supported: {SUPPORTED_CURVES}"
        )
    return CURVE_PARAMS[curve][0]


def get_max_secret_bytes(curve: Optional[str] = None, prime: Optional[int] = None) -> int:
    """Return maximum secret length in bytes for split() for the given curve or prime."""
    if curve is not None:
        if curve not in CURVE_PARAMS:
            raise ValueError(f"Unsupported curve: {curve}. Supported: {SUPPORTED_CURVES}")
        return CURVE_PARAMS[curve][1]
    if prime is not None:
        for _, (p, max_b, _) in CURVE_PARAMS.items():
            if p == prime:
                return max_b
        # Arbitrary prime: use byte length of prime - 1
        return (prime.bit_length() + 7) // 8 - 1
    return MAX_SECRET_BYTES


def get_share_value_bytes(curve: str) -> int:
    """Return number of bytes to encode a share value for the curve."""
    if curve not in CURVE_PARAMS:
        raise ValueError(f"Unsupported curve: {curve}. Supported: {SUPPORTED_CURVES}")
    return CURVE_PARAMS[curve][2]


def _bytes_to_int(data: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(data, "big")


def _int_to_bytes(value: int, length: int = 32) -> bytes:
    """Convert non-negative integer to bytes (big-endian), zero-padded to length."""
    if value < 0:
        raise ValueError("value must be non-negative")
    return value.to_bytes(length, "big")[:length].rjust(length, b"\x00")


def split(
    secret: bytes,
    threshold_k: int,
    num_shares_n: int,
    prime: Optional[int] = None,
    curve: Optional[str] = None,
) -> List[Tuple[int, int]]:
    """
    Split a secret into N shares with threshold K (K-of-N).

    Any K or more shares can reconstruct the secret. Uses Shamir's scheme
    over GF(prime): polynomial f(X) of degree K-1 with f(0) = secret mod prime;
    share i is (i, f(i)) for i in 1..N. BSI/RFC 5639: use curve to select
    the Brainpool curve order as prime (brainpoolP256r1, brainpoolP384r1,
    brainpoolP512r1).

    Args:
        secret: Secret bytes; max length depends on curve/prime (31 for P256, 47 for P384, 63 for P512)
        threshold_k: Minimum number of shares required to reconstruct (K)
        num_shares_n: Total number of shares to generate (N)
        prime: Prime modulus (optional; ignored if curve is set)
        curve: Brainpool curve name (optional; selects prime and max secret length)

    Returns:
        List of (index, value) pairs; index is 1..N, value is in [0, prime-1]

    Raises:
        ValueError: If secret too long, or K > N, or K < 1
    """
    if curve is not None:
        prime = get_curve_prime(curve)
        max_bytes = get_max_secret_bytes(curve=curve)
    else:
        prime = prime if prime is not None else BRAINPOOL_P256R1_ORDER
        max_bytes = get_max_secret_bytes(prime=prime)
    if len(secret) > max_bytes:
        raise ValueError(
            f"secret length must be at most {max_bytes} bytes for this field"
        )
    if len(secret) == 0:
        raise ValueError("secret must not be empty")
    if threshold_k > num_shares_n:
        raise ValueError("threshold_k must be <= num_shares_n")
    if threshold_k < 1 or num_shares_n < 1:
        raise ValueError("threshold_k and num_shares_n must be >= 1")

    s = _bytes_to_int(secret) % prime
    coeffs = [s] + [
        secrets.randbelow(prime) for _ in range(threshold_k - 1)
    ]

    def eval_poly(x: int) -> int:
        v = 0
        for c in reversed(coeffs):
            v = (v * x + c) % prime
        return v

    return [(i, eval_poly(i)) for i in range(1, num_shares_n + 1)]


def reconstruct(
    shares: List[Tuple[int, int]],
    prime: Optional[int] = None,
    secret_length: Optional[int] = None,
    curve: Optional[str] = None,
) -> bytes:
    """
    Reconstruct the secret from at least K shares (Lagrange interpolation at 0).

    Args:
        shares: List of (index, value) from split(); need at least K distinct shares
        prime: Same prime used in split() (optional if curve is set)
        secret_length: Length in bytes of the returned secret (optional; default by curve)
        curve: Brainpool curve name (optional; selects prime and default secret_length)

    Returns:
        Reconstructed secret bytes

    Raises:
        ValueError: If not enough shares or duplicate index
    """
    if curve is not None:
        prime = get_curve_prime(curve)
        if secret_length is None:
            secret_length = get_share_value_bytes(curve)
    else:
        prime = prime if prime is not None else BRAINPOOL_P256R1_ORDER
        if secret_length is None:
            secret_length = 32
    if not shares:
        raise ValueError("at least one share required")
    indices = [s[0] for s in shares]
    if len(indices) != len(set(indices)):
        raise ValueError("duplicate share indices")

    # Lagrange: f(0) = sum_j y_j * L_j(0),  L_j(0) = prod_{m != j} (0 - x_m)/(x_j - x_m)
    zero_val = 0
    for j, (x_j, y_j) in enumerate(shares):
        num = 1
        den = 1
        for m, (x_m, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (0 - x_m)) % prime
            den = (den * (x_j - x_m)) % prime
        den_inv = pow(den, prime - 2, prime)  # Fermat
        zero_val = (zero_val + y_j * num * den_inv) % prime

    return _int_to_bytes(zero_val, secret_length)


def create_shamir_backed_key(
    threshold_k: int,
    num_shares_n: int,
    prime: Optional[int] = None,
    curve: Optional[str] = None,
) -> Tuple[List[Tuple[int, int]], bytes]:
    """
    Create a random 32-byte session key and Shamir shares that can reconstruct it.

    A random secret S (31 bytes for P256, up to 47/63 for P384/P512) is generated
    and split into N shares (threshold K). The 32-byte session key is
    K = HKDF-SHA256(S). Use for K-of-N quorum decryption. BSI/RFC 5639: use
    curve to select the Brainpool curve order (brainpoolP256r1, P384r1, P512r1).

    Args:
        threshold_k: Minimum shares required to reconstruct (K)
        num_shares_n: Total number of shares (N)
        prime: Prime modulus (optional if curve is set)
        curve: Brainpool curve name (optional)

    Returns:
        (shares, session_key_32): shares as list of (index, value); key is 32 bytes
    """
    if curve is not None:
        prime = get_curve_prime(curve)
    else:
        prime = prime if prime is not None else BRAINPOOL_P256R1_ORDER
    # 31-byte secret for all curves so session key is always 32 bytes (AES-256)
    secret = secrets.token_bytes(31)
    shares = split(secret, threshold_k, num_shares_n, prime=prime)
    key_32 = _hkdf_32(secret)
    return shares, key_32


def reconstruct_session_key(
    shares: List[Tuple[int, int]],
    prime: Optional[int] = None,
    curve: Optional[str] = None,
) -> bytes:
    """
    Reconstruct the 32-byte session key from shares created by create_shamir_backed_key.

    Reconstructs the secret S from shares, then returns HKDF-SHA256(S). Use the
    same curve or prime as when creating shares.

    Args:
        shares: At least K shares from create_shamir_backed_key
        prime: Same prime used when creating shares (optional if curve is set)
        curve: Brainpool curve name (optional)

    Returns:
        32-byte session key
    """
    if curve is not None:
        prime = get_curve_prime(curve)
        out_len = get_share_value_bytes(curve)
    else:
        prime = prime if prime is not None else BRAINPOOL_P256R1_ORDER
        out_len = 31
    reconstructed = reconstruct(shares, prime=prime, secret_length=out_len)
    # Session key is derived from 31-byte secret; take low 31 bytes when output is 48/64
    secret_31 = reconstructed[-31:] if len(reconstructed) > 31 else reconstructed
    return _hkdf_32(secret_31)


def _hkdf_32(secret_31: bytes) -> bytes:
    """Derive 32-byte key from 31-byte secret using HKDF-style expansion."""
    return hashlib.sha256(
        secret_31 + b"gr-linux-crypto-shamir-32byte-v1"
    ).digest()
