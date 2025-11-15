#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Brainpool ECC test vector parsers.

Supports:
- Wycheproof JSON format (Google)
- RFC 5639 format
- NIST CAVP format
"""

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class TestVectorType(Enum):
    """Type of test vector."""

    VALID = "valid"
    INVALID = "invalid"
    ACB = "acceptable"  # Acceptable but with warnings


@dataclass
class ECDHTestVector:
    """ECDH key exchange test vector."""

    tc_id: int
    curve: str
    private_key: bytes
    public_key: bytes
    shared_secret: bytes
    comment: str
    result: str  # "valid", "invalid", "acceptable"
    flags: List[str]


@dataclass
class ECDSATestVector:
    """ECDSA signature test vector."""

    tc_id: int
    curve: str
    message: bytes
    private_key: bytes
    public_key: bytes
    signature_r: bytes
    signature_s: bytes
    comment: str
    result: str
    flags: List[str]


@dataclass
class RFC5639CurveParams:
    """RFC 5639 Brainpool curve parameters."""

    curve_name: str
    p: int  # Prime modulus
    a: int  # Curve parameter a
    b: int  # Curve parameter b
    gx: int  # Generator point x coordinate
    gy: int  # Generator point y coordinate
    n: int  # Order
    h: int  # Cofactor


class WycheproofParser:
    """Parser for Wycheproof JSON test vectors."""

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        if not hex_str:
            return b""
        hex_clean = re.sub(r"[\s\n\r]", "", hex_str)
        return bytes.fromhex(hex_clean)

    @staticmethod
    def parse_ecdh_file(file_path: str) -> List[ECDHTestVector]:
        """
        Parse Wycheproof ECDH test vector JSON file.

        Format:
        {
          "algorithm": "ECDH",
          "generatorVersion": "...",
          "numberOfTests": 123,
          "header": [...],
          "testGroups": [{
            "curve": "brainpoolP256r1",
            "type": "ECDH",
            "tests": [{
              "tcId": 1,
              "comment": "...",
              "public": "...",
              "private": "...",
              "shared": "...",
              "result": "valid",
              "flags": []
            }]
          }]
        }
        """
        vectors = []

        with open(file_path, "r") as f:
            data = json.load(f)

        for group in data.get("testGroups", []):
            curve = group.get("curve", "")
            if "brainpool" not in curve.lower():
                continue

            for test in group.get("tests", []):
                vectors.append(
                    ECDHTestVector(
                        tc_id=test.get("tcId", 0),
                        curve=curve,
                        private_key=WycheproofParser.hex_to_bytes(
                            test.get("private", "")
                        ),
                        public_key=WycheproofParser.hex_to_bytes(
                            test.get("public", "")
                        ),
                        shared_secret=WycheproofParser.hex_to_bytes(
                            test.get("shared", "")
                        ),
                        comment=test.get("comment", ""),
                        result=test.get("result", "invalid"),
                        flags=test.get("flags", []),
                    )
                )

        return vectors

    @staticmethod
    def parse_ecdsa_file(file_path: str) -> List[ECDSATestVector]:
        """
        Parse Wycheproof ECDSA test vector JSON file.

        Format:
        {
          "algorithm": "ECDSA",
          "testGroups": [{
            "curve": "brainpoolP256r1",
            "sha": "SHA-256",
            "type": "EcdsaVerify",
            "tests": [{
              "tcId": 1,
              "comment": "...",
              "msg": "...",
              "key": {
                "curve": "...",
                "keySize": 256,
                "type": "EcPublicKey",
                "uncompressed": "...",
                "wx": "...",
                "wy": "..."
              },
              "sig": "...",
              "result": "valid"
            }]
          }]
        }
        """
        vectors = []

        with open(file_path, "r") as f:
            data = json.load(f)

        for group in data.get("testGroups", []):
            # In Wycheproof ECDSA format, curve is in publicKey dict, not at group level
            pub_key_info = group.get("publicKey", {})
            if isinstance(pub_key_info, dict):
                curve = pub_key_info.get("curve", "")
            else:
                # Fallback: check group level
                curve = group.get("curve", "")

            if "brainpool" not in curve.lower():
                continue

            sha_algo = group.get("sha", "")

            # Get public key from group level (Wycheproof format)
            # Try publicKeyDer (DER-encoded), publicKeyPem, or publicKey (hex)
            pub_key_der = group.get("publicKeyDer", "")
            pub_key_pem = group.get("publicKeyPem", "")
            pub_key_hex = group.get("publicKey", {})

            # Prefer uncompressed hex from publicKey dict (most reliable), then DER, then PEM
            if isinstance(pub_key_hex, dict):
                # publicKey is a dict with uncompressed field - this is most reliable
                uncompressed_hex = pub_key_hex.get("uncompressed", "")
                pub_key = WycheproofParser.hex_to_bytes(uncompressed_hex)
            elif pub_key_der:
                # DER is base64 encoded
                import base64

                try:
                    pub_key = base64.b64decode(pub_key_der)
                except Exception:
                    pub_key = b""
            elif pub_key_pem:
                # PEM is text, convert to bytes for storage
                pub_key = pub_key_pem.encode("utf-8")
            elif pub_key_hex:
                # Fallback: treat as hex string
                pub_key = WycheproofParser.hex_to_bytes(pub_key_hex)
            else:
                pub_key = b""

            for test in group.get("tests", []):
                msg = WycheproofParser.hex_to_bytes(test.get("msg", ""))
                sig = WycheproofParser.hex_to_bytes(test.get("sig", ""))

                # Also check if test has its own key info (fallback)
                if not pub_key:
                    key_info = test.get("key", {})
                    pub_key = WycheproofParser.hex_to_bytes(
                        key_info.get("uncompressed", "")
                    )

                # Extract private key if available (may not be in all test vectors)
                private_key = b""  # Usually not in verify-only test vectors

                # Parse signature - Wycheproof uses DER-encoded signatures
                # Try to decode DER signature to get r and s
                sig_r = b""
                sig_s = b""

                try:
                    from cryptography.hazmat.primitives.asymmetric.utils import (
                        decode_dss_signature,
                    )

                    # Try to decode as DER
                    r, s = decode_dss_signature(sig)
                    # Get component size based on curve
                    curve_size = int(curve.replace("brainpoolP", "").replace("r1", ""))
                    component_size = curve_size // 8
                    # Convert back to bytes (pad to component_size)
                    sig_r = r.to_bytes(component_size, "big")
                    sig_s = s.to_bytes(component_size, "big")
                except Exception:
                    # If DER decoding fails, try raw format (r and s concatenated)
                    if len(sig) >= 64:  # Minimum 256 bits = 32 bytes each for r and s
                        curve_size = int(
                            curve.replace("brainpoolP", "").replace("r1", "")
                        )
                        component_size = curve_size // 8

                        if len(sig) >= component_size * 2:
                            sig_r = sig[:component_size]
                            sig_s = sig[component_size : component_size * 2]
                        else:
                            # Try splitting in half
                            sig_r = sig[: len(sig) // 2]
                            sig_s = sig[len(sig) // 2 :]

                vectors.append(
                    ECDSATestVector(
                        tc_id=test.get("tcId", 0),
                        curve=curve,
                        message=msg,
                        private_key=private_key,
                        public_key=pub_key,
                        signature_r=sig_r,
                        signature_s=sig_s,
                        comment=f"{test.get('comment', '')} ({sha_algo})",
                        result=test.get("result", "invalid"),
                        flags=test.get("flags", []),
                    )
                )

        return vectors


class RFC5639Parser:
    """Parser for RFC 5639 Brainpool curve parameters."""

    @staticmethod
    def parse_curve_params(file_path: str) -> List[RFC5639CurveParams]:
        """
        Parse RFC 5639 curve parameters.

        Format can vary, but typically includes:
        brainpoolP256r1:
          p = ...
          a = ...
          b = ...
          G = (x, y)
          n = ...
          h = ...
        """
        params = []

        with open(file_path, "r") as f:
            content = f.read()

        # RFC 5639 format varies - try common patterns
        # Pattern 1: brainpoolP256r1: p=..., a=..., b=..., etc.
        curve_block_pattern = r"(brainpoolP\d+r1)[:\s]+(?:p\s*=\s*([0-9a-fA-F]+))?\s*(?:a\s*=\s*([0-9a-fA-F]+))?\s*(?:b\s*=\s*([0-9a-fA-F]+))?\s*(?:G\s*=\s*\(([^,]+),\s*([^)]+)\))?\s*(?:n\s*=\s*([0-9a-fA-F]+))?\s*(?:h\s*=\s*(\d+))?"

        matches = re.finditer(
            curve_block_pattern, content, re.IGNORECASE | re.MULTILINE
        )

        for match in matches:
            try:
                curve_name = match.group(1)
                p_hex = match.group(2) or ""
                a_hex = match.group(3) or ""
                b_hex = match.group(4) or ""
                gx_hex = match.group(5) or ""
                gy_hex = match.group(6) or ""
                n_hex = match.group(7) or ""
                h_str = match.group(8) or "1"

                # Convert hex strings to integers if present
                if p_hex:
                    p = int(p_hex, 16) if p_hex else 0
                    a = int(a_hex, 16) if a_hex else 0
                    b = int(b_hex, 16) if b_hex else 0
                    gx = int(gx_hex, 16) if gx_hex else 0
                    gy = int(gy_hex, 16) if gy_hex else 0
                    n = int(n_hex, 16) if n_hex else 0
                    h = int(h_str) if h_str else 1

                    params.append(
                        RFC5639CurveParams(
                            curve_name=curve_name, p=p, a=a, b=b, gx=gx, gy=gy, n=n, h=h
                        )
                    )
            except (ValueError, AttributeError):
                # Skip malformed entries
                continue

        return params


def download_wycheproof_vectors(curve: str, test_type: str = "ecdh") -> Optional[str]:
    """
    Get Wycheproof test vectors from local directory or download.

    Args:
        curve: Curve name (e.g., 'brainpoolP256r1')
        test_type: 'ecdh' or 'ecdsa'

    Returns:
        Path to test vector file or None
    """
    import urllib.request
    from pathlib import Path

    test_vectors_dir = Path(__file__).parent / "test_vectors"
    test_vectors_dir.mkdir(exist_ok=True)

    if test_type == "ecdh":
        filename = f"ecdh_{curve}_test.json"
    elif test_type == "ecdsa":
        # Try common SHA variants
        for sha_var in ["sha256", "sha384", "sha512"]:
            filename = f"ecdsa_{curve}_{sha_var}_test.json"
            local_path = test_vectors_dir / filename
            if local_path.exists():
                return str(local_path)
        # Default to sha256 if none found
        filename = f"ecdsa_{curve}_sha256_test.json"
    else:
        return None

    local_path = test_vectors_dir / filename

    # Check if file exists locally first
    if local_path.exists():
        return str(local_path)

    # Try to download if not present
    base_url = "https://raw.githubusercontent.com/google/wycheproof/master/testvectors"
    url = f"{base_url}/{filename}"

    try:
        print(f"Downloading {filename} from Wycheproof...")
        urllib.request.urlretrieve(url, str(local_path))
        print(f"Downloaded to {local_path}")
        return str(local_path)
    except Exception as e:
        print(f"Failed to download {filename}: {e}")
        return None
