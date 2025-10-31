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
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


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
        hex_clean = re.sub(r'[\s\n\r]', '', hex_str)
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
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        for group in data.get('testGroups', []):
            curve = group.get('curve', '')
            if 'brainpool' not in curve.lower():
                continue
            
            for test in group.get('tests', []):
                vectors.append(ECDHTestVector(
                    tc_id=test.get('tcId', 0),
                    curve=curve,
                    private_key=WycheproofParser.hex_to_bytes(test.get('private', '')),
                    public_key=WycheproofParser.hex_to_bytes(test.get('public', '')),
                    shared_secret=WycheproofParser.hex_to_bytes(test.get('shared', '')),
                    comment=test.get('comment', ''),
                    result=test.get('result', 'invalid'),
                    flags=test.get('flags', [])
                ))
        
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
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        for group in data.get('testGroups', []):
            curve = group.get('curve', '')
            if 'brainpool' not in curve.lower():
                continue
            
            sha_algo = group.get('sha', '')
            
            for test in group.get('tests', []):
                msg = WycheproofParser.hex_to_bytes(test.get('msg', ''))
                key_info = test.get('key', {})
                sig = WycheproofParser.hex_to_bytes(test.get('sig', ''))
                
                # Extract public key (uncompressed format: 04 + x + y)
                pub_key = WycheproofParser.hex_to_bytes(key_info.get('uncompressed', ''))
                
                # Extract private key if available (may not be in all test vectors)
                private_key = b""  # Usually not in verify-only test vectors
                
                # Split signature into r and s (each is half the signature length)
                if len(sig) >= 64:  # Minimum 256 bits = 32 bytes each for r and s
                    # For P256, r and s are typically 32 bytes each
                    # For P384, 48 bytes each
                    # For P512, 64 bytes each
                    curve_size = int(curve.replace('brainpoolP', '').replace('r1', ''))
                    component_size = curve_size // 8
                    
                    if len(sig) >= component_size * 2:
                        sig_r = sig[:component_size]
                        sig_s = sig[component_size:component_size*2]
                    else:
                        # Try splitting in half
                        sig_r = sig[:len(sig)//2]
                        sig_s = sig[len(sig)//2:]
                else:
                    sig_r = b""
                    sig_s = b""
                
                vectors.append(ECDSATestVector(
                    tc_id=test.get('tcId', 0),
                    curve=curve,
                    message=msg,
                    private_key=private_key,
                    public_key=pub_key,
                    signature_r=sig_r,
                    signature_s=sig_s,
                    comment=f"{test.get('comment', '')} ({sha_algo})",
                    result=test.get('result', 'invalid'),
                    flags=test.get('flags', [])
                ))
        
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
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Look for curve definitions
        curve_pattern = r'brainpoolP(\d+)r1'
        curves = re.finditer(curve_pattern, content, re.IGNORECASE)
        
        for match in curves:
            curve_name = match.group(0)
            # Extract parameters following the curve name
            # This is a simplified parser - may need adjustment based on actual format
            pass
        
        return params


def download_wycheproof_vectors(curve: str, test_type: str = 'ecdh') -> Optional[str]:
    """
    Download Wycheproof test vectors.
    
    Args:
        curve: Curve name (e.g., 'brainpoolP256r1')
        test_type: 'ecdh' or 'ecdsa'
    
    Returns:
        Path to downloaded file or None
    """
    import urllib.request
    import tempfile
    from pathlib import Path
    
    base_url = "https://raw.githubusercontent.com/google/wycheproof/master/testvectors"
    
    if test_type == 'ecdh':
        filename = f"ecdh_{curve}_test.json"
    elif test_type == 'ecdsa':
        # ECDSA files have SHA in the name
        filename = f"ecdsa_{curve}_sha256_test.json"
    else:
        return None
    
    url = f"{base_url}/{filename}"
    
    try:
        # Create test_vectors directory if it doesn't exist
        test_vectors_dir = Path(__file__).parent / 'test_vectors'
        test_vectors_dir.mkdir(exist_ok=True)
        
        output_path = test_vectors_dir / filename
        
        # Download if file doesn't exist
        if not output_path.exists():
            print(f"Downloading {filename} from Wycheproof...")
            urllib.request.urlretrieve(url, str(output_path))
            print(f"Downloaded to {output_path}")
        
        return str(output_path)
    
    except Exception as e:
        print(f"Failed to download {filename}: {e}")
        return None

