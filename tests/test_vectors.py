#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test vector parsers for NIST CAVP and RFC 8439 test vectors.

Provides parsers for:
- NIST CAVP AES-GCM test vectors
- RFC 8439 ChaCha20-Poly1305 test vectors
"""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class AESGCMTestVector:
    """AES-GCM test vector data structure."""
    count: int
    key: bytes
    iv: bytes
    plaintext: bytes
    aad: Optional[bytes]  # Additional authenticated data
    ciphertext: bytes
    tag: bytes
    description: Optional[str] = None


@dataclass
class ChaCha20Poly1305TestVector:
    """ChaCha20-Poly1305 test vector data structure."""
    test_case: int
    key: bytes
    nonce: bytes
    plaintext: bytes
    aad: Optional[bytes]  # Additional authenticated data
    ciphertext: bytes
    tag: bytes
    description: Optional[str] = None


class NISTCAVPParser:
    """Parser for NIST CAVP test vector format."""
    
    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes, handling whitespace."""
        hex_clean = re.sub(r'[\s\n\r]', '', hex_str)
        return bytes.fromhex(hex_clean)
    
    @staticmethod
    def parse_aes_gcm_file(file_path: str) -> List[AESGCMTestVector]:
        """
        Parse NIST CAVP AES-GCM test vector file.
        
        Format example:
        Count = 0
        Key = 00000000000000000000000000000000
        IV = 000000000000000000000000
        PT = 
        AAD = 
        CT = 
        Tag = 58e2fccefa7e3061367f1d57a4e7455a
        """
        vectors = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Normalize line endings
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        # Split into individual test vector blocks
        # Look for "Count = " or "COUNT = " as vector separators
        vector_blocks = re.split(r'(?=^Count\s*=\s*\d+|^COUNT\s*=\s*\d+)', content, flags=re.MULTILINE)
        
        current_vector = {}
        
        for block in vector_blocks:
            block = block.strip()
            if not block or block.startswith('#'):
                continue
            
            lines = block.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse key-value pairs (more flexible pattern)
                match = re.match(r'^([A-Za-z]+)\s*=\s*(.*)$', line)
                if match:
                    key = match.group(1).upper()
                    value = match.group(2).strip()
                    
                    if key == 'COUNT':
                        # New vector, save previous if exists
                        if current_vector and 'key' in current_vector:
                            vectors.append(NISTCAVPParser._create_aes_gcm_vector(current_vector))
                        try:
                            current_vector = {'count': int(value)}
                        except ValueError:
                            continue
                    
                    elif key == 'KEY':
                        try:
                            current_vector['key'] = NISTCAVPParser.hex_to_bytes(value)
                        except (ValueError, TypeError) as e:
                            print(f"Warning: Invalid key in vector {current_vector.get('count', 'unknown')}: {e}")
                            continue
                    
                    elif key == 'IV':
                        try:
                            current_vector['iv'] = NISTCAVPParser.hex_to_bytes(value)
                        except (ValueError, TypeError) as e:
                            print(f"Warning: Invalid IV in vector {current_vector.get('count', 'unknown')}: {e}")
                            continue
                    
                    elif key == 'PT':
                        current_vector['plaintext'] = NISTCAVPParser.hex_to_bytes(value)
                    
                    elif key == 'AAD':
                        current_vector['aad'] = NISTCAVPParser.hex_to_bytes(value) if value else None
                    
                    elif key == 'CT':
                        current_vector['ciphertext'] = NISTCAVPParser.hex_to_bytes(value)
                    
                    elif key == 'TAG':
                        try:
                            current_vector['tag'] = NISTCAVPParser.hex_to_bytes(value)
                        except (ValueError, TypeError) as e:
                            print(f"Warning: Invalid tag in vector {current_vector.get('count', 'unknown')}: {e}")
                            continue
            
            # Handle last vector in block
            if current_vector and 'key' in current_vector:
                vectors.append(NISTCAVPParser._create_aes_gcm_vector(current_vector))
                current_vector = {}
        
        # Handle any remaining vector
        if current_vector and 'key' in current_vector:
            vectors.append(NISTCAVPParser._create_aes_gcm_vector(current_vector))
        
        return vectors
    
    @staticmethod
    def _create_aes_gcm_vector(data: Dict) -> AESGCMTestVector:
        """Create AESGCMTestVector from parsed data."""
        return AESGCMTestVector(
            count=data.get('count', 0),
            key=data.get('key', b''),
            iv=data.get('iv', b''),
            plaintext=data.get('plaintext', b''),
            aad=data.get('aad'),
            ciphertext=data.get('ciphertext', b''),
            tag=data.get('tag', b''),
            description=f"Test vector {data.get('count', 0)}"
        )


class RFC8439Parser:
    """Parser for RFC 8439 ChaCha20-Poly1305 test vectors."""
    
    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes, handling empty strings."""
        if not hex_str:
            return b""
        hex_clean = re.sub(r'[\s\n\r]', '', hex_str)
        if not hex_clean:
            return b""
        return bytes.fromhex(hex_clean)
    
    @staticmethod
    def parse_chacha20_poly1305_file(file_path: str) -> List[ChaCha20Poly1305TestVector]:
        """
        Parse RFC 8439 ChaCha20-Poly1305 test vector file.
        
        Format can vary, but typical format:
        Test Vector #1:
        Key: ...
        Nonce: ...
        PT: ...
        AAD: ...
        CT: ...
        Tag: ...
        """
        vectors = []
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Split by test vector markers
        test_blocks = re.split(r'Test\s+Vector\s+#?\s*(\d+)', content, flags=re.IGNORECASE)
        
        for i in range(1, len(test_blocks), 2):
            if i + 1 >= len(test_blocks):
                break
            
            test_case_num = int(test_blocks[i])
            test_content = test_blocks[i + 1]
            
            vector_data = RFC8439Parser._parse_test_block(test_content)
            if vector_data:
                vectors.append(ChaCha20Poly1305TestVector(
                    test_case=test_case_num,
                    key=vector_data.get('key', b''),
                    nonce=vector_data.get('nonce', b''),
                    plaintext=vector_data.get('plaintext', b''),
                    aad=vector_data.get('aad'),
                    ciphertext=vector_data.get('ciphertext', b''),
                    tag=vector_data.get('tag', b''),
                    description=f"RFC 8439 Test Vector #{test_case_num}"
                ))
        
        return vectors
    
    @staticmethod
    def _parse_test_block(block: str) -> Optional[Dict]:
        """Parse a single test vector block."""
        data = {}
        lines = block.split('\n')
        
        current_field = None
        current_value = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Check for field markers
            field_match = re.match(r'^(Key|Nonce|PT|AAD|CT|Tag|Ciphertext|Plaintext|AuthTag):\s*(.*)$', 
                                  line, re.IGNORECASE)
            
            if field_match:
                # Save previous field
                if current_field and current_value:
                    data[current_field.lower()] = RFC8439Parser.hex_to_bytes(''.join(current_value))
                    current_value = []
                
                current_field = field_match.group(1).lower()
                value_part = field_match.group(2).strip()
                if value_part:
                    current_value.append(value_part)
            
            elif current_field:
                # Continuation of current field
                current_value.append(line)
        
        # Save last field
        if current_field and current_value:
            data[current_field] = RFC8439Parser.hex_to_bytes(''.join(current_value))
        
        # Normalize field names
        result = {}
        if 'key' in data:
            result['key'] = data['key']
        if 'nonce' in data:
            result['nonce'] = data['nonce']
        if 'pt' in data or 'plaintext' in data:
            result['plaintext'] = data.get('pt') or data.get('plaintext', b'')
        if 'aad' in data:
            result['aad'] = data['aad'] if data['aad'] else None
        if 'ct' in data or 'ciphertext' in data:
            result['ciphertext'] = data.get('ct') or data.get('ciphertext', b'')
        if 'tag' in data or 'authtag' in data:
            result['tag'] = data.get('tag') or data.get('authtag', b'')
        
        return result if result else None


def download_nist_vectors(url: Optional[str] = None) -> str:
    """
    Download NIST CAVP test vectors.
    
    Returns path to downloaded file or raises exception.
    """
    import urllib.request
    import tempfile
    
    # Default NIST CAVP AES-GCM test vectors URL
    # Note: You may need to update this URL based on NIST's current location
    if url is None:
        url = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.zip"
    
    # For now, return a path that should contain manually downloaded vectors
    # Users should download from NIST and place in tests/test_vectors/ directory
    raise NotImplementedError(
        "Automatic download not implemented. Please download NIST CAVP test vectors "
        "from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-testing"
        " and place in tests/test_vectors/ directory"
    )

