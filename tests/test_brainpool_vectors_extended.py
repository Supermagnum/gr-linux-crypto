#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extended Brainpool test vector parsers for multiple sources.

Supports:
- OpenSSL test vectors
- Linux kernel testmgr.h format
- mbedTLS test data format
- libgcrypt test format
"""

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class LinuxKernelTestVector:
    """Linux kernel testmgr.h test vector."""

    curve_name: str
    private_key: bytes
    public_key_x: bytes
    public_key_y: bytes
    shared_secret: bytes
    description: str


@dataclass
class OpenSSLTestVector:
    """OpenSSL test vector."""

    curve_name: str
    private_key: bytes
    public_key: bytes
    shared_secret: Optional[bytes]
    signature: Optional[bytes]
    message: Optional[bytes]
    description: str


@dataclass
class MbedTLSTestVector:
    """mbedTLS test data vector."""

    curve_id: str
    private_key: bytes
    public_key: bytes
    shared_secret: bytes
    description: str


class LinuxKernelParser:
    """Parser for Linux kernel testmgr.h Brainpool test vectors."""

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex array string to bytes."""
        # Format: { 0x12, 0x34, 0x56, ... }
        hex_values = re.findall(r"0x([0-9a-fA-F]{2})", hex_str)
        return bytes([int(h, 16) for h in hex_values])

    @staticmethod
    def parse_testmgr_file(file_path: str) -> List[LinuxKernelTestVector]:
        """
        Parse Linux kernel testmgr.h Brainpool test vectors.

        Format:
        static const struct dh_testvec brainpoolP256r1_dh_tv_template[] = {
            {
                .secret = { 0x... },
                .b_public = {
                    .x = { 0x... },
                    .y = { 0x... },
                },
                .expected_a_public = {
                    .x = { 0x... },
                    .y = { 0x... },
                },
                .expected_shared = { 0x... },
            },
        };
        """
        vectors = []

        with open(file_path, "r") as f:
            content = f.read()

        # Find Brainpool test vector sections
        # Look for patterns like "brainpoolP256r1_dh_tv_template" or similar
        brainpool_patterns = [
            r"brainpoolP256r1[^{]*\{([^}]+)\}",
            r"brainpoolP384r1[^{]*\{([^}]+)\}",
            r"brainpoolP512r1[^{]*\{([^}]+)\}",
        ]

        for pattern in brainpool_patterns:
            matches = re.finditer(pattern, content, re.DOTALL)
            for match in matches:
                curve_name = pattern.replace(r"[^{]*\{([^}]+)\}", "").replace("r", "r")
                vector_content = match.group(1)

                # Extract fields
                secret_match = re.search(r"\.secret\s*=\s*\{([^}]+)\}", vector_content)
                x_match = re.search(r"\.x\s*=\s*\{([^}]+)\}", vector_content)
                y_match = re.search(r"\.y\s*=\s*\{([^}]+)\}", vector_content)
                shared_match = re.search(
                    r"\.expected_shared\s*=\s*\{([^}]+)\}", vector_content
                )

                if secret_match and x_match and y_match and shared_match:
                    vectors.append(
                        LinuxKernelTestVector(
                            curve_name=curve_name,
                            private_key=LinuxKernelParser.hex_to_bytes(
                                secret_match.group(1)
                            ),
                            public_key_x=LinuxKernelParser.hex_to_bytes(
                                x_match.group(1)
                            ),
                            public_key_y=LinuxKernelParser.hex_to_bytes(
                                y_match.group(1)
                            ),
                            shared_secret=LinuxKernelParser.hex_to_bytes(
                                shared_match.group(1)
                            ),
                            description=f"Linux kernel testmgr.h {curve_name}",
                        )
                    )

        return vectors


class OpenSSLTestParser:
    """Parser for OpenSSL test vectors."""

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        hex_clean = re.sub(r"[\s\n\r:,\"]", "", hex_str)
        return bytes.fromhex(hex_clean)

    @staticmethod
    def parse_evp_test_file(file_path: str) -> List[OpenSSLTestVector]:
        """
        Parse OpenSSL EVP test data files.

        Format can vary, but typically includes:
        - Curve names
        - Private/public keys
        - Expected results
        """
        vectors = []

        with open(file_path, "r") as f:
            content = f.read()

        # Look for Brainpool references
        # Format can be various - look for curve names and hex data
        brainpool_curves = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]

        for curve in brainpool_curves:
            # Find sections with this curve
            pattern = rf"{re.escape(curve)}[^{{]*\{{([^}}]+)\}}"
            matches = re.finditer(pattern, content, re.DOTALL | re.IGNORECASE)

            for match in matches:
                test_content = match.group(1)

                # Extract key components (format varies)
                priv_match = re.search(
                    r"priv(?:ate)?[^:]*[:=]\s*([0-9a-fA-F\s]+)", test_content
                )
                pub_match = re.search(
                    r"pub(?:lic)?[^:]*[:=]\s*([0-9a-fA-F\s]+)", test_content
                )

                if priv_match or pub_match:
                    vectors.append(
                        OpenSSLTestVector(
                            curve_name=curve,
                            private_key=(
                                OpenSSLTestParser.hex_to_bytes(priv_match.group(1))
                                if priv_match
                                else b""
                            ),
                            public_key=(
                                OpenSSLTestParser.hex_to_bytes(pub_match.group(1))
                                if pub_match
                                else b""
                            ),
                            shared_secret=None,
                            signature=None,
                            message=None,
                            description=f"OpenSSL {curve}",
                        )
                    )

        return vectors


class MbedTLSParser:
    """Parser for mbedTLS test data format."""

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert hex string to bytes."""
        hex_clean = re.sub(r"[\s\n\r]", "", hex_str)
        return bytes.fromhex(hex_clean)

    @staticmethod
    def parse_test_data_file(file_path: str) -> List[MbedTLSTestVector]:
        """
        Parse mbedTLS test data files.

        Format:
        # Curve name
        curve: brainpoolP256r1
        dA: <hex>
        xA: <hex>
        yA: <hex>
        xB: <hex>
        yB: <hex>
        Z: <hex>
        """
        vectors = []

        with open(file_path, "r") as f:
            lines = f.readlines()

        current_vector = {}
        in_brainpool_section = False

        for line in lines:
            line = line.strip()

            if line.startswith("#") or not line:
                continue

            # Check if this is a Brainpool curve section
            if "curve:" in line.lower():
                curve_name = line.split(":")[1].strip()
                if "brainpool" in curve_name.lower():
                    in_brainpool_section = True
                    current_vector = {"curve_id": curve_name}
                else:
                    in_brainpool_section = False
                    current_vector = {}
                continue

            if not in_brainpool_section:
                continue

            # Parse key-value pairs
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()

                if key == "da" or key == "d":
                    current_vector["private_key"] = MbedTLSParser.hex_to_bytes(value)
                elif key == "xa" or key == "xb":
                    if "public_x" not in current_vector:
                        current_vector["public_x"] = MbedTLSParser.hex_to_bytes(value)
                elif key == "ya" or key == "yb":
                    if "public_y" not in current_vector:
                        current_vector["public_y"] = MbedTLSParser.hex_to_bytes(value)
                elif key == "z":
                    current_vector["shared_secret"] = MbedTLSParser.hex_to_bytes(value)

                # If we have all required fields, create vector
                if all(
                    k in current_vector
                    for k in ["private_key", "public_x", "public_y", "shared_secret"]
                ):
                    # Combine x and y into public key (uncompressed format: 04 + x + y)
                    pub_key = (
                        b"\x04"
                        + current_vector["public_x"]
                        + current_vector["public_y"]
                    )

                    vectors.append(
                        MbedTLSTestVector(
                            curve_id=current_vector["curve_id"],
                            private_key=current_vector["private_key"],
                            public_key=pub_key,
                            shared_secret=current_vector["shared_secret"],
                            description=f"mbedTLS {current_vector['curve_id']}",
                        )
                    )
                    current_vector = {}

        return vectors


def download_linux_kernel_testmgr() -> Optional[str]:
    """Download Linux kernel testmgr.h."""
    import urllib.request
    from pathlib import Path

    url = "https://raw.githubusercontent.com/torvalds/linux/master/crypto/testmgr.h"
    output_path = Path(__file__).parent / "test_vectors" / "testmgr.h"

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not output_path.exists():
            print("Downloading testmgr.h from Linux kernel...")
            urllib.request.urlretrieve(url, str(output_path))
            print(f"Downloaded to {output_path}")

        return str(output_path)
    except Exception as e:
        print(f"Failed to download testmgr.h: {e}")
        return None


def extract_brainpool_from_testmgr(file_path: str) -> List[LinuxKernelTestVector]:
    """Extract Brainpool test vectors from testmgr.h."""
    vectors = []

    try:
        with open(file_path, "r") as f:
            content = f.read()

        # Search for Brainpool patterns
        # Linux kernel uses specific struct definitions
        brainpool_pattern = r"brainpoolP(\d+)r1"
        matches = re.finditer(brainpool_pattern, content, re.IGNORECASE)

        for match in matches:
            curve_size = match.group(1)
            curve_name = f"brainpoolP{curve_size}r1"

            # Look for test vector structures after curve name
            # This is a simplified extraction - actual parsing would need
            # to understand the C struct layout

            # Try to find ECDH test vectors
            pattern = rf"{re.escape(curve_name)}[^{{]*\{{([^}}]+\}})"
            struct_matches = re.finditer(pattern, content, re.DOTALL)

            for struct_match in struct_matches[:5]:  # Limit to first 5 matches
                struct_content = struct_match.group(1)

                # Extract hex arrays - Linux kernel uses C array format
                # Pattern: .private_key = { 0x12, 0x34, ... } or .private_key = {0x1234, ...}
                private_key_pattern = r"\.private_key\s*=\s*\{([^}]+)\}"
                public_key_pattern = r"\.public_key\s*=\s*\{([^}]+)\}"
                expected_pattern = r"\.expected\s*=\s*\{([^}]+)\}"

                private_match = re.search(
                    private_key_pattern, struct_content, re.IGNORECASE
                )
                public_match = re.search(
                    public_key_pattern, struct_content, re.IGNORECASE
                )
                expected_match = re.search(
                    expected_pattern, struct_content, re.IGNORECASE
                )

                if private_match and public_match and expected_match:
                    try:
                        # Extract hex bytes from C array format
                        def extract_hex_bytes(hex_str):
                            hex_vals = re.findall(r"0x([0-9a-fA-F]{2})", hex_str)
                            return bytes([int(h, 16) for h in hex_vals])

                        private_key = extract_hex_bytes(private_match.group(1))
                        public_key = extract_hex_bytes(public_match.group(1))
                        shared_secret = extract_hex_bytes(expected_match.group(1))

                        if private_key and public_key and shared_secret:
                            vectors.append(
                                LinuxKernelTestVector(
                                    curve=curve_name,
                                    private_key=private_key,
                                    public_key=public_key,
                                    shared_secret=shared_secret,
                                    test_type="ECDH",
                                )
                            )
                    except (ValueError, IndexError):
                        # Skip malformed entries
                        continue

        print(f"Extracted {len(vectors)} Brainpool vectors from testmgr.h")
        return vectors

    except Exception as e:
        print(f"Error parsing testmgr.h: {e}")
        return []
