#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RFC Test Vector Parsers for Brainpool Elliptic Curve Cryptography.

This module provides parsers for test vectors from:
- RFC 7027: Additional Elliptic Curves for OpenPGP (Brainpool curves)
- RFC 6954: Using the Elliptic Curve Diffie-Hellman Key Agreement Algorithm
            with Brainpool curves in IKEv2
- RFC 8734: Using Brainpool Curves in TLS 1.3

These RFCs provide standardized test vectors for Brainpool curves in various
protocol contexts.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class RFC7027TestVector:
    """Test vector from RFC 7027 (OpenPGP with Brainpool curves)."""

    curve_name: str
    private_key: bytes
    public_key: bytes
    message: bytes
    signature: Optional[bytes] = None
    key_id: Optional[str] = None
    comment: str = ""


@dataclass
class RFC6954TestVector:
    """Test vector from RFC 6954 (IKEv2 with Brainpool curves)."""

    curve_name: str
    initiator_private: bytes
    initiator_public: bytes
    responder_private: bytes
    responder_public: bytes
    shared_secret: bytes
    comment: str = ""


@dataclass
class RFC8734TestVector:
    """Test vector from RFC 8734 (TLS 1.3 with Brainpool curves)."""

    curve_name: str
    client_private: bytes
    client_public: bytes
    server_private: bytes
    server_public: bytes
    shared_secret: bytes
    handshake_hash: Optional[bytes] = None
    comment: str = ""


class RFC7027Parser:
    """Parser for RFC 7027 test vectors."""

    @staticmethod
    def parse_file(file_path: str) -> List[RFC7027TestVector]:
        """
        Parse RFC 7027 test vector file.

        RFC 7027 format is typically text-based with hex-encoded values.
        """
        vectors = []
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            return vectors

        # RFC 7027 test vectors are typically in text format
        # Format: Curve name, private key, public key, message, signature
        with open(file_path, "r") as f:
            content = f.read()

        # Try to parse as JSON first (if someone converted it)
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    vector = RFC7027Parser._parse_json_item(item)
                    if vector:
                        vectors.append(vector)
                return vectors
        except json.JSONDecodeError:
            pass

        # Parse as text format (typical RFC format)
        # Look for patterns like: Curve: brainpoolP256r1, Private: ..., Public: ...
        lines = content.split("\n")
        current_vector = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Try to match RFC 7027 format patterns
            if "curve" in line.lower() or "brainpool" in line.lower():
                match = re.search(r"brainpoolP(\d+)r1", line, re.IGNORECASE)
                if match:
                    current_vector["curve_name"] = f"brainpoolP{match.group(1)}r1"

            if "private" in line.lower() and "key" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                if hex_match:
                    current_vector["private_key"] = bytes.fromhex(hex_match.group(1))

            if "public" in line.lower() and "key" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                if hex_match:
                    current_vector["public_key"] = bytes.fromhex(hex_match.group(1))

            if "message" in line.lower() or "data" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]+)", line)
                if hex_match:
                    current_vector["message"] = bytes.fromhex(hex_match.group(1))

            if "signature" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                if hex_match:
                    current_vector["signature"] = bytes.fromhex(hex_match.group(1))

            # If we have enough data, create a vector
            if all(
                k in current_vector for k in ["curve_name", "private_key", "public_key"]
            ):
                vectors.append(
                    RFC7027TestVector(
                        curve_name=current_vector["curve_name"],
                        private_key=current_vector["private_key"],
                        public_key=current_vector["public_key"],
                        message=current_vector.get("message", b""),
                        signature=current_vector.get("signature"),
                        comment=current_vector.get("comment", ""),
                    )
                )
                current_vector = {}

        return vectors

    @staticmethod
    def _parse_json_item(item: Dict) -> Optional[RFC7027TestVector]:
        """Parse a single JSON item into a test vector."""
        try:
            # Skip placeholder entries
            if "note" in item or (
                not item.get("curve") and not item.get("private_key")
            ):
                return None

            curve = item.get("curve", "")
            private_key_hex = item.get("private_key", "")

            # Skip if essential fields are missing
            if not curve or not private_key_hex:
                return None

            return RFC7027TestVector(
                curve_name=curve,
                private_key=bytes.fromhex(private_key_hex),
                public_key=bytes.fromhex(item.get("public_key", "")),
                message=bytes.fromhex(item.get("message", "")),
                signature=(
                    bytes.fromhex(item.get("signature", ""))
                    if item.get("signature")
                    else None
                ),
                key_id=item.get("key_id"),
                comment=item.get("comment", ""),
            )
        except (KeyError, ValueError):
            return None


class RFC6954Parser:
    """Parser for RFC 6954 test vectors (IKEv2)."""

    @staticmethod
    def parse_file(file_path: str) -> List[RFC6954TestVector]:
        """
        Parse RFC 6954 test vector file.

        RFC 6954 provides ECDH test vectors for IKEv2.
        """
        vectors = []
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            return vectors

        with open(file_path, "r") as f:
            content = f.read()

        # Try JSON first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    vector = RFC6954Parser._parse_json_item(item)
                    if vector:
                        vectors.append(vector)
                return vectors
        except json.JSONDecodeError:
            pass

        # Parse text format
        lines = content.split("\n")
        current_vector = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Match curve name
            if "curve" in line.lower() or "brainpool" in line.lower():
                match = re.search(r"brainpoolP(\d+)r1", line, re.IGNORECASE)
                if match:
                    current_vector["curve_name"] = f"brainpoolP{match.group(1)}r1"

            # Match initiator/responder keys
            if "initiator" in line.lower():
                if "private" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                    if hex_match:
                        current_vector["initiator_private"] = bytes.fromhex(
                            hex_match.group(1)
                        )
                elif "public" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                    if hex_match:
                        current_vector["initiator_public"] = bytes.fromhex(
                            hex_match.group(1)
                        )

            if "responder" in line.lower():
                if "private" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                    if hex_match:
                        current_vector["responder_private"] = bytes.fromhex(
                            hex_match.group(1)
                        )
                elif "public" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                    if hex_match:
                        current_vector["responder_public"] = bytes.fromhex(
                            hex_match.group(1)
                        )

            if "shared" in line.lower() and "secret" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                if hex_match:
                    current_vector["shared_secret"] = bytes.fromhex(hex_match.group(1))

            # Create vector when we have all required fields
            required = [
                "curve_name",
                "initiator_private",
                "initiator_public",
                "responder_private",
                "responder_public",
                "shared_secret",
            ]
            if all(k in current_vector for k in required):
                vectors.append(
                    RFC6954TestVector(
                        curve_name=current_vector["curve_name"],
                        initiator_private=current_vector["initiator_private"],
                        initiator_public=current_vector["initiator_public"],
                        responder_private=current_vector["responder_private"],
                        responder_public=current_vector["responder_public"],
                        shared_secret=current_vector["shared_secret"],
                        comment=current_vector.get("comment", ""),
                    )
                )
                current_vector = {}

        return vectors

    @staticmethod
    def _parse_json_item(item: Dict) -> Optional[RFC6954TestVector]:
        """Parse a single JSON item into a test vector."""
        try:
            # Skip placeholder entries
            if "note" in item or (
                not item.get("curve") and not item.get("initiator_private")
            ):
                return None

            curve = item.get("curve", "")
            initiator_private_hex = item.get("initiator_private", "")

            # Skip if essential fields are missing
            if not curve or not initiator_private_hex:
                return None

            return RFC6954TestVector(
                curve_name=curve,
                initiator_private=bytes.fromhex(initiator_private_hex),
                initiator_public=bytes.fromhex(item.get("initiator_public", "")),
                responder_private=bytes.fromhex(item.get("responder_private", "")),
                responder_public=bytes.fromhex(item.get("responder_public", "")),
                shared_secret=bytes.fromhex(item.get("shared_secret", "")),
                comment=item.get("comment", ""),
            )
        except (KeyError, ValueError):
            return None


class RFC8734Parser:
    """Parser for RFC 8734 test vectors (TLS 1.3)."""

    @staticmethod
    def parse_file(file_path: str) -> List[RFC8734TestVector]:
        """
        Parse RFC 8734 test vector file.

        RFC 8734 provides ECDH test vectors for TLS 1.3 with Brainpool curves.
        """
        vectors = []
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            return vectors

        with open(file_path, "r") as f:
            content = f.read()

        # Try JSON first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    vector = RFC8734Parser._parse_json_item(item)
                    if vector:
                        vectors.append(vector)
                return vectors
        except json.JSONDecodeError:
            pass

        # Parse text format
        lines = content.split("\n")
        current_vector = {}

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Match curve name
            if "curve" in line.lower() or "brainpool" in line.lower():
                match = re.search(r"brainpoolP(\d+)r1", line, re.IGNORECASE)
                if match:
                    current_vector["curve_name"] = f"brainpoolP{match.group(1)}r1"

            # Match client/server keys
            if "client" in line.lower():
                if "private" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                    if hex_match:
                        current_vector["client_private"] = bytes.fromhex(
                            hex_match.group(1)
                        )
                elif "public" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                    if hex_match:
                        current_vector["client_public"] = bytes.fromhex(
                            hex_match.group(1)
                        )

            if "server" in line.lower():
                if "private" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                    if hex_match:
                        current_vector["server_private"] = bytes.fromhex(
                            hex_match.group(1)
                        )
                elif "public" in line.lower():
                    hex_match = re.search(r"([0-9a-fA-F]{128,})", line)
                    if hex_match:
                        current_vector["server_public"] = bytes.fromhex(
                            hex_match.group(1)
                        )

            if "shared" in line.lower() and "secret" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                if hex_match:
                    current_vector["shared_secret"] = bytes.fromhex(hex_match.group(1))

            if "handshake" in line.lower() and "hash" in line.lower():
                hex_match = re.search(r"([0-9a-fA-F]{64,})", line)
                if hex_match:
                    current_vector["handshake_hash"] = bytes.fromhex(hex_match.group(1))

            # Create vector when we have all required fields
            required = [
                "curve_name",
                "client_private",
                "client_public",
                "server_private",
                "server_public",
                "shared_secret",
            ]
            if all(k in current_vector for k in required):
                vectors.append(
                    RFC8734TestVector(
                        curve_name=current_vector["curve_name"],
                        client_private=current_vector["client_private"],
                        client_public=current_vector["client_public"],
                        server_private=current_vector["server_private"],
                        server_public=current_vector["server_public"],
                        shared_secret=current_vector["shared_secret"],
                        handshake_hash=current_vector.get("handshake_hash"),
                        comment=current_vector.get("comment", ""),
                    )
                )
                current_vector = {}

        return vectors

    @staticmethod
    def _parse_json_item(item: Dict) -> Optional[RFC8734TestVector]:
        """Parse a single JSON item into a test vector."""
        try:
            # Skip placeholder entries
            if "note" in item or (
                not item.get("curve") and not item.get("client_private")
            ):
                return None

            curve = item.get("curve", "")
            client_private_hex = item.get("client_private", "")

            # Skip if essential fields are missing
            if not curve or not client_private_hex:
                return None

            return RFC8734TestVector(
                curve_name=curve,
                client_private=bytes.fromhex(client_private_hex),
                client_public=bytes.fromhex(item.get("client_public", "")),
                server_private=bytes.fromhex(item.get("server_private", "")),
                server_public=bytes.fromhex(item.get("server_public", "")),
                shared_secret=bytes.fromhex(item.get("shared_secret", "")),
                handshake_hash=(
                    bytes.fromhex(item.get("handshake_hash", ""))
                    if item.get("handshake_hash")
                    else None
                ),
                comment=item.get("comment", ""),
            )
        except (KeyError, ValueError):
            return None


def download_rfc_vectors():
    """
    Download RFC test vectors from IETF sources.

    Note: RFCs typically don't provide downloadable test vector files.
    Test vectors are usually embedded in the RFC text itself.
    This function provides a framework for extracting vectors from RFC text.
    """
    # RFC test vectors are typically in the RFC text itself
    # Users would need to extract them manually or use this framework
    rfc_urls = {
        "7027": "https://datatracker.ietf.org/doc/html/rfc7027",
        "6954": "https://datatracker.ietf.org/doc/html/rfc6954",
        "8734": "https://datatracker.ietf.org/doc/html/rfc8734",
    }

    return rfc_urls
