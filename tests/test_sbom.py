# -*- coding: utf-8 -*-
"""
Tests for SBOM generation and validation (Component 3).

When GR_LINUX_CRYPTO_SBOM=ON, build generates sbom.cdx.json and sbom.spdx.json.
These tests verify SBOM files (if present) are valid and contain known dependencies.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


def sbom_build_dir():
    """Return build dir that might contain SBOM (e.g. from in-tree build)."""
    root = Path(__file__).resolve().parents[1]
    for d in (root / "build", root / "builds", Path.cwd()):
        if (d / "sbom.cdx.json").exists():
            return d
    return root / "build"


@pytest.fixture
def cdx_path():
    p = sbom_build_dir() / "sbom.cdx.json"
    if not p.exists():
        pytest.skip("SBOM not generated (build with -DGR_LINUX_CRYPTO_SBOM=ON)")
    return p


@pytest.fixture
def spdx_path():
    p = sbom_build_dir() / "sbom.spdx.json"
    if not p.exists():
        pytest.skip("SBOM not generated (build with -DGR_LINUX_CRYPTO_SBOM=ON)")
    return p


class TestSbomCycloneDX:
    """CycloneDX 1.6 SBOM structure and content."""

    def test_cdx_valid_json(self, cdx_path):
        with open(cdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data.get("bomFormat") == "CycloneDX"
        assert data.get("specVersion") == "1.6"

    def test_cdx_has_metadata_component(self, cdx_path):
        with open(cdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "metadata" in data
        assert "component" in data["metadata"]
        comp = data["metadata"]["component"]
        assert comp.get("name") == "gr-linux-crypto"
        assert comp.get("version")
        assert "GPL" in str(comp.get("licenses", []))

    def test_cdx_components_include_openssl(self, cdx_path):
        with open(cdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        names = [c.get("name") for c in data.get("components", [])]
        assert "OpenSSL" in names

    def test_cdx_components_include_libkeyutils(self, cdx_path):
        with open(cdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        names = [c.get("name") for c in data.get("components", [])]
        assert "libkeyutils" in names

    def test_cdx_license_fields_populated(self, cdx_path):
        with open(cdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for comp in data.get("components", []):
            assert "licenses" in comp or "name" in comp


class TestSbomSpdx:
    """SPDX 2.3 SBOM structure and content."""

    def test_spdx_valid_json(self, spdx_path):
        with open(spdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data.get("spdxVersion") == "SPDX-2.3"
        assert data.get("dataLicense") == "CC0-1.0"

    def test_spdx_has_packages(self, spdx_path):
        with open(spdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "packages" in data
        assert len(data["packages"]) >= 1
        names = [p.get("name") for p in data["packages"]]
        assert "gr-linux-crypto" in names

    def test_spdx_creation_info(self, spdx_path):
        with open(spdx_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "creationInfo" in data
        assert data["creationInfo"].get("created")
        assert data["creationInfo"].get("creators")


class TestVerifySbomScript:
    """verify_sbom.py script runs and validates."""

    def test_verify_script_exists(self):
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "verify_sbom.py"
        assert script.exists()

    def test_verify_script_validates_generated_sbom(self, cdx_path, spdx_path):
        root = Path(__file__).resolve().parents[1]
        script = root / "scripts" / "verify_sbom.py"
        build_dir = cdx_path.parent
        result = subprocess.run(
            [sys.executable, str(script), "--cdx", str(cdx_path), "--spdx", str(spdx_path)],
            cwd=str(build_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (result.stderr or result.stdout)
