#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate Software Bill of Materials (SBOM) in CycloneDX 1.6 and SPDX 2.3 formats.

Invoked by CMake when GR_LINUX_CRYPTO_SBOM=ON. Writes build/sbom.cdx.json and
build/sbom.spdx.json with module name, version, license, and all direct
C++ and Python dependencies and their licenses/versions.
"""

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


def parse_requirements(requirements_path: Path) -> list:
    """Parse requirements.txt into list of (name, version_spec or None)."""
    deps = []
    if not requirements_path.exists():
        return deps
    with open(requirements_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Simple parse: package>=x.y or package==x.y
            name = line
            version = None
            for sep in (">=", "==", "~=", "<=", "!=", "<", ">"):
                if sep in line:
                    parts = line.split(sep, 1)
                    name = parts[0].strip()
                    version = (sep + parts[1].strip()) if len(parts) > 1 else None
                    break
            if name:
                deps.append({"name": name, "version": version})
    return deps


def cpp_dependencies(fips: bool = False, pq_kem: bool = False, nitrokey: bool = False) -> list:
    """Return list of C++ dependency dicts (name, version, license)."""
    deps = [
        {"name": "OpenSSL", "version": "3.x", "license": "Apache-2.0"},
        {"name": "libkeyutils", "version": "1.6+", "license": "LGPL-2.1-or-later"},
    ]
    if pq_kem:
        deps.append({"name": "oqs-provider", "version": "0.x", "license": "MIT"})
    if nitrokey:
        deps.append({"name": "libnitrokey", "version": "3.x", "license": "LGPL-3.0-or-later"})
    return deps


def cyclonedx_bom(module_name: str, version: str, requirements_path: Path,
                  fips: bool, pq_kem: bool, nitrokey: bool) -> dict:
    """Build CycloneDX 1.6 BOM."""
    bom_ref_root = "pkg:generic/gr-linux-crypto@" + version
    components = [
        {
            "type": "library",
            "bom-ref": bom_ref_root,
            "name": module_name,
            "version": version,
            "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
            "description": "GNU Radio module for Linux kernel crypto and Brainpool ECC",
        }
    ]
    for dep in cpp_dependencies(fips, pq_kem, nitrokey):
        ref = "pkg:generic/" + dep["name"].lower().replace(" ", "-") + "@" + dep["version"]
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": dep["name"],
            "version": dep["version"],
            "licenses": [{"license": {"id": dep["license"]}}],
        })
    for d in parse_requirements(requirements_path):
        ref = "pkg:pypi/" + d["name"] + ("@" + d["version"] if d.get("version") else "")
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": d["name"],
            "version": d.get("version") or "unknown",
            "licenses": [{"license": {"id": "NOASSERTION"}}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "component": {
                "type": "library",
                "bom-ref": bom_ref_root,
                "name": module_name,
                "version": version,
                "licenses": [{"license": {"id": "GPL-3.0-or-later"}}],
            },
        },
        "components": components,
    }


def spdx_document(module_name: str, version: str, requirements_path: Path,
                  fips: bool, pq_kem: bool, nitrokey: bool) -> dict:
    """Build SPDX 2.3 document."""
    doc_id = "SPDXRef-DOCUMENT"
    ns = "https://spdx.org/spdxdocs/gr-linux-crypto-" + version + "-" + str(uuid.uuid4())
    root_id = "SPDXRef-Root"
    packages = [
        {
            "SPDXID": root_id,
            "name": module_name,
            "versionInfo": version,
            "licenseConcluded": "GPL-3.0-or-later",
            "licenseDeclared": "GPL-3.0-or-later",
            "description": "GNU Radio module for Linux kernel crypto and Brainpool ECC",
        }
    ]
    relationships = [{"spdxElementId": doc_id, "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    for dep in cpp_dependencies(fips, pq_kem, nitrokey):
        pid = "SPDXRef-" + dep["name"].replace(" ", "-").replace(".", "-")
        packages.append({
            "SPDXID": pid,
            "name": dep["name"],
            "versionInfo": dep["version"],
            "licenseConcluded": dep["license"],
            "licenseDeclared": dep["license"],
        })
        relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": pid})
    for d in parse_requirements(requirements_path):
        pid = "SPDXRef-pypi-" + d["name"].replace("-", "_")
        packages.append({
            "SPDXID": pid,
            "name": d["name"],
            "versionInfo": d.get("version") or "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
        })
        relationships.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": pid})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": "gr-linux-crypto SBOM",
        "documentNamespace": ns,
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: generate_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate CycloneDX and SPDX SBOMs")
    parser.add_argument("--build-dir", required=True, help="Build directory (output)")
    parser.add_argument("--source-dir", required=True, help="Source root (for requirements.txt)")
    parser.add_argument("--version", default="1.0.0", help="Module version")
    parser.add_argument("--fips", action="store_true", help="FIPS option enabled")
    parser.add_argument("--pq-kem", action="store_true", help="PQ_KEM option enabled")
    parser.add_argument("--nitrokey", action="store_true", help="Nitrokey support enabled")
    args = parser.parse_args()
    build_dir = Path(args.build_dir)
    source_dir = Path(args.source_dir)
    requirements_path = source_dir / "requirements.txt"
    build_dir.mkdir(parents=True, exist_ok=True)
    module_name = "gr-linux-crypto"
    cdx = cyclonedx_bom(
        module_name, args.version, requirements_path,
        args.fips, args.pq_kem, args.nitrokey,
    )
    spdx = spdx_document(
        module_name, args.version, requirements_path,
        args.fips, args.pq_kem, args.nitrokey,
    )
    cdx_path = build_dir / "sbom.cdx.json"
    spdx_path = build_dir / "sbom.spdx.json"
    with open(cdx_path, "w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2)
    with open(spdx_path, "w", encoding="utf-8") as f:
        json.dump(spdx, f, indent=2)
    print("Wrote", cdx_path, "and", spdx_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
