#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validate SBOM files (CycloneDX 1.6 and SPDX 2.3) against their respective schemas.

Schema URLs:
- CycloneDX: https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json
- SPDX: use local structural checks or schema from https://github.com/spdx/spdx-spec
"""

import argparse
import json
import sys
from pathlib import Path
from urllib.request import urlopen


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_cyclonedx(data: dict) -> list:
    errors = []
    if data.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat must be 'CycloneDX'")
    if data.get("specVersion") != "1.6":
        errors.append("specVersion must be '1.6'")
    if "metadata" in data and "component" in data["metadata"]:
        comp = data["metadata"]["component"]
        if not comp.get("name") or not comp.get("version"):
            errors.append("metadata.component must have name and version")
    if "components" not in data:
        errors.append("components array missing")
    elif not isinstance(data["components"], list):
        errors.append("components must be an array")
    else:
        for i, c in enumerate(data["components"]):
            if not c.get("name"):
                errors.append(f"components[{i}] missing name")
            if not c.get("bom-ref"):
                errors.append(f"components[{i}] missing bom-ref")
    return errors


def validate_spdx(data: dict) -> list:
    errors = []
    if data.get("spdxVersion") != "SPDX-2.3":
        errors.append("spdxVersion must be 'SPDX-2.3'")
    if data.get("dataLicense") != "CC0-1.0":
        errors.append("dataLicense must be 'CC0-1.0'")
    if not data.get("SPDXID"):
        errors.append("SPDXID missing")
    if not data.get("documentNamespace"):
        errors.append("documentNamespace missing")
    if "creationInfo" not in data:
        errors.append("creationInfo missing")
    else:
        ci = data["creationInfo"]
        if not ci.get("created") or not ci.get("creators"):
            errors.append("creationInfo must have created and creators")
    if "packages" not in data:
        errors.append("packages missing")
    elif not isinstance(data["packages"], list):
        errors.append("packages must be an array")
    else:
        for i, p in enumerate(data["packages"]):
            if not p.get("SPDXID"):
                errors.append(f"packages[{i}] missing SPDXID")
            if not p.get("name"):
                errors.append(f"packages[{i}] missing name")
    if "relationships" not in data:
        errors.append("relationships missing")
    return errors


def validate_with_jsonschema(data: dict, schema_url: str) -> list:
    try:
        import jsonschema
    except ImportError:
        return []
    try:
        with urlopen(schema_url, timeout=10) as r:
            schema = json.loads(r.read().decode())
        jsonschema.validate(instance=data, schema=schema)
        return []
    except json.JSONDecodeError as e:
        return [f"Schema JSON error: {e}"]
    except Exception as e:  # jsonschema.ValidationError
        return [str(e)]


def main():
    parser = argparse.ArgumentParser(description="Validate SBOM files")
    parser.add_argument("--cdx", default="sbom.cdx.json", help="CycloneDX SBOM path")
    parser.add_argument("--spdx", default="sbom.spdx.json", help="SPDX SBOM path")
    parser.add_argument("--schema", action="store_true", help="Validate against remote schema (requires network)")
    args = parser.parse_args()
    cdx_path = Path(args.cdx)
    spdx_path = Path(args.spdx)
    all_errors = []
    if cdx_path.exists():
        cdx = load_json(cdx_path)
        all_errors.extend(validate_cyclonedx(cdx))
        if args.schema:
            all_errors.extend(
                validate_with_jsonschema(
                    cdx,
                    "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json",
                )
            )
    else:
        all_errors.append(f"CycloneDX file not found: {cdx_path}")
    if spdx_path.exists():
        spdx = load_json(spdx_path)
        all_errors.extend(validate_spdx(spdx))
        if args.schema:
            # SPDX 2.3 schema URL may vary; structural check is primary
            pass
    else:
        all_errors.append(f"SPDX file not found: {spdx_path}")
    if all_errors:
        for e in all_errors:
            print("ERROR:", e, file=sys.stderr)
        return 1
    print("SBOM validation passed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
