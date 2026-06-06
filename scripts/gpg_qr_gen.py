#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate QR codes for GnuPG public-key distribution on physical cards.

Encodes an OpenPGP fingerprint URI, keyserver search URL, or callsign search URL.
Requires ``gpg`` on PATH and optional ``qrcode[pil]`` / ``lxml`` (see requirements.txt).

For an uninstalled tree, set ``GR_LINUX_CRYPTO_DIR`` to the repository root or run
from the repository with ``python3 scripts/gpg_qr_gen.py``.
"""

from __future__ import annotations

import argparse
import os
import sys
from io import BytesIO
from pathlib import Path
from typing import Optional


def _prepend_python_path() -> None:
    root = os.environ.get("GR_LINUX_CRYPTO_DIR")
    if not root:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if root not in sys.path:
        sys.path.insert(0, root)
    pd = os.path.join(root, "python")
    if os.path.isdir(pd) and pd not in sys.path:
        sys.path.insert(0, pd)


def _build_payload(
    style: str,
    fingerprint: str,
    callsign_or_email: str,
    callsign_hint: Optional[str],
) -> str:
    fpr = fingerprint.lower()
    if style == "openpgp4fpr":
        return f"openpgp4fpr:{fpr}"
    if style == "keyserver":
        return f"https://keys.openpgp.org/search?q=0x{fpr}"
    if style == "callsign":
        if "@" not in callsign_or_email:
            query = callsign_or_email.strip().upper()
        else:
            query = (callsign_hint or callsign_or_email.split("@", 1)[0]).strip()
        return f"https://keys.openpgp.org/search?q={query}"
    raise ValueError(f"Unknown style: {style}")


def _make_qr_svg(payload: str) -> bytes:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError as exc:
        raise ImportError(
            "QR generation requires qrcode. Install with: pip install 'qrcode[pil]' lxml"
        ) from exc

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    factory = qrcode.image.svg.SvgPathImage
    img = qr.make_image(image_factory=factory)
    buf = BytesIO()
    img.save(buf)
    return buf.getvalue()


def _make_qr_png(payload: str) -> bytes:
    try:
        import qrcode
    except ImportError as exc:
        raise ImportError(
            "PNG output requires qrcode with Pillow. "
            "Install with: pip install 'qrcode[pil]' lxml"
        ) from exc

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image()
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a QR code for a GnuPG public key (physical card printing)"
    )
    parser.add_argument(
        "identifier",
        help="Amateur-radio callsign or email address (looked up via gpg)",
    )
    parser.add_argument(
        "--style",
        choices=("openpgp4fpr", "keyserver", "callsign"),
        default="openpgp4fpr",
        help="Payload encoding (default: openpgp4fpr URI for OpenKeychain)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        help="Output file (.svg default format, or .png if --png); '-' for stdout",
    )
    parser.add_argument(
        "--png",
        action="store_true",
        help="Write PNG instead of SVG (requires Pillow via qrcode[pil])",
    )
    parser.add_argument(
        "--gpg",
        default="gpg",
        help="GnuPG binary (default: gpg)",
    )
    args = parser.parse_args(argv)

    _prepend_python_path()
    from callsign_verifier import gpg_lookup_fingerprint, gpg_uid_callsign_hint

    try:
        fingerprint = gpg_lookup_fingerprint(args.gpg, args.identifier)
        callsign_hint = gpg_uid_callsign_hint(args.gpg, args.identifier)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        payload = _build_payload(
            args.style, fingerprint, args.identifier, callsign_hint
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(payload)

    try:
        if args.png:
            data = _make_qr_png(payload)
        else:
            data = _make_qr_svg(payload)
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output == "-":
        out_stream = sys.stdout.buffer if args.png else sys.stdout
        if args.png:
            out_stream.write(data)
        else:
            if isinstance(data, bytes):
                out_stream.write(data.decode("utf-8"))
            else:
                out_stream.write(data)
    else:
        out_path = Path(args.output)
        out_path.write_bytes(data)

    return 0


if __name__ == "__main__":
    sys.exit(main())
