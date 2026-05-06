#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI for out-of-band ephemeral key offers (``.epk.gpg``).

Subcommands: ``generate``, ``import``, ``status``, ``expire`` (manual revocation of an
offer by ``session_id``; see ``docs/USAGE.md``).

Requires ``gpg`` on PATH. For an uninstalled tree, set ``GR_LINUX_CRYPTO_DIR`` to the
repository root (recommended so ``gr_linux_crypto`` imports resolve). Alternatively
prepend the repository root to ``PYTHONPATH`` if you use that layout instead.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _prepend_python_path() -> None:
    root = os.environ.get("GR_LINUX_CRYPTO_DIR")
    if not root:
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    # Repo root must precede python/: ``gr_linux_crypto`` is a package dir (or symlink to
    # ``python/``) at the repository root for ``from gr_linux_crypto.ephemeral_key_store``.
    if root not in sys.path:
        sys.path.insert(0, root)
    pd = os.path.join(root, "python")
    if os.path.isdir(pd) and pd not in sys.path:
        sys.path.insert(0, pd)


def cmd_generate(args: argparse.Namespace) -> int:
    _prepend_python_path()
    from gr_linux_crypto.ephemeral_key_store import EphemeralKeyStore

    store = EphemeralKeyStore()
    priv, blob = store.generate(
        args.long_term_key,
        list(args.recipient),
        args.expires_in,
    )
    out = Path(args.output)
    out.write_bytes(blob)
    timeout = max(1, int(args.expires_in))
    sid = store.last_session_id
    if sid:
        store.store_private_in_keyring(priv, sid, timeout)
    print(
        json.dumps(
            {"wrote": str(out), "session_id": sid, "private_keyring_timeout_s": timeout},
            indent=2,
        )
    )
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    _prepend_python_path()
    from gr_linux_crypto.ephemeral_key_store import EphemeralKeyStore

    raw = Path(args.offer).read_bytes()
    store = EphemeralKeyStore()
    offer = store.import_offer(raw, args.verify_fingerprint)
    print(json.dumps({"imported": True, "session_id": offer.get("session_id")}, indent=2))
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    _prepend_python_path()
    from gr_linux_crypto.ephemeral_key_store import EphemeralKeyStore

    rows = EphemeralKeyStore().status()
    print(json.dumps(rows, indent=2))
    return 0


def cmd_expire(args: argparse.Namespace) -> int:
    _prepend_python_path()
    from gr_linux_crypto.ephemeral_key_store import EphemeralKeyStore

    store = EphemeralKeyStore()
    try:
        store.revoke_offer(args.session_id)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("Offer {} revoked.".format(args.session_id.strip().lower()))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Ephemeral key offer (.epk.gpg) utilities")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="Create BrainpoolP256r1 offer and write .epk.gpg")
    g.add_argument("--long-term-key", required=True, help="GnuPG key ID for signing")
    g.add_argument(
        "--recipient",
        action="append",
        dest="recipient",
        required=True,
        help="GnuPG recipient (repeat for group distribution)",
    )
    g.add_argument(
        "--expires-in",
        type=int,
        default=86400,
        help="Validity window in seconds (default 86400)",
    )
    g.add_argument("--output", required=True, help="Output path, e.g. offer.epk.gpg")
    g.set_defaults(func=cmd_generate)

    i = sub.add_parser("import", help="Decrypt and import an offer")
    i.add_argument("--offer", required=True, help="Path to .epk.gpg")
    i.add_argument(
        "--verify-fingerprint",
        required=True,
        help="Expected issuer long-term fingerprint (hex)",
    )
    i.set_defaults(func=cmd_import)

    s = sub.add_parser("status", help="List in-memory imported offers (this process)")
    s.set_defaults(func=cmd_status)

    x = sub.add_parser(
        "expire",
        help="Manually revoke an offer (unlink keyring keys by session_id)",
    )
    x.add_argument(
        "session_id",
        help="Offer session_id (hex); same id as shown by status / import output",
    )
    x.set_defaults(func=cmd_expire)

    ns = p.parse_args()
    return int(ns.func(ns))


if __name__ == "__main__":
    sys.exit(main())
