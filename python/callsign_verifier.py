# -*- coding: utf-8 -*-
"""
Verify amateur-radio callsigns against GnuPG-signed material.

Uses subprocess calls to ``gpg`` (no Python GPG bindings). Integrates with
:class:`CallsignKeyStore` for optional local callsign-to-key metadata; signature
verification uses the GnuPG keyring and ``gpg --verify``.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

try:
    from .callsign_key_store import CallsignKeyStore
except ImportError:
    from callsign_key_store import CallsignKeyStore


def gpg_lookup_fingerprint(gpg_binary: str, key_spec: str) -> str:
    """
    Return the primary fingerprint (40 hex chars, lowercase) for a key spec.

    Uses ``gpg --list-keys --with-colons --with-fingerprint``, consistent with
    :mod:`ephemeral_key_store`.
    """
    result = subprocess.run(
        [
            gpg_binary,
            "--batch",
            "--list-keys",
            "--with-colons",
            "--with-fingerprint",
            key_spec,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(
            f"gpg could not find key for {key_spec!r}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    for line in result.stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) > 9 and parts[0] == "fpr":
            return parts[9].lower()
    raise ValueError(f"No fingerprint in gpg output for {key_spec!r}")


def gpg_uid_callsign_hint(gpg_binary: str, key_spec: str) -> Optional[str]:
    """
    Extract an amateur-radio callsign from the key UID if present.

    Matches common UID patterns (callsign at start or in parentheses).
    """
    result = subprocess.run(
        [gpg_binary, "--batch", "--list-keys", "--with-colons", key_spec],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode != 0:
        return None
    call_re = re.compile(r"\b([A-Z0-9]{1,2}[0-9][A-Z0-9]{1,3}[A-Z0-9]?)\b")
    for line in result.stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) > 9 and parts[0] == "uid":
            uid = parts[9]
            match = call_re.search(uid.upper())
            if match:
                return match.group(1)
    return None


class CallsignVerifier:
    """
    Verify that detached OpenPGP signatures match an expected amateur-radio callsign.

    Anti-piracy rationale
    ---------------------
    When logging software signs each QSO record with the operator's **private** key
    held on a hardware token (Nitrokey via libnitrokey, or a Galdralag / Baochip-1x
    token in OpenPGP CCID smart-card mode), and verifies incoming records against the
    sender's **public** key (from a QR code, keyserver, or web-of-trust), callsign
    impersonation becomes mathematically infeasible in practice: an attacker would
    need the physical token **and** its PIN to produce a valid signature for that
    callsign. On a Galdralag token the private key never leaves the device even when
    export commands are issued; PIN lockout after a configurable number of failed
    attempts (typically 3--10 per the token PIN policy) blocks brute force. The
    Galdralag authenticated ephemeral ECDH session protocol additionally provides
    forward secrecy for radio sessions, so a future compromise of the long-term
    signing key does not retroactively expose past signed QSO records once those
    sessions used ephemeral key agreement. Optional future three-factor models on
    Galdralag (possession + PIN + biometric) add another layer when deployed.

    This class does not perform signing; it verifies detached signatures with ``gpg``.
    """

    def __init__(
        self,
        key_store: Optional[CallsignKeyStore] = None,
        gpg_binary: str = "gpg",
    ):
        self.key_store = key_store or CallsignKeyStore()
        self._gpg = gpg_binary

    def lookup_fingerprint(self, callsign_or_email: str) -> str:
        """Resolve callsign or email to a GnuPG primary fingerprint."""
        return gpg_lookup_fingerprint(self._gpg, callsign_or_email)

    def verify_signed_log_entry(
        self, entry: bytes, signature: bytes, callsign: str
    ) -> bool:
        """
        Verify a detached OpenPGP signature over a log entry for the given callsign.

        Suitable for ADIF-based logging software or digital-mode tools that exchange
        signed QSO records. Returns ``True`` only if ``gpg --verify`` succeeds and the
        signing key fingerprint matches the key associated with ``callsign`` in GnuPG.

        Args:
            entry: Canonical signed payload (e.g. ADIF snippet or log line bytes).
            signature: Detached OpenPGP signature bytes.
            callsign: Expected operator callsign (case-insensitive).

        Returns:
            ``True`` if the signature is valid and matches the callsign's key.
        """
        callsign = callsign.upper().strip()
        if not callsign:
            return False
        try:
            expected_fpr = self.lookup_fingerprint(callsign)
        except ValueError:
            return False

        if self.key_store.has_callsign(callsign):
            _ = self.key_store.get_public_key(callsign)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            entry_path = tmp_path / "entry.bin"
            sig_path = tmp_path / "entry.sig"
            entry_path.write_bytes(entry)
            sig_path.write_bytes(signature)

            proc = subprocess.run(
                [
                    self._gpg,
                    "--batch",
                    "--status-fd",
                    "1",
                    "--verify",
                    str(sig_path),
                    str(entry_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if proc.returncode != 0:
                return False
            for line in proc.stdout.splitlines():
                if not line.startswith("[GNUPG:] VALIDSIG"):
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    signer_fpr = parts[2].lower()
                    return signer_fpr == expected_fpr
            return False
