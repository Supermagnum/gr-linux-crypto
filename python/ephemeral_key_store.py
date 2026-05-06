# -*- coding: utf-8 -*-
"""
Out-of-band ephemeral Brainpool key offers for Galdralag-compatible session KDF.

Signed JSON (per docs/EPHEMERAL_KEY_EXCHANGE.md) is armored with GnuPG sign+encrypt
and exchanged as ``.epk.gpg`` files. Expiry is enforced in-process and optionally
via kernel ``keyctl timeout`` on stored blobs.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .crypto_helpers import CryptoHelpers
from .galdralag_session_kdf import (
    derive_galdralag_session_keys,
    validate_offer_consumed,
    validate_offer_expiry,
)
from .keyring_helper import KeyringHelper

OFFER_SCHEMA_VERSION = 1
OFFER_KEYRING_PREFIX = "gr_linux_crypto:ephemeral_offer:"
PRIV_KEYRING_PREFIX = "gr_linux_crypto:ephemeral_priv:"
DEFAULT_CURVE = "brainpoolP256r1"


def _norm_fp(fp: str) -> str:
    return fp.strip().replace(" ", "").lower()


def _run_gpg(
    gpg_binary: str,
    args: List[str],
    *,
    stdin: Optional[bytes] = None,
    input_path: Optional[str] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    cmd = [gpg_binary] + ["--batch", "--yes"] + args
    inp = stdin
    if input_path:
        with open(input_path, "rb") as f:
            inp = f.read()
    return subprocess.run(
        cmd,
        input=inp,
        capture_output=True,
        check=check,
    )


def _gpg_list_fingerprint(gpg_binary: str, key_spec: str) -> str:
    r = _run_gpg(
        gpg_binary,
        ["--list-keys", "--with-colons", "--with-fingerprint", key_spec],
        check=True,
    )
    for line in r.stdout.splitlines():
        parts = line.strip().split(":")
        if len(parts) > 9 and parts[0] == "fpr":
            return parts[9].lower()
    raise RuntimeError("Could not parse GnuPG fingerprint for {!r}".format(key_spec))


class EphemeralKeyStore:
    """
    Generate, import, and derive from ephemeral key offers (``.epk.gpg``).

    All expiry and single-use (``consumed``) checks are enforced here.
    """

    def __init__(
        self,
        keyring_helper: Optional[KeyringHelper] = None,
        gpg_binary: str = "gpg",
        audit_log_path: Optional[Union[str, Path]] = None,
        time_fn: Optional[Callable[[], float]] = None,
        keyring_target: str = "@s",
    ) -> None:
        self._kh = keyring_helper or KeyringHelper()
        self._gpg = gpg_binary
        self._time = time_fn or time.time
        self._keyring_target = keyring_target
        self._audit_path = (
            Path(audit_log_path)
            if audit_log_path
            else Path(
                os.environ.get(
                    "XDG_STATE_HOME",
                    str(Path.home() / ".local" / "state"),
                )
            )
            / "gr-linux-crypto"
            / "ephemeral_key_audit.log"
        )
        self._offers: Dict[str, Dict[str, Any]] = {}
        self._last_session_id: Optional[str] = None

    @property
    def last_session_id(self) -> Optional[str]:
        """Set by the most recent successful :meth:`generate` call (offer ``session_id`` hex)."""
        return self._last_session_id

    def _audit(self, record: Dict[str, Any]) -> None:
        record = dict(record)
        record["ts"] = int(self._time())
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._audit_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def generate(
        self,
        long_term_key_id: str,
        recipient_key_ids: List[str],
        expires_in_seconds: int,
    ) -> Tuple[EllipticCurvePrivateKey, bytes]:
        """
        Create a BrainpoolP256r1 ephemeral keypair and a signed, encrypted offer.

        Returns:
            (ephemeral_private_key, offer_gpg_bytes) for writing as ``.epk.gpg``.
            The caller should store the private key (e.g. ``store_private_in_keyring``)
            before distributing the offer.
        """
        if expires_in_seconds <= 0:
            raise ValueError("expires_in_seconds must be positive")
        if not recipient_key_ids:
            raise ValueError("recipient_key_ids must be non-empty")

        priv, pub = CryptoHelpers.generate_brainpool_keypair(DEFAULT_CURVE)
        epk_sec1 = pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        epk_hex = epk_sec1.hex()
        now = int(self._time())
        expires_at = now + int(expires_in_seconds)
        session_id = secrets.token_bytes(16).hex()

        with tempfile.TemporaryDirectory() as tmp:
            epk_path = os.path.join(tmp, "epk.bin")
            sig_path = os.path.join(tmp, "epk.sig")
            with open(epk_path, "wb") as f:
                f.write(epk_sec1)
            _run_gpg(
                self._gpg,
                [
                    "--detach-sign",
                    "--local-user",
                    long_term_key_id,
                    "--output",
                    sig_path,
                    epk_path,
                ],
                check=True,
            )
            with open(sig_path, "rb") as f:
                sig_bin = f.read()

        lt_fp = _gpg_list_fingerprint(self._gpg, long_term_key_id)
        body = {
            "schema_version": OFFER_SCHEMA_VERSION,
            "epk_hex": epk_hex,
            "long_term_fingerprint": lt_fp,
            "signature_hex": sig_bin.hex(),
            "expires_at": expires_at,
            "created_at": now,
            "session_id": session_id,
            "consumed": False,
        }
        raw_json = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

        args: List[str] = [
            "--encrypt",
            "--sign",
            "--local-user",
            long_term_key_id,
            "--trust-model",
            "always",
        ]
        for rid in recipient_key_ids:
            args.extend(["--recipient", rid])
        args.extend(["-o", "-"])
        proc = _run_gpg(self._gpg, args, stdin=raw_json, check=True)
        self._last_session_id = session_id
        return priv, proc.stdout

    def store_private_in_keyring(
        self,
        private_key: EllipticCurvePrivateKey,
        session_id: str,
        timeout_seconds: int,
    ) -> str:
        """Serialize PKCS#8 PEM and store under ``gr_linux_crypto:ephemeral_priv:{session_id}``."""
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        desc = f"{PRIV_KEYRING_PREFIX}{session_id}"
        return self._kh.store_with_timeout(
            desc, pem, timeout_seconds, self._keyring_target
        )

    def import_offer(
        self, offer_gpg_bytes: bytes, verify_fingerprint: str
    ) -> Dict[str, Any]:
        """
        Decrypt a ``.epk.gpg`` offer, verify issuer fingerprint and detached EPK signature.

        Stores offer JSON in the kernel keyring until ``expires_at`` and keeps a
        copy in memory for ``derive_session_keys``.
        """
        proc = subprocess.run(
            [self._gpg, "--batch", "--yes", "--decrypt"],
            input=offer_gpg_bytes,
            capture_output=True,
            check=True,
        )
        offer = json.loads(proc.stdout.decode("utf-8"))
        if offer.get("schema_version") != OFFER_SCHEMA_VERSION:
            self._audit(
                {"event": "reject", "reason": "bad_schema", "session_id": offer.get("session_id")}
            )
            raise ValueError("schema_version must be {}".format(OFFER_SCHEMA_VERSION))
        if not validate_offer_consumed(offer):
            self._audit(
                {
                    "event": "reject",
                    "reason": "already_consumed",
                    "session_id": offer.get("session_id"),
                }
            )
            raise ValueError("offer already consumed")
        if not validate_offer_expiry(offer, now=self._time()):
            self._audit(
                {"event": "reject", "reason": "expired", "session_id": offer.get("session_id")}
            )
            raise ValueError("offer expired (expires_at not in the future)")

        got_fp = _norm_fp(str(offer.get("long_term_fingerprint", "")))
        if got_fp != _norm_fp(verify_fingerprint):
            self._audit(
                {
                    "event": "reject",
                    "reason": "fingerprint_mismatch",
                    "session_id": offer.get("session_id"),
                }
            )
            raise ValueError("long_term_fingerprint does not match verify_fingerprint")

        epk_sec1 = bytes.fromhex(str(offer["epk_hex"]))
        sig_bin = bytes.fromhex(str(offer["signature_hex"]))
        with tempfile.TemporaryDirectory() as tmp:
            epk_path = os.path.join(tmp, "epk.bin")
            sig_path = os.path.join(tmp, "epk.sig")
            with open(epk_path, "wb") as f:
                f.write(epk_sec1)
            with open(sig_path, "wb") as f:
                f.write(sig_bin)
            vr = subprocess.run(
                [self._gpg, "--batch", "--yes", "--verify", sig_path, epk_path],
                capture_output=True,
                text=True,
            )
            if vr.returncode != 0:
                self._audit(
                    {
                        "event": "reject",
                        "reason": "bad_epk_signature",
                        "session_id": offer.get("session_id"),
                    }
                )
                raise ValueError("detached GnuPG signature over EPK failed verification")

        sid = str(offer["session_id"])
        timeout_s = max(1, int(float(offer["expires_at"]) - self._time()))
        blob = json.dumps(offer, sort_keys=True, separators=(",", ":")).encode("utf-8")
        kid = self._kh.store_with_timeout(
            f"{OFFER_KEYRING_PREFIX}{sid}",
            blob,
            timeout_s,
            self._keyring_target,
        )
        state = dict(offer)
        state["_keyring_key_id"] = kid
        state["consumed"] = False
        self._offers[sid] = state
        self._audit(
            {
                "event": "import",
                "session_id": sid,
                "created_at": offer.get("created_at"),
                "expires_at": offer.get("expires_at"),
                "long_term_fingerprint": got_fp,
            }
        )
        return offer

    def derive_session_keys(
        self,
        session_id: str,
        our_epk_private: EllipticCurvePrivateKey,
        peer_offer: Dict[str, Any],
        *,
        peer_was_initiator: bool = True,
    ) -> Dict[str, bytes]:
        """
        Derive Galdralag session keys after ECDH with the peer EPK from ``peer_offer``.

        Args:
            session_id: Must match ``peer_offer['session_id']`` and a prior ``import_offer``.
            our_epk_private: Local ephemeral Brainpool private key.
            peer_offer: Parsed offer dict (must contain ``epk_hex``).
            peer_was_initiator: If True (default), the imported peer sent the first move
                (their ``epk_hex`` is the initiator EPK for ``derive_galdralag_session_keys``).
        """
        sid = str(session_id)
        if sid != str(peer_offer.get("session_id", "")):
            raise ValueError("session_id does not match peer_offer")
        st = self._offers.get(sid)
        if st is None:
            raise KeyError("unknown session_id; import_offer first")
        if bytes.fromhex(str(st.get("epk_hex", ""))) != bytes.fromhex(
            str(peer_offer.get("epk_hex", ""))
        ):
            raise ValueError("peer_offer does not match stored import for session_id")
        if not validate_offer_expiry(st, now=self._time()):
            self._audit({"event": "reject", "reason": "expired_at_derive", "session_id": sid})
            raise ValueError("offer expired before derivation")
        if not validate_offer_consumed(st):
            self._audit({"event": "reject", "reason": "consumed_at_derive", "session_id": sid})
            raise ValueError("offer already consumed")

        peer_sec1 = bytes.fromhex(str(peer_offer["epk_hex"]))
        peer_pub = CryptoHelpers.brainpool_public_key_from_sec1_uncompressed(
            peer_sec1, DEFAULT_CURVE
        )
        shared = CryptoHelpers.brainpool_ecdh(our_epk_private, peer_pub)
        our_pub = our_epk_private.public_key()
        our_sec1 = our_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        if peer_was_initiator:
            keys = derive_galdralag_session_keys(shared, peer_sec1, our_sec1)
        else:
            keys = derive_galdralag_session_keys(shared, our_sec1, peer_sec1)

        st["consumed"] = True
        self._audit({"event": "derive", "session_id": sid, "consumed": True})
        return keys

    @staticmethod
    def export_offer(offer_gpg_bytes: bytes, output_path: Union[str, Path]) -> None:
        Path(output_path).write_bytes(offer_gpg_bytes)

    def status(self) -> List[Dict[str, Any]]:
        """List imported offers from memory and from the kernel keyring (offer blobs)."""
        merged: Dict[str, Dict[str, Any]] = {}
        try:
            for k in self._kh.list_keys(self._keyring_target):
                desc = k.get("description", "")
                if not desc.startswith(OFFER_KEYRING_PREFIX):
                    continue
                sid = desc[len(OFFER_KEYRING_PREFIX) :]
                try:
                    raw = self._kh.read_key_raw(k["id"])
                    offer = json.loads(raw.decode("utf-8"))
                except (OSError, ValueError, KeyError, json.JSONDecodeError):
                    continue
                merged[sid] = {
                    "session_id": sid,
                    "created_at": offer.get("created_at"),
                    "expires_at": offer.get("expires_at"),
                    "consumed": offer.get("consumed"),
                    "long_term_fingerprint": offer.get("long_term_fingerprint"),
                }
        except RuntimeError:
            pass
        for sid, st in self._offers.items():
            row = merged.get(
                sid,
                {
                    "session_id": sid,
                    "created_at": st.get("created_at"),
                    "expires_at": st.get("expires_at"),
                    "consumed": st.get("consumed"),
                    "long_term_fingerprint": st.get("long_term_fingerprint"),
                },
            )
            row["consumed"] = st.get("consumed", row.get("consumed"))
            merged[sid] = row
        return [merged[k] for k in sorted(merged.keys())]

    def load_private_from_keyring(self, session_id: str) -> EllipticCurvePrivateKey:
        """Load PKCS#8 PEM ephemeral private key stored with ``store_private_in_keyring``."""
        sid = str(session_id)
        kid = self._kh.search_key(
            "user", f"{PRIV_KEYRING_PREFIX}{sid}", self._keyring_target
        )
        if not kid:
            raise KeyError("ephemeral private key not in keyring for session_id")
        pem = self._kh.read_key_raw(kid)
        if pem.startswith(b"-----BEGIN"):
            return serialization.load_pem_private_key(pem, password=None)  # type: ignore[return-value]
        raise ValueError("keyring payload is not PEM private key")
