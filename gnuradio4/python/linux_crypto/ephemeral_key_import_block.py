# -*- coding: utf-8 -*-
"""
GNU Radio message source: import ``.epk.gpg`` offer and emit ``set_key`` PMT for GR-K-GDSS.

Decrypts and validates an ephemeral key offer, derives the Galdralag GDSS masking key,
and outputs the same PMT shape as ``gdss_set_key_source_block`` (``key`` + ``nonce``).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization

from gnuradio import gr
from gnuradio.gr import pmt

try:
    from .crypto_helpers import CryptoHelpers
except ImportError:
    CryptoHelpers = None

try:
    from .ephemeral_key_store import EphemeralKeyStore
except ImportError:
    EphemeralKeyStore = None

NONCE_SESSION_BYTES = 4
NONCE_TXSEQ_BYTES = 8


def _gdss_nonce(session_id: int, tx_seq: int) -> bytes:
    return session_id.to_bytes(NONCE_SESSION_BYTES, "big") + tx_seq.to_bytes(
        NONCE_TXSEQ_BYTES, "big"
    )


def _hex_to_bytes(s: str) -> Optional[bytes]:
    t = s.strip().replace(" ", "").replace("0x", "")
    if not t:
        return None
    if len(t) % 2 != 0:
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


class ephemeral_key_import_block(gr.basic_block):
    """
    At flowgraph start: import ``.epk.gpg``, derive Galdralag masking key, emit ``set_key`` PMT.
    """

    def __init__(
        self,
        offer_gpg_path: str = "",
        verify_fingerprint: str = "",
        our_epk_private_hex: str = "",
        our_session_id: str = "",
        session_id: int = 1,
        tx_seq: int = 0,
        peer_was_initiator: str = "true",
    ) -> None:
        if CryptoHelpers is None or EphemeralKeyStore is None:
            raise RuntimeError("ephemeral_key_import_block requires gr_linux_crypto Python helpers")
        gr.basic_block.__init__(
            self,
            name="ephemeral_key_import",
            in_sig=None,
            out_sig=None,
        )
        self.message_port_register_out(pmt.intern("set_key_out"))
        self._msg = None

        pwi = str(peer_was_initiator).strip().lower() in ("1", "true", "yes", "on")
        path = (offer_gpg_path or "").strip()
        vf = (verify_fingerprint or "").strip()
        sid = (our_session_id or "").strip()
        if not path or not vf or not sid:
            return

        try:
            raw = Path(path).read_bytes()
        except OSError:
            return

        store = EphemeralKeyStore()
        try:
            offer = store.import_offer(raw, vf)
        except (
            ValueError,
            subprocess.SubprocessError,
            json.JSONDecodeError,
            RuntimeError,
            KeyError,
        ):
            return
        except Exception:
            return

        if our_epk_private_hex.strip():
            sk = _hex_to_bytes(our_epk_private_hex)
            if sk is None:
                return
            try:
                priv = serialization.load_der_private_key(sk, password=None)
            except Exception:
                try:
                    priv = serialization.load_pem_private_key(sk, password=None)
                except Exception:
                    return
        else:
            try:
                priv = store.load_private_from_keyring(sid)
            except (KeyError, ValueError, RuntimeError):
                return

        try:
            keys = store.derive_session_keys(sid, priv, offer, peer_was_initiator=pwi)
        except Exception:
            return

        gdss_key = keys["gdss_mask_key"]
        nonce = _gdss_nonce(session_id, tx_seq)
        self._msg = pmt.dict_add(
            pmt.dict_add(
                pmt.make_dict(),
                pmt.intern("key"),
                pmt.init_u8vector(len(gdss_key), list(gdss_key)),
            ),
            pmt.intern("nonce"),
            pmt.init_u8vector(len(nonce), list(nonce)),
        )

    def start(self) -> bool:
        if self._msg is not None:
            self.message_port_pub(pmt.intern("set_key_out"), self._msg)
        return super().start()
