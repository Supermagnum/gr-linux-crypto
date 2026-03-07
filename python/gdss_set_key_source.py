# -*- coding: utf-8 -*-
"""
GDSS set_key message source for gr-linux-crypto.

Produces the PMT message expected by gr-k-gdss kgdss_spreader_cc and
kgdss_despreader_cc set_key ports: a dict with "key" (u8vector 32 bytes)
and "nonce" (u8vector 12 bytes). Key is derived from shared secret via
HKDF (info b"gdss-chacha20-masking-v1"); nonce is session_id (4 bytes BE)
+ tx_seq (8 bytes BE). Matches gr-k-gdss session_key_derivation so that
key and nonce are never entered manually.

Connect the set_key_out message port to the set_key input of the spreader
and despreader. The message is sent once when the flowgraph starts.
"""

from __future__ import annotations

from typing import Optional

from gnuradio import gr
from gnuradio.gr import pmt

try:
    from .crypto_helpers import CryptoHelpers
except ImportError:
    CryptoHelpers = None


# Must match gr-k-gdss session_key_derivation (derive_session_keys, gdss_nonce)
GDSS_MASKING_INFO = b"gdss-chacha20-masking-v1"
NONCE_SESSION_BYTES = 4
NONCE_TXSEQ_BYTES = 8


def _derive_gdss_key(shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
    if CryptoHelpers is None:
        raise RuntimeError("gdss_set_key_source requires gr_linux_crypto.CryptoHelpers")
    if salt is None:
        salt = bytes(32)
    return CryptoHelpers.derive_key_hkdf(
        shared_secret,
        salt=salt,
        info=GDSS_MASKING_INFO,
        length=32,
    )


def _gdss_nonce(session_id: int, tx_seq: int) -> bytes:
    return session_id.to_bytes(NONCE_SESSION_BYTES, "big") + tx_seq.to_bytes(
        NONCE_TXSEQ_BYTES, "big"
    )


class gdss_set_key_source_block(gr.basic_block):
    """
    Source block that outputs the set_key PMT message for gr-k-gdss.

    Derives the 32-byte GDSS masking key from shared_secret via HKDF and
    builds the 12-byte nonce from session_id and tx_seq. Sends the message
    once when the flowgraph starts. Connect set_key_out to the set_key port
    of kgdss_spreader_cc and kgdss_despreader_cc so key/nonce are set
    automatically with no manual entry.
    """

    def __init__(
        self,
        shared_secret_hex: str = "",
        session_id: int = 1,
        tx_seq: int = 0,
    ) -> None:
        if CryptoHelpers is None:
            raise RuntimeError("gdss_set_key_source requires gr_linux_crypto.CryptoHelpers")
        gr.basic_block.__init__(
            self,
            name="gdss_set_key_source",
            in_sig=None,
            out_sig=None,
        )
        self.message_port_register_out(pmt.intern("set_key_out"))
        secret = bytes.fromhex(shared_secret_hex.strip()) if shared_secret_hex.strip() else None
        if secret is None or len(secret) < 32:
            self._msg = None
            return
        # Use full shared secret for HKDF (match gr-k-gdss derive_session_keys; supports P256/32, P384/48, P512/64 bytes)
        gdss_key = _derive_gdss_key(secret)
        nonce = _gdss_nonce(session_id, tx_seq)
        self._msg = pmt.dict_add(
            pmt.dict_add(
                pmt.make_dict(),
                pmt.intern("key"),
                pmt.init_u8vector(32, list(gdss_key)),
            ),
            pmt.intern("nonce"),
            pmt.init_u8vector(12, list(nonce)),
        )

    def start(self) -> bool:
        if self._msg is not None:
            self.message_port_pub(pmt.intern("set_key_out"), self._msg)
        return super().start()
