#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZMQ REP server exposing CallsignKeyStore over JSON request/response.

Public keys and callsigns only; never private keys or plaintext.
Loopback bind only (127.0.0.1 by default). No transport-layer crypto.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    import zmq
except ImportError as exc:
    raise ImportError(
        "pyzmq is required for the ZMQ key store server. "
        "Install with: pip install pyzmq"
    ) from exc

def _import_deps():
    try:
        from gr_linux_crypto.callsign_key_store import CallsignKeyStore as _store
        from gr_linux_crypto.zmq_key_store_client import (
            MAX_MESSAGE_BYTES as _max_bytes,
            validate_brainpool_public_pem as _validate_pem,
        )

        return _store, _max_bytes, _validate_pem
    except ImportError:
        pass
    try:
        from .callsign_key_store import CallsignKeyStore as _store
        from .zmq_key_store_client import (
            MAX_MESSAGE_BYTES as _max_bytes,
            validate_brainpool_public_pem as _validate_pem,
        )

        return _store, _max_bytes, _validate_pem
    except ImportError:
        pass
    parent = Path(__file__).resolve().parent
    if str(parent) not in sys.path:
        sys.path.insert(0, str(parent))
    from callsign_key_store import CallsignKeyStore as _store
    from zmq_key_store_client import MAX_MESSAGE_BYTES as _max_bytes
    from zmq_key_store_client import validate_brainpool_public_pem as _validate_pem

    return _store, _max_bytes, _validate_pem


CallsignKeyStore, MAX_MESSAGE_BYTES, validate_brainpool_public_pem = _import_deps()

SERVER_VERSION = "1.0"
LOG = logging.getLogger("zmq_key_store_server")


def _is_loopback(bind_addr: str) -> bool:
    try:
        return ipaddress.ip_address(bind_addr).is_loopback
    except ValueError:
        return False


def _require_loopback_bind(bind_addr: str) -> str:
    """Reject non-loopback binds; this server has no transport-layer security."""
    addr = bind_addr.strip()
    if not _is_loopback(addr):
        raise ValueError(
            "Only loopback bind addresses are supported (e.g. 127.0.0.1 or ::1). "
            "The ZMQ key store is unauthenticated and unencrypted at the transport "
            "layer. For remote access, use transport security outside this module "
            "and keep the server on loopback."
        )
    return addr


def _error_response(message: str) -> bytes:
    return json.dumps({"status": "error", "message": message}).encode("utf-8")


def _ok_response(**fields: Any) -> bytes:
    payload: Dict[str, Any] = {"status": "ok"}
    payload.update(fields)
    return json.dumps(payload).encode("utf-8")


def _not_found_response(**fields: Any) -> bytes:
    payload: Dict[str, Any] = {"status": "not_found"}
    payload.update(fields)
    return json.dumps(payload).encode("utf-8")


def handle_request(store: CallsignKeyStore, raw: bytes) -> bytes:
    """Process one REP request and return the response bytes."""
    if len(raw) > MAX_MESSAGE_BYTES:
        return _error_response("message exceeds maximum size (64 KiB)")
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error_response("malformed JSON")
    if not isinstance(req, dict):
        return _error_response("request must be a JSON object")

    op = req.get("op")
    if not isinstance(op, str):
        return _error_response("missing or invalid op")

    if op == "ping":
        return _ok_response(version=SERVER_VERSION)

    if op == "get":
        callsign = req.get("callsign")
        if not isinstance(callsign, str) or not callsign.strip():
            return _error_response("missing or invalid callsign")
        callsign_norm = callsign.upper().strip()
        pem = store.get_public_key(callsign_norm)
        if pem is None:
            LOG.info("get not_found callsign=%s", callsign_norm)
            return _not_found_response(callsign=callsign_norm)
        LOG.info("get ok callsign=%s", callsign_norm)
        return _ok_response(callsign=callsign_norm, public_key_pem=pem)

    if op == "put":
        callsign = req.get("callsign")
        pem = req.get("public_key_pem")
        if not isinstance(callsign, str) or not callsign.strip():
            return _error_response("missing or invalid callsign")
        if not isinstance(pem, str) or not pem.strip():
            return _error_response("missing or invalid public_key_pem")
        try:
            validate_brainpool_public_pem(pem)
        except ValueError as exc:
            LOG.info("put rejected callsign=%s reason=%s", callsign.upper().strip(), exc)
            return _error_response(str(exc))
        callsign_norm = callsign.upper().strip()
        if not store.add_public_key(callsign_norm, pem.strip()):
            return _error_response("failed to store public key")
        LOG.info("put ok callsign=%s", callsign_norm)
        return _ok_response()

    if op == "delete":
        callsign = req.get("callsign")
        if not isinstance(callsign, str) or not callsign.strip():
            return _error_response("missing or invalid callsign")
        callsign_norm = callsign.upper().strip()
        if store.remove_public_key(callsign_norm):
            LOG.info("delete ok callsign=%s", callsign_norm)
            return _ok_response()
        LOG.info("delete not_found callsign=%s", callsign_norm)
        return _not_found_response(callsign=callsign_norm)

    if op == "list":
        callsigns = store.list_callsigns()
        LOG.info("list ok count=%d", len(callsigns))
        return _ok_response(callsigns=callsigns)

    return _error_response(f"unknown op: {op}")


class ZmqKeyStoreServer:
    """REP server wrapper for tests and programmatic startup."""

    def __init__(
        self,
        key_store_path: str,
        *,
        port: int = 5557,
        bind: str = "127.0.0.1",
        use_keyring: bool = False,
    ):
        self.store = CallsignKeyStore(
            store_path=key_store_path, use_keyring=use_keyring
        )
        self.bind = _require_loopback_bind(bind)
        self.port = port
        self.endpoint = f"tcp://{bind}:{port}"
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._ctx: Optional[zmq.Context] = None
        self._sock: Optional[zmq.Socket] = None

    def serve_once(self, timeout_ms: int = 500) -> bool:
        """Poll for one request; return False if stopped or timed out."""
        if self._sock is None:
            return False
        poller = zmq.Poller()
        poller.register(self._sock, zmq.POLLIN)
        events = dict(poller.poll(timeout_ms))
        if self._sock not in events:
            return self._running
        try:
            raw = self._sock.recv(zmq.NOBLOCK)
        except zmq.Again:
            return self._running
        reply = handle_request(self.store, raw)
        self._sock.send(reply)
        return self._running

    def _serve_loop(self) -> None:
        self._ctx = zmq.Context()
        self._sock = self._ctx.socket(zmq.REP)
        self._sock.bind(self.endpoint)
        LOG.info("listening on %s", self.endpoint)
        try:
            while self._running:
                self.serve_once(timeout_ms=500)
        finally:
            if self._sock is not None:
                self._sock.close(linger=0)
                self._sock = None
            if self._ctx is not None:
                self._ctx.term()
                self._ctx = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def run_forever(self) -> None:
        self._running = True
        self._serve_loop()


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ZMQ REP server for CallsignKeyStore (public keys only)"
    )
    parser.add_argument(
        "--key-store",
        default="keys.json",
        help="Path to callsign JSON key store (default: keys.json)",
    )
    parser.add_argument("--port", type=int, default=5557, help="TCP port (default: 5557)")
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Loopback bind address only (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--use-keyring",
        action="store_true",
        help="Also use kernel keyring in CallsignKeyStore (default: file only)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    args = _parse_args(argv)
    try:
        bind = _require_loopback_bind(args.bind)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    server = ZmqKeyStoreServer(
        args.key_store,
        port=args.port,
        bind=bind,
        use_keyring=args.use_keyring,
    )
    try:
        server.run_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down")
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
