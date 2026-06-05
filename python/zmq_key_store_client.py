# -*- coding: utf-8 -*-
"""
ZMQ REQ client for the callsign key store server.

Optional dependency: pyzmq. Existing blocks work without it; only this module
and zmq_key_store_server.py require pyzmq.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Dict, List, Optional, Set

try:
    import zmq
except ImportError as exc:
    raise ImportError(
        "pyzmq is required for ZMQ key store support. "
        "Install with: pip install pyzmq"
    ) from exc

try:
    from .crypto_helpers import CryptoHelpers
except ImportError:
    from crypto_helpers import CryptoHelpers

BRAINPOOL_CURVE_NAMES: Set[str] = {
    "brainpoolP256r1",
    "brainpoolP384r1",
    "brainpoolP512r1",
}

MAX_MESSAGE_BYTES = 64 * 1024


class ZmqKeyStoreError(Exception):
    """Raised on ZMQ key store connection, timeout, or server error responses."""


def validate_brainpool_public_pem(pem: str) -> None:
    """
    Validate PEM is a Brainpool **public** key (not private, not RSA).

    Raises:
        ValueError: If the PEM is invalid or not an allowed public key type.
    """
    if not pem or not isinstance(pem, str):
        raise ValueError("public_key_pem must be a non-empty string")
    normalized = pem.strip()
    if "BEGIN PRIVATE KEY" in normalized or "BEGIN RSA PRIVATE KEY" in normalized:
        raise ValueError("private keys are not accepted")
    if "BEGIN PUBLIC KEY" not in normalized and "BEGIN RSA PUBLIC KEY" not in normalized:
        raise ValueError("malformed PEM: expected a public key")
    try:
        key = CryptoHelpers.load_brainpool_public_key(normalized.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid public key PEM: {exc}") from exc
    curve_name = getattr(key.curve, "name", "")
    if curve_name not in BRAINPOOL_CURVE_NAMES:
        raise ValueError(
            f"only Brainpool public keys are accepted (got curve {curve_name!r})"
        )


class ZmqKeyStoreClient:
    """
    REQ client for the ZMQ callsign key store server.

    Thread-safe: one REQ socket per client, guarded by a lock.
    """

    def __init__(self, endpoint: str = "tcp://127.0.0.1:5557", timeout: float = 5.0):
        """
        Args:
            endpoint: ZMQ endpoint (tcp://127.0.0.1:port). The server accepts
                loopback connections only; see docs/ZMQ_KEY_STORE.md.
            timeout: Send/receive timeout in seconds (default 5).
        """
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._endpoint = endpoint
        self._timeout_ms = int(timeout * 1000)
        self._lock = threading.Lock()
        self._ctx: Optional[zmq.Context] = None
        self._sock: Optional[zmq.Socket] = None
        self._connect()

    def _connect(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close(linger=0)
            except Exception:
                pass
        if self._ctx is not None:
            try:
                self._ctx.term()
            except Exception:
                pass
        self._ctx = zmq.Context()
        self._sock = self._ctx.socket(zmq.REQ)
        self._sock.setsockopt(zmq.RCVTIMEO, self._timeout_ms)
        self._sock.setsockopt(zmq.SNDTIMEO, self._timeout_ms)
        self._sock.setsockopt(zmq.LINGER, 0)
        self._sock.connect(self._endpoint)

    def close(self) -> None:
        """Release the ZMQ socket and context."""
        with self._lock:
            if self._sock is not None:
                self._sock.close(linger=0)
                self._sock = None
            if self._ctx is not None:
                self._ctx.term()
                self._ctx = None

    def _request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_MESSAGE_BYTES:
            raise ZmqKeyStoreError("request exceeds maximum message size (64 KiB)")
        with self._lock:
            if self._sock is None:
                raise ZmqKeyStoreError("client is closed")
            try:
                self._sock.send(body)
                reply = self._sock.recv()
            except zmq.Again as exc:
                self._connect()
                raise ZmqKeyStoreError(
                    f"timeout waiting for key store server at {self._endpoint}"
                ) from exc
            except zmq.ZMQError as exc:
                self._connect()
                raise ZmqKeyStoreError(f"ZMQ error: {exc}") from exc
        if len(reply) > MAX_MESSAGE_BYTES:
            raise ZmqKeyStoreError("server response exceeds maximum message size (64 KiB)")
        try:
            data = json.loads(reply.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ZmqKeyStoreError("invalid JSON in server response") from exc
        if not isinstance(data, dict):
            raise ZmqKeyStoreError("server response must be a JSON object")
        return data

    def _check_status(self, data: Dict[str, Any], *, op: str) -> Dict[str, Any]:
        status = data.get("status")
        if status == "ok":
            return data
        if status == "not_found":
            raise ZmqKeyStoreError(data.get("message", f"not found for op {op}"))
        if status == "error":
            raise ZmqKeyStoreError(data.get("message", "server error"))
        raise ZmqKeyStoreError(f"unexpected server status: {status!r}")

    def ping(self) -> str:
        """Confirm the server is reachable. Returns server version string."""
        data = self._request({"op": "ping"})
        data = self._check_status(data, op="ping")
        return str(data.get("version", ""))

    def get(self, callsign: str) -> str:
        """Return the Brainpool public key PEM for callsign."""
        data = self._request({"op": "get", "callsign": callsign})
        if data.get("status") == "not_found":
            raise ZmqKeyStoreError(f"callsign not found: {callsign}")
        data = self._check_status(data, op="get")
        pem = data.get("public_key_pem")
        if not pem:
            raise ZmqKeyStoreError("server returned ok without public_key_pem")
        try:
            validate_brainpool_public_pem(pem)
        except ValueError as exc:
            raise ZmqKeyStoreError(f"server returned invalid public key: {exc}") from exc
        return pem

    def put(self, callsign: str, public_key_pem: str) -> None:
        """Add or update a Brainpool public key for callsign."""
        try:
            validate_brainpool_public_pem(public_key_pem)
        except ValueError as exc:
            raise ZmqKeyStoreError(str(exc)) from exc
        data = self._request(
            {"op": "put", "callsign": callsign, "public_key_pem": public_key_pem}
        )
        self._check_status(data, op="put")

    def delete(self, callsign: str) -> None:
        """Remove callsign from the store. Raises if not found."""
        data = self._request({"op": "delete", "callsign": callsign})
        if data.get("status") == "not_found":
            raise ZmqKeyStoreError(f"callsign not found: {callsign}")
        self._check_status(data, op="delete")

    def list(self) -> List[str]:
        """Return all callsign strings (no key material)."""
        data = self._request({"op": "list"})
        data = self._check_status(data, op="list")
        callsigns = data.get("callsigns")
        if not isinstance(callsigns, list):
            raise ZmqKeyStoreError("server returned ok without callsigns list")
        return [str(c) for c in callsigns]
