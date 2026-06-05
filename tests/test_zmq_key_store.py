# -*- coding: utf-8 -*-
"""Tests for ZMQ callsign key store server and client."""

from __future__ import annotations

import json
import socket
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("zmq")

sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from crypto_helpers import CryptoHelpers  # noqa: E402
from multi_recipient_ecies import MultiRecipientECIES  # noqa: E402
from zmq_key_store_client import (  # noqa: E402
    ZmqKeyStoreClient,
    ZmqKeyStoreError,
    validate_brainpool_public_pem,
)
from zmq_key_store_client import MAX_MESSAGE_BYTES  # noqa: E402
from zmq_key_store_server import (  # noqa: E402
    ZmqKeyStoreServer,
    _require_loopback_bind,
    handle_request,
)
from callsign_key_store import CallsignKeyStore  # noqa: E402


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def brainpool_public_pem():
    crypto = CryptoHelpers()
    _priv, pub = crypto.generate_brainpool_keypair("brainpoolP256r1")
    return crypto.serialize_brainpool_public_key(pub).decode("ascii")


@pytest.fixture
def brainpool_private_pem():
    crypto = CryptoHelpers()
    priv, _pub = crypto.generate_brainpool_keypair("brainpoolP256r1")
    return crypto.serialize_brainpool_private_key(priv).decode("ascii")


@pytest.fixture
def rsa_public_pem():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


@pytest.fixture
def zmq_server(tmp_path):
    store_path = tmp_path / "keys.json"
    port = _free_tcp_port()
    server = ZmqKeyStoreServer(str(store_path), port=port, bind="127.0.0.1")
    server.start()
    time.sleep(0.15)
    endpoint = f"tcp://127.0.0.1:{port}"
    yield endpoint, store_path
    server.stop()


@pytest.fixture
def zmq_client(zmq_server):
    endpoint, _store_path = zmq_server
    client = ZmqKeyStoreClient(endpoint=endpoint, timeout=5.0)
    yield client
    client.close()


def test_server_ping(zmq_client):
    assert zmq_client.ping() == "1.0"


def test_put_get_roundtrip(zmq_client, brainpool_public_pem):
    zmq_client.put("W1ABC", brainpool_public_pem)
    got = zmq_client.get("W1ABC")
    assert got.strip() == brainpool_public_pem.strip()


def test_put_rejects_private_key(zmq_client, brainpool_private_pem):
    with pytest.raises(ZmqKeyStoreError, match="private keys are not accepted"):
        zmq_client.put("W1ABC", brainpool_private_pem)


def test_put_rejects_rsa(zmq_client, rsa_public_pem):
    with pytest.raises(ZmqKeyStoreError, match="Brainpool|elliptic curve|invalid"):
        zmq_client.put("W1ABC", rsa_public_pem)


def test_put_rejects_malformed_pem(zmq_client):
    with pytest.raises(ZmqKeyStoreError, match="malformed|invalid"):
        zmq_client.put("W1ABC", "not-a-pem")


def test_get_not_found(zmq_client):
    with pytest.raises(ZmqKeyStoreError, match="not found"):
        zmq_client.get("NOBODY")


def test_delete_and_get_not_found(zmq_client, brainpool_public_pem):
    zmq_client.put("K2XYZ", brainpool_public_pem)
    zmq_client.delete("K2XYZ")
    with pytest.raises(ZmqKeyStoreError, match="not found"):
        zmq_client.get("K2XYZ")


def test_list_callsigns_only(zmq_client, brainpool_public_pem):
    zmq_client.put("W1ABC", brainpool_public_pem)
    zmq_client.put("K2XYZ", brainpool_public_pem)
    listed = zmq_client.list()
    assert set(listed) == {"W1ABC", "K2XYZ"}
    for item in listed:
        assert "BEGIN PUBLIC KEY" not in item


def test_malformed_json_does_not_crash_server(zmq_server):
    endpoint, store_path = zmq_server
    store = CallsignKeyStore(store_path=str(store_path), use_keyring=False)
    reply = handle_request(store, b"{not json")
    data = json.loads(reply.decode("utf-8"))
    assert data["status"] == "error"


def test_oversized_message_returns_error(tmp_path):
    store = CallsignKeyStore(store_path=str(tmp_path / "k.json"), use_keyring=False)
    huge = b"x" * (MAX_MESSAGE_BYTES + 1)
    reply = handle_request(store, huge)
    data = json.loads(reply.decode("utf-8"))
    assert data["status"] == "error"
    assert "64 KiB" in data["message"]


def test_client_timeout_when_server_not_running():
    port = _free_tcp_port()
    client = ZmqKeyStoreClient(endpoint=f"tcp://127.0.0.1:{port}", timeout=0.5)
    try:
        with pytest.raises(ZmqKeyStoreError, match="timeout"):
            client.ping()
    finally:
        client.close()


def test_multi_recipient_ecies_with_zmq_client(zmq_server, brainpool_public_pem):
    endpoint, _store_path = zmq_server
    crypto = CryptoHelpers()
    priv_a, pub_a = crypto.generate_brainpool_keypair("brainpoolP256r1")
    priv_b, pub_b = crypto.generate_brainpool_keypair("brainpoolP256r1")
    pem_a = crypto.serialize_brainpool_public_key(pub_a).decode("ascii")
    pem_b = crypto.serialize_brainpool_public_key(pub_b).decode("ascii")
    priv_a_pem = crypto.serialize_brainpool_private_key(priv_a).decode("ascii")

    client = ZmqKeyStoreClient(endpoint=endpoint, timeout=5.0)
    try:
        client.put("W1ABC", pem_a)
        client.put("K2XYZ", pem_b)
        ecies = MultiRecipientECIES(
            curve="brainpoolP256r1",
            key_store_path=str(_store_path),
            use_keyring=False,
            key_store_client=client,
        )
        plaintext = b"zmq multi-recipient test"
        encrypted = ecies.encrypt(plaintext, ["W1ABC", "K2XYZ"])
        decrypted = ecies.decrypt(encrypted, "W1ABC", priv_a_pem)
        assert decrypted == plaintext
        assert encrypted[0] == MultiRecipientECIES.FORMAT_VERSION
    finally:
        client.close()


def test_multi_recipient_ecies_without_zmq_client_regression(tmp_path):
    crypto = CryptoHelpers()
    store_path = tmp_path / "keys.json"
    store = CallsignKeyStore(store_path=str(store_path), use_keyring=False)
    priv, pub = crypto.generate_brainpool_keypair("brainpoolP256r1")
    pem = crypto.serialize_brainpool_public_key(pub).decode("ascii")
    priv_pem = crypto.serialize_brainpool_private_key(priv).decode("ascii")
    store.add_public_key("W01ABC", pem)

    ecies = MultiRecipientECIES(
        curve="brainpoolP256r1",
        key_store_path=str(store_path),
        use_keyring=False,
    )
    plaintext = b"local key store regression"
    encrypted = ecies.encrypt(plaintext, ["W01ABC"])
    assert ecies.decrypt(encrypted, "W01ABC", priv_pem) == plaintext


def test_validate_brainpool_public_pem_rejects_private(brainpool_private_pem):
    with pytest.raises(ValueError, match="private keys"):
        validate_brainpool_public_pem(brainpool_private_pem)


def test_server_rejects_non_loopback_bind(tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        ZmqKeyStoreServer(
            str(tmp_path / "keys.json"),
            port=_free_tcp_port(),
            bind="0.0.0.0",
        )


def test_require_loopback_bind_accepts_ipv6_loopback():
    assert _require_loopback_bind("::1") == "::1"
