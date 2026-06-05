#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demonstrate ZMQ callsign key store with MultiRecipientECIES.

Requires: pip install pyzmq cryptography

Run: python3 examples/zmq_key_store_example.py
"""

from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python"))

try:
    from zmq_key_store_client import ZmqKeyStoreClient, ZmqKeyStoreError
    from zmq_key_store_server import ZmqKeyStoreServer
except ImportError as exc:
    print(f"Missing dependency: {exc}", file=sys.stderr)
    sys.exit(1)

from crypto_helpers import CryptoHelpers
from multi_recipient_ecies import MultiRecipientECIES


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> int:
    crypto = CryptoHelpers()
    curve = "brainpoolP256r1"

    with tempfile.TemporaryDirectory() as tmp:
        store_path = Path(tmp) / "keys.json"
        port = _free_port()
        server = ZmqKeyStoreServer(str(store_path), port=port, bind="127.0.0.1")
        print(f"Starting ZMQ key store server on 127.0.0.1:{port}")
        thread = threading.Thread(target=server.run_forever, daemon=True)
        thread.start()
        time.sleep(0.2)

        endpoint = f"tcp://127.0.0.1:{port}"
        client = ZmqKeyStoreClient(endpoint=endpoint, timeout=5.0)
        try:
            version = client.ping()
            print(f"Ping OK (server version {version})")

            recipients = []
            for callsign in ("W1ABC", "K2XYZ"):
                priv, pub = crypto.generate_brainpool_keypair(curve)
                pem = crypto.serialize_brainpool_public_key(pub).decode("ascii")
                priv_pem = crypto.serialize_brainpool_private_key(priv).decode("ascii")
                client.put(callsign, pem)
                recipients.append((callsign, priv_pem))
                print(f"Added public key for {callsign}")

            listed = client.list()
            print(f"Callsigns in store: {listed}")

            ecies = MultiRecipientECIES(
                curve=curve,
                key_store_path=str(store_path),
                use_keyring=False,
                key_store_client=client,
            )
            plaintext = b"Hello from ZMQ key store example"
            callsigns = [c for c, _ in recipients]
            encrypted = ecies.encrypt(plaintext, callsigns)
            print(f"Encrypted {len(plaintext)} bytes to {callsigns} ({len(encrypted)} byte block)")

            callsign, priv_pem = recipients[0]
            decrypted = ecies.decrypt(encrypted, callsign, priv_pem)
            print(f"Decrypted for {callsign}: {decrypted!r}")
            assert decrypted == plaintext
        except ZmqKeyStoreError as exc:
            print(f"ZMQ key store error: {exc}", file=sys.stderr)
            return 1
        finally:
            client.close()
            server.stop()

    print("Example completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
