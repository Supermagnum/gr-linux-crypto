# ZeroMQ callsign key store

The ZMQ key store exposes `CallsignKeyStore` over a local **REQ/REP** socket so GNU Radio flowgraphs and external processes can look up Brainpool **public** keys by amateur-radio callsign at runtime. Transport uses [gr-zeromq](https://www.gnuradio.org/doc/doxygen/page_grzeromq.html) semantics (ZeroMQ); this module does **not** ship ZMQ source/sink blocks.

## When to use it

| Approach | Use when |
|----------|----------|
| **Local JSON** (`CallsignKeyStore`, default) | Single machine, keys edited infrequently, C++ multi-recipient blocks with `key_store_path` |
| **ZMQ key store** | Multiple processes, dynamic key updates, Python `MultiRecipientECIES` with `key_store_client` |

ECIES encryption and decryption are unchanged. The ZMQ layer only replaces **public key lookup** during `encrypt()`.

## Security model

**Transport layer:** The ZMQ REQ/REP channel is **unauthenticated and unencrypted**. This module provides no transport security. ECIES blocks handle cryptography for payloads; the key store socket is plain TCP JSON only.

**Supported deployment:** The server binds to a **loopback address only** (`127.0.0.1` by default; `::1` is also accepted). Non-loopback bind addresses are rejected at startup. That limits exposure to local processes on the same host. Operators who need network-facing deployments should read [ZMQ_TRANSPORT_SECURITY.md](ZMQ_TRANSPORT_SECURITY.md) for transport options outside this module.

**Remote or network access:** Not supported by this module. If you need a key store reachable across a network, you must provide transport security **outside** gr-linux-crypto (for example an SSH tunnel or VPN terminating on the host, with the server still bound to loopback). Do not point the server at a network interface and assume the channel is protected.

**Crosses the socket (public data only):**

- Callsign strings
- Brainpool public keys in PEM form
- JSON status fields (`ok`, `not_found`, `error`)

**Never crosses the socket:**

- Private keys (server rejects PEM containing `PRIVATE KEY`; client re-validates responses)
- Plaintext payloads
- Session state, symmetric keys, or ECIES ciphertext (use existing ECIES blocks for that)

**Information disclosure:** Any local process that can reach the REP socket can **enumerate callsigns** (`list`) and **fetch public keys** (`get`). Public keys are public, but callsign-to-key mappings may still be sensitive operationally.

**Logging:** The server logs operation type, callsign, and errors — never PEM bodies.

## Start the server

```bash
cd /path/to/gr-linux-crypto
source .venv/bin/activate
pip install pyzmq

python3 python/zmq_key_store_server.py \
    --key-store ~/.gnuradio/callsign_keys.json \
    --port 5557 \
    --bind 127.0.0.1
```

Defaults: `keys.json` in the current directory, port `5557`, bind `127.0.0.1`.

After `cmake --install`, the script is also installed under `share/gr-linux-crypto/scripts/zmq_key_store_server.py` (imports `gr_linux_crypto` from site-packages). A sample **systemd** unit is in `scripts/zmq_key_store.service`; adjust `/usr/local` to your `CMAKE_INSTALL_PREFIX`.

### Request types (JSON)

| `op` | Request | Success response |
|------|---------|------------------|
| `ping` | `{"op":"ping"}` | `{"status":"ok","version":"1.0"}` |
| `get` | `{"op":"get","callsign":"W1ABC"}` | `{"status":"ok","callsign":"W1ABC","public_key_pem":"..."}` |
| `put` | `{"op":"put","callsign":"W1ABC","public_key_pem":"..."}` | `{"status":"ok"}` |
| `delete` | `{"op":"delete","callsign":"W1ABC"}` | `{"status":"ok"}` or `{"status":"not_found",...}` |
| `list` | `{"op":"list"}` | `{"status":"ok","callsigns":["W1ABC",...]}` |

Malformed JSON, unknown `op`, missing fields, and messages over **64 KiB** return `{"status":"error","message":"..."}` without crashing the server.

## Python client

```python
from gr_linux_crypto.zmq_key_store_client import ZmqKeyStoreClient, ZmqKeyStoreError

client = ZmqKeyStoreClient(endpoint="tcp://127.0.0.1:5557", timeout=5.0)
client.ping()
client.put("W1ABC", public_key_pem)
pem = client.get("W1ABC")
print(client.list())
client.delete("W1ABC")
client.close()
```

Failures raise **`ZmqKeyStoreError`** (timeouts, connection errors, server `error` / `not_found`).

## MultiRecipientECIES integration

```python
from gr_linux_crypto.multi_recipient_ecies import MultiRecipientECIES
from gr_linux_crypto.zmq_key_store_client import ZmqKeyStoreClient

client = ZmqKeyStoreClient("tcp://127.0.0.1:5557")
ecies = MultiRecipientECIES(
    curve="brainpoolP256r1",
    key_store_client=client,
)
ciphertext = ecies.encrypt(b"payload", ["W1ABC", "K2XYZ"])
```

Omit `key_store_client` to keep the original JSON/keyring behaviour.

See `examples/zmq_key_store_example.py` for a full encrypt/decrypt walkthrough.

## systemd

Sample unit: `scripts/zmq_key_store.service`. Adjust paths to your install prefix and key-store directory.

```bash
sudo cp scripts/zmq_key_store.service /etc/systemd/system/
sudo mkdir -p /var/lib/gr-linux-crypto
sudo systemctl daemon-reload
sudo systemctl enable --now zmq_key_store.service
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `ZmqKeyStoreError: timeout waiting for key store server` | Server not running, wrong port, or firewall |
| `private keys are not accepted` | `put` with a PEM containing `PRIVATE KEY` |
| `only Brainpool public keys are accepted` | RSA or non-Brainpool EC key |
| `callsign not found` | No `put` for that callsign, or typo (callsigns are uppercased) |
| `ImportError: pyzmq` | Install in venv: `pip install pyzmq` |

Existing blocks and tests work without `pyzmq`; only `zmq_key_store_server.py`, `zmq_key_store_client.py`, and ZMQ tests require it.
