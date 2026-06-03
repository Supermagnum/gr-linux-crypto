# gr-linux-crypto Test Suite

Python tests for `gr_linux_crypto` helpers, GNU Radio Python bindings (when installed), and cryptographic behaviour. C++ blocks (Brainpool ECIES, libsodium KEM PDU, kernel keyring) are exercised indirectly via Python helpers or require a built `linux_crypto` module and GNU Radio on the system.

**Last full run (reference):** 506 passed, 47 skipped, 553 collected (`pytest tests/` on Linux, Python 3.12).

## Prerequisites

### Virtual environment

Install dependencies from the repository root (do not install into system Python):

```bash
cd /path/to/gr-linux-crypto
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

`requirements.txt` includes `pytest`, `cryptography`, and `numpy`. **GNU Radio** (`python3-gnuradio`, `gnuradio-dev`) should come from system packages; the PyPI `gnuradio` package is commented out in `requirements.txt` because it is incomplete for block bindings.

### PYTHONPATH

`tests/conftest.py` adds the repo `python/` directory automatically. If imports fail outside pytest, use:

```bash
export PYTHONPATH="$(pwd)/python:$(pwd)"
```

## Running tests

```bash
# All tests (default: skip slow keyring integration unless enabled)
pytest tests/ -v

# Exclude slow tests
pytest tests/ -v -m "not slow"

# Ephemeral key offer + Galdralag KDF
pytest tests/test_ephemeral_key_store.py tests/test_galdralag_session_kdf.py -v

# Core Python crypto helpers
pytest tests/test_linux_crypto.py -v

# Brainpool / ECIES / compliance
pytest tests/test_brainpool_comprehensive.py tests/test_multi_recipient_ecies.py -v

# Optional: real keyctl timeout test (~11s); needs keyutils
RUN_KEYRING_SLOW_TESTS=1 pytest tests/test_ephemeral_key_store.py -v -m slow
```

### Coverage

With the project venv activated (see **Virtual environment** above):

```bash
pip3 install pytest-cov
pytest tests/ --cov=python --cov-report=html
```

### Markers (`pytest.ini`)

| Marker | Meaning |
|--------|---------|
| `slow` | Long-running (e.g. kernel keyring timeout); deselect with `-m "not slow"` |
| `integration` | Integration-style tests |
| `openssl` | Requires OpenSSL CLI (`pytest -m openssl`) |

## Test modules (by area)

| Module | Focus |
|--------|--------|
| `test_linux_crypto.py` | AES/ChaCha helpers, round-trip, errors, OpenSSL cross-validation |
| `test_performance.py` | Latency and resource benchmarks |
| `test_multi_recipient_ecies.py` | Multi-recipient ECIES, ECKA-EG, Shamir-backed flows, key store files |
| `test_brainpool_comprehensive.py` | Brainpool ECDH/ECDSA, Wycheproof, BSI hooks |
| `test_brainpool_all_sources.py` | Cross-implementation (OpenSSL CLI, etc.) |
| `test_brainpool_vectors.py`, `test_brainpool_vectors_extended.py` | Vector-driven Brainpool checks |
| `test_nist_vectors.py` | NIST CAVP AES-GCM, RFC 8439 ChaCha20-Poly1305 |
| `test_bsi_tr03111.py` | BSI TR-03111 curve/ECDH/ECDSA compliance |
| `test_ectester.py` | ECTester-style curve checks |
| `test_rfc_compliance.py`, `test_rfc_vectors.py` | RFC 7027/6954/8734 Brainpool usage |
| `test_ecgdsa.py` | ECGDSA framework (NotImplemented where expected) |
| `test_galdralag_session_kdf.py` | Galdralag HKDF labels, GDSS mask agreement, optional blake3 CESS |
| `test_ephemeral_key_store.py` | `.epk.gpg` offer validation, `revoke_offer`, `epk_generate.py` CLI, audit `manual_revoke` |
| `test_shamir_hpke_nitrokey.py` | Shamir, HPKE Brainpool, Nitrokey bridge stubs |
| `test_m17_integration.py` | M17 frame and session helpers |
| `test_scapy_attack_vectors.py` | Scapy packet crafting (no on-air traffic) |
| `test_side_channel.py` | Timing framework (some tests environment-sensitive) |
| `test_zeroization.py` | `secure_zero` / buffer clearing |
| `test_fips.py` | FIPS status helper when OpenSSL FIPS build enabled |
| `test_pq_kem.py` | PQ hybrid KEM stubs when not built with `GR_LINUX_CRYPTO_PQ_KEM` |
| `test_sbom.py` | SBOM generation when `GR_LINUX_CRYPTO_SBOM=ON` |
| `test_algorithm_boundary.py` | BSI TR-02102 approved/rejected algorithm lists |

**Not in pytest (separate workflows):**

- `integration_test_multi_recipient.py`, `validate_multi_recipient.py` — manual/integration scripts
- `cbmc/` — CBMC harnesses for kernel AES (see `cbmc/README.md`)
- `dudect/` — side-channel analysis examples (submodule; see `dudect/README.md`)
- **C++ libsodium PDU blocks** (`kem_encrypt`, `kem_decrypt`, `kem_generate_keypair`, `hash_sha3`) — built when `SODIUM_FOUND`; no dedicated Python unit tests yet; validate via GRC/message-port flowgraphs after install

## Ephemeral key tests (`test_ephemeral_key_store.py`)

Covers `EphemeralKeyStore` and `scripts/epk_generate.py`:

- Offer expiry and `consumed` validation helpers
- Derive session keys, consumed replay, EPK mismatch
- `revoke_offer` (unconsumed/consumed, unknown session, keyring unlink mocks)
- Audit log `manual_revoke`
- `cmd_expire` and subprocess `expire` exit codes
- **Slow:** `test_offer_keyring_timeout_removes_key` — set `RUN_KEYRING_SLOW_TESTS=1`

See `docs/EPHEMERAL_KEY_EXCHANGE.md` and `docs/USAGE.md`.

## Brainpool vectors and compliance

- Download helpers: `download_brainpool_vectors.sh`, `download_nist_vectors.py`, `setup_test_vectors.sh`
- Vector docs: `test_vectors/README.md`, `README_BRAINPOOL_TESTS.md`

## Fixtures (`conftest.py`)

Common fixtures include `random_key_128`, `random_key_256`, `random_key_chacha20`, `fixed_iv_16`, `fixed_iv_12`, `test_data_small`, `test_data_empty`, `test_data_large`, and parametrized `variable_size_data`.

## Expected results

All non-skipped tests should pass. Skips are normal for:

- Optional GNU Radio / OpenSSL CLI / Nitrokey / HPKE (blake3) dependencies
- Parametrized duplicates filtered in `test_linux_crypto.py`
- `slow` keyring test unless `RUN_KEYRING_SLOW_TESTS=1`
- Galdralag CESS tests when `blake3` is not installed

## Troubleshooting

### Import errors for `gr_linux_crypto` or `gnuradio`

1. Activate the project venv and install `requirements.txt`.
2. Ensure system `python3-gnuradio` matches your GNU Radio install.
3. After `make install`, test: `python3 -c "from gnuradio import linux_crypto"`.

### OpenSSL CLI tests skip

Expected if OpenSSL is missing or a mode is unsupported; tests skip with a message.

### `test_auth_tag_constant_time_comparison` fails

Environment-sensitive Python timing; see `TEST_RESULTS.md` (Side-Channel). Verify constant-time behaviour at the C/library level separately.

### Performance thresholds

Adjust thresholds in `test_performance.py` if the host is heavily loaded; re-run to confirm variance.

## Further reading

- **`TEST_RESULTS.md`** — Detailed historical results, NIST/Wycheproof status, fuzzing, use-case notes
- **`README_BRAINPOOL_TESTS.md`** — Brainpool vector download and focused pytest commands
