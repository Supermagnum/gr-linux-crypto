# gr-linux-crypto Usage Notes

This document supplements the top-level `README.md` with task-focused instructions.

## Python environment

Install test and helper dependencies from `requirements.txt` in a **virtual environment**:

```bash
cd /path/to/gr-linux-crypto
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

GNU Radio itself should still come from system packages (`gnuradio-dev`, `python3-gnuradio`). Use the venv when running `pytest`, `scripts/epk_generate.py`, and examples that import `gr_linux_crypto` helpers.

## libsodium PDU blocks (X-Wing KEM, SHA3)

Built when CMake finds **libsodium** (prefer `/usr/local` 1.0.22 via `PKG_CONFIG_PATH`; see README). Blocks are under **`[gr-linux-crypto]/Sodium`** in GRC and exposed in Python as `linux_crypto.kem_*` and `linux_crypto.hash_sha3`.

| Block | Message ports | Role |
|-------|---------------|------|
| **KEM Generate Keypair** | `generate` (in), `status` (out) | `crypto_kem_keypair()`; writes raw pk/sk files |
| **KEM Encrypt** | `in`, `out` | `crypto_kem_enc()` + `crypto_secretbox_easy()` on plaintext PDU |
| **KEM Decrypt** | `in`, `out` | Inverse of encrypt (`crypto_kem_dec`, `crypto_secretbox_open_easy`) |
| **Hash SHA3** | `in`, `out` | SHA3-256 or SHA3-512 digest PDU (`digest_bits` 256 or 512) |

**Key files:** raw binary — public key `crypto_kem_PUBLICKEYBYTES` (1216 B), secret key `crypto_kem_SECRETKEYBYTES` (32 B). **Encrypt output PDU** uses framing magic `GKEM`, then length-prefixed KEM ciphertext, nonce (24 B), and secretbox ciphertext.

```python
from gnuradio import linux_crypto

linux_crypto.kem_generate_keypair("/tmp/xwing_pk.bin", "/tmp/xwing_sk.bin")
enc = linux_crypto.kem_encrypt("/tmp/xwing_pk.bin")
dec = linux_crypto.kem_decrypt("/tmp/xwing_sk.bin")
h = linux_crypto.hash_sha3(256)
```

Connect message ports to PDU blocks (for example GNU Radio `pdu_*` blocks). Complements Brainpool ECIES under **`[gr-linux-crypto]/Crypto`** for post-quantum-safe encapsulation with libsodium X-Wing.

## Ephemeral key exchange (out-of-band)

Forward secrecy for GR-K-GDSS-style links is described in GR-K-GDSS documentation (ephemeral ECDH vs long-term-only ECDH). This repository provides:

- `EphemeralKeyStore` (`python/ephemeral_key_store.py`) for generating, importing, deriving from, and revoking `.epk.gpg` offers (Galdralag-compatible session KDF material).
- `scripts/epk_generate.py` for command-line generate/import/status/expire.
- GNU Radio block **Ephemeral Key Import (Galdralag / GDSS)** (`grc/linux_crypto_ephemeral_key_import.block.yml`) emitting the same `set_key` PMT as **GDSS Set Key Source**.

Full format and threat model: `docs/EPHEMERAL_KEY_EXCHANGE.md`.

### Physical swap workflow

1. Operator A generates an offer and a BrainpoolP256r1 ephemeral keypair; stores the private key in the session keyring; hands the `.epk.gpg` file to operator B (USB, email with separate channel for fingerprint verification, etc.).
2. Operator B imports the offer with the expected issuer fingerprint; the offer JSON is stored in the kernel keyring with `keyctl timeout` until `expires_at`.
3. Both sides run ECDH with their ephemeral private key and the peer public key from the offer, then `derive_galdralag_session_keys` (or the GRC block which derives the GDSS masking key only).

### CLI examples

```bash
export GR_LINUX_CRYPTO_DIR=/path/to/gr-linux-crypto

python3 scripts/epk_generate.py generate \
  --long-term-key KEY_ID \
  --recipient RECIPIENT_KEY_ID \
  --expires-in 86400 \
  --output offer.epk.gpg

python3 scripts/epk_generate.py import \
  --offer peer_offer.epk.gpg \
  --verify-fingerprint ISSUER_FINGERPRINT_HEX

python3 scripts/epk_generate.py status

python3 scripts/epk_generate.py expire SESSION_ID_HEX
```

`expire` unlinks the offer (and matching local ephemeral private key, if present) from the kernel keyring and clears this process's in-memory offer row. It matches Galdralag-style manual revocation (`reason: manual_revoke` in the audit log). Use the same `session_id` as printed by `import` or `status`. A second `expire` on the same id fails with a non-zero exit once nothing remains to revoke.

Multiple `--recipient` flags encrypt to a group.

### GRC

Add **Ephemeral Key Import (Galdralag / GDSS)** under `[gr-linux-crypto]/Galdralag`. Parameter sources (issuer fingerprint, offer session id vs GDSS session id, `peer_was_initiator`, private key): see [README — Obtaining parameters](README.md#obtaining-parameters-gdss-set-key-source-and-ephemeral-key-import).

Minimum fields:

| GRC parameter | Where to get it |
|---------------|-----------------|
| `offer_gpg_path` | Path to peer `.epk.gpg` |
| `verify_fingerprint` | Issuer long-term GnuPG fingerprint (40 hex chars); `gpg --fingerprint` or `import` / decrypted JSON |
| `our_session_id` | **32 hex chars** from `epk_generate.py import` output or `status` — **not** the GDSS integer |
| `our_epk_private_hex` | Your ephemeral PKCS#8 PEM/DER as hex; empty only if private key is in keyring under the same offer `session_id` |
| `session_id` (int) | Agreed GDSS nonce value with the other station (default `1`) |
| `tx_seq` (int) | Agreed TX sequence for this burst (default `0`) |
| `peer_was_initiator` | `true` if you imported the peer's offer they sent first; `false` if you generated first |

Connect `set_key_out` to GR-K-GDSS spreader/despreader `set_key` ports.

**GDSS Set Key Source** (`[gr-linux-crypto]/GDSS`) uses `shared_secret_hex` from Brainpool ECDH (or the same ECDH implied by two offers), optional `key_derivation=galdralag` with both EPK hex strings, and the same integer `session_id` / `tx_seq`. See the same [parameter guide](README.md#obtaining-parameters-gdss-set-key-source-and-ephemeral-key-import).

### Expiry model

Each offer is valid for **one successful derivation** or until `expires_at`, whichever comes first. The kernel key is also removed after `expires_at - import_time` seconds via `keyctl timeout`. An operator may end the offer earlier with `epk_generate.py expire` (see above).

### NFC (planned)

See Section 7 of `docs/EPHEMERAL_KEY_EXCHANGE.md`. No code changes are required to the envelope when NFC transport is added.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/epk_generate.py` | Ephemeral offer CLI: `generate`, `import`, `status`, `expire` (requires `gpg`, `GR_LINUX_CRYPTO_DIR` or install) |
| `scripts/generate_sbom.py` | SBOM output when built with `-DGR_LINUX_CRYPTO_SBOM=ON` |
| `scripts/verify_sbom.py` | Validate `build/sbom.cdx.json` and `build/sbom.spdx.json` |

Run from the repository root with the venv activated (see [Python environment](#python-environment)).
