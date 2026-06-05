# gr-linux-crypto Usage Notes

This document supplements the top-level `README.md` with task-focused instructions.

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
