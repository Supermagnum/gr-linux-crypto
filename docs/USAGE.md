# gr-linux-crypto Usage Notes

This document supplements the top-level `README.md` with task-focused instructions.

## Ephemeral key exchange (out-of-band)

Forward secrecy for GR-K-GDSS-style links is described in GR-K-GDSS documentation (ephemeral ECDH vs long-term-only ECDH). This repository provides:

- `EphemeralKeyStore` (`python/ephemeral_key_store.py`) for generating, importing, and deriving Galdralag session keys from `.epk.gpg` offers.
- `scripts/epk_generate.py` for command-line generate/import/status.
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
```

Multiple `--recipient` flags encrypt to a group.

### GRC

Add **Ephemeral Key Import (Galdralag / GDSS)** under `[gr-linux-crypto]/Galdralag`. Set `offer_gpg_path`, `verify_fingerprint`, `our_session_id` (hex from the offer JSON), and either `our_epk_private_hex` or leave it blank to load PKCS#8 PEM from the keyring (`store_private_in_keyring` after generate). Connect `set_key_out` to GR-K-GDSS spreader/despreader `set_key` ports.

### Expiry model

Each offer is valid for **one successful derivation** or until `expires_at`, whichever comes first. The kernel key is also removed after `expires_at - import_time` seconds via `keyctl timeout`.

### NFC (planned)

See Section 7 of `docs/EPHEMERAL_KEY_EXCHANGE.md`. No code changes are required to the envelope when NFC transport is added.
