# Ephemeral Key Exchange (Out-of-Band)

Specification for signed, encrypted BrainpoolP256r1 ephemeral public key offers (`.epk.gpg`) used with Galdralag-compatible session KDF in gr-linux-crypto. NFC transport is planned; the file format is intended unchanged when NFC is added.

## 1. Purpose and threat model

Long-term static ECDH keys (for example GnuPG-backed keys used historically with GR-K-GDSS) allow an adversary who later obtains the long-term private key to decrypt recorded traffic. Ephemeral ECDH per session, authenticated by long-term keys, restores forward secrecy for the radio link when combined with `derive_galdralag_session_keys` (see `python/galdralag_session_kdf.py`).

Expiry limits the window in which a stolen offer file can be abused. Combined one-time use (`consumed`) limits replay after a successful session derivation.

This document does not replace the Galdralag firmware `ephemeral-session` protocol on the token; it defines a **host-to-host** envelope for exchanging uncompressed SEC1 ephemeral public keys out-of-band.

## 2. Key offer format (plaintext JSON)

Plaintext is UTF-8 JSON with the following fields (all required unless noted):

| Field | Type | Description |
|-------|------|---------------|
| `schema_version` | integer | Must be `1`. |
| `epk_hex` | string | Lowercase hex of uncompressed SEC1 BrainpoolP256r1 public key (65 bytes). |
| `long_term_fingerprint` | string | Lowercase hex GnuPG fingerprint of the issuer long-term signing key (40 hex chars for SHA-1 style). |
| `signature_hex` | string | Lowercase hex of a **detached GnuPG binary signature** over the raw decoded `epk_hex` bytes (not over the JSON text). |
| `expires_at` | integer | UTC Unix time in seconds; offer invalid at or after this instant. |
| `created_at` | integer | UTC Unix time in seconds when the offer was created; shared audit reference. |
| `session_id` | string | Lowercase hex of 16 random bytes (32 hex chars). |
| `consumed` | boolean | Must be `false` in generated offers; host marks `true` after one successful `derive_session_keys`. |

### Deviation from Galdralag `InitMessage` signing

Galdralag-firmware `ephemeral-session` signs `init_sign_preimage(version, curve_wire_id, epk_bytes)` (see `crates/ephemeral-session/src/protocol.rs`). This host offer format signs **only** the raw SEC1 EPK bytes with GnuPG detached mode so verifiers without the full handshake stack can still bind the long-term key to the ephemeral public key. Interoperating with a Baochip `InitMessage` verifier requires translating to that preimage; this format targets GNU Radio hosts and file swap first.

## 3. Outer envelope (transport)

1. The JSON object is serialized with sorted keys and no extra whitespace (`separators=(",", ":")`).
2. The UTF-8 blob is encrypted and signed with GnuPG in one step: `gpg --encrypt --sign --local-user <issuer> --recipient <r1> [--recipient <r2> ...]` producing binary OpenPGP data (`.epk.gpg`).

Recipients must be able to decrypt with their secret keys. The embedded OpenPGP signature covers the plaintext during decrypt. The inner `signature_hex` field is verified separately with `gpg --verify` against the decoded EPK bytes.

## 4. Timestamp semantics

- `created_at` and `expires_at` are UTC Unix seconds, carried inside the signed+encrypted envelope so they cannot be altered without breaking the OpenPGP layer.
- Clock skew between stations affects perceived freshness; operators should use NTP. If `expires_at` is in the past at import or derive time, the offer is rejected.

## 5. Expiry enforcement

**Combined model:** an offer is valid until the **first** of:

- wall-clock time reaches `expires_at`, or
- a successful `derive_session_keys` marks it `consumed`.

**Kernel keyring:** On import, the serialized JSON is stored with `keyctl padd` and `keyctl timeout <keyid> <seconds>` where `seconds` is `expires_at - now` (minimum 1 second). Per keyutils documentation, the timeout is a number of **seconds into the future**, not an absolute Unix timestamp.

**Application state:** `EphemeralKeyStore` keeps in-memory `consumed` and re-checks `expires_at` on derive so policy holds even if keyring timeout semantics differ on a given system.

**Manual revocation (`epk expire`):** Operators may drop an offer before use by running `python3 scripts/epk_generate.py expire <session_id>`, which calls `EphemeralKeyStore.revoke_offer`. That path unlinks the offer JSON key (`gr_linux_crypto:ephemeral_offer:{session_id}`) and any matching ephemeral private key (`gr_linux_crypto:ephemeral_priv:{session_id}`) from the configured keyring (default session keyring `@s`) via `keyctl unlink` **before** clearing in-memory state, so the payload is detached from the keyring immediately. Revoking an offer that is already `consumed` in memory is allowed and still unlinks any remaining keyring material.

There is **no** host-side SQLite table like Galdralag `ephemeral_offers`. `consumed` is not written back into the keyring JSON when deriving; after a process exit, only keyring blobs (until timeout/unlink), the audit log file, and any other operator-held state survive. A **new** process can revoke by `session_id` if the keyring entries still exist; if the session keyring was cleared or the keys already expired, `revoke_offer` raises `KeyError` unless this process still holds the row in `_offers`.

**Kernel note:** `keyctl unlink` removes the key from the keyring immediately and the kernel frees the key object; this is **not** documented as cryptographic zeroisation of RAM. Material may remain in freed pages until reused.

**`status` after revoke:** The offer row is removed from `_offers` and keys are unlinked, so `status` no longer lists that offer once the keyring and memory are consistent (no `revoked: true` tombstone).

## 6. Audit log

Append-only JSON lines (default file under `XDG_STATE_HOME/gr-linux-crypto/ephemeral_key_audit.log`). Event types include:

- `import` with `session_id`, `created_at`, `expires_at`, `long_term_fingerprint`
- `derive` with `session_id`, `consumed: true`
- `reject` with `reason` (`bad_schema`, `already_consumed`, `expired`, `fingerprint_mismatch`, `bad_epk_signature`, `expired_at_derive`, `consumed_at_derive`, `manual_revoke`)

## 7. Planned: NFC transport

- The `.epk.gpg` file is transmitted as opaque bytes over NFC without format changes.
- NFC proximity (~4 cm) is an operational supplement; cryptographic assurance remains OpenPGP sign+encrypt and the inner detached signature over the EPK.
- The receiving path continues to call `EphemeralKeyStore.import_offer` on the decrypted bytes.
- Python: `nfcpy`; C: `libnfc`. Typical NFC Type 4 payload capacity (~32 KB) exceeds expected `.epk.gpg` size (Brainpool EPK + signatures + OpenPGP framing, order of hundreds of bytes to a few KB).

## 8. Security considerations

- Manage recipient lists carefully; any recipient can decrypt the offer.
- If no Galdralag token is present, hosts rely on GnuPG and Brainpool implementations in software.
- Do not mix X25519 shared secrets from other modules with this Brainpool-only KDF path.

## 9. Galdralag-firmware alignment

Host offers and session KDF in gr-linux-crypto are aligned with
[Galdralag-firmware](https://github.com/Supermagnum/Galdralag-firmware) `galdra-core-host` and
`ephemeral-session` as documented in **[GALDRALAG_COMPATIBILITY.md](GALDRALAG_COMPATIBILITY.md)**.
Automated cross-verification (session subkeys, Brainpool ECDH IKM, CESS HKDF-BLAKE3 vectors) does
not require physical Baochip hardware; token wire handshake and on-device cipher profiles remain
integration tests for when hardware is available.
