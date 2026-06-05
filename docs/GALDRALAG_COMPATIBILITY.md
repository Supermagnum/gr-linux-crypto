# Galdralag-firmware compatibility

This document records how **gr-linux-crypto** aligns with
[Galdralag-firmware](https://github.com/Supermagnum/Galdralag-firmware) (Baochip-1x token
framework) and what can be verified **without physical hardware**.

Normative host offer format: [EPHEMERAL_KEY_EXCHANGE.md](EPHEMERAL_KEY_EXCHANGE.md).

## Reference tree

When refreshing vectors or auditing drift, clone Galdralag-firmware alongside this repository
and run its unit tests:

```bash
git clone https://github.com/Supermagnum/Galdralag-firmware.git
cd Galdralag-firmware
cargo test -p ephemeral-session --lib
cargo test -p cess --lib
```

Re-export session KDF golden vectors into gr-linux-crypto:

```bash
cargo run -p ephemeral-session --example export_session_kdf_vectors \
  > ../gr-linux-crypto/tests/fixtures/galdralag_session_kdf_vectors.json
```

## Compatibility matrix

| Area | Galdralag-firmware | gr-linux-crypto | Status |
|------|-------------------|-----------------|--------|
| Session HKDF-SHA256 salt | `ordered_epk_salt` (lexicographic min\|\|max EPK bytes) | `ordered_epk_salt` in `galdralag_session_kdf.py` | Aligned |
| HKDF domain labels | `crates/ephemeral-session/src/hkdf_labels.rs` | Same byte strings in `galdralag_session_kdf.py` | Aligned |
| `profile_prk` | HKDF-Extract output | Returned as `profile_prk` in `derive_galdralag_session_keys` | Aligned |
| GDSS masking key | `galdralag/session/gdss-mask/v1` | `derive_galdralag_gdss_masking_key`, GDSS Set Key Source `key_derivation=galdralag` | Aligned |
| Classical ECDH IKM | Brainpool `x` coordinate (`pack_shared` / vault ECDH) | `CryptoHelpers.brainpool_ecdh` | Aligned (golden-vector tested) |
| CESS Mode A `K_outer` | `cess::derive_k_outer` (HKDF-BLAKE3) | `derive_galdralag_cess_k_outer_mode_a` (needs PyPI `blake3`) | Aligned (Rust unit-test vectors) |
| Host `.epk.gpg` schema v1 | `galdra-core-host` `OfferJson` | `EphemeralKeyStore`, `scripts/epk_generate.py` | Aligned |
| Inner offer signature | Detached GnuPG over raw SEC1 EPK only | Same (`gpg --verify` on decoded `epk_hex`) | Aligned |
| Token `InitMessage` / `ResponseMessage` | ECDSA over SHA256(preimage) | Not used by host offers | Different by design |
| Issuer fingerprint in offers | GnuPG fingerprint (40 hex) | `long_term_fingerprint` in offers | Host path only |
| Token trust fingerprint | SHA-256(uncompressed SEC1 verifying key) (64 hex) | Not mixed into host offers | Do not interchange |
| Ephemeral curves in offers | Host: BrainpoolP256r1 only | `DEFAULT_CURVE` in ephemeral key store | Subset of token P256/P384/P512 |
| CESS Mode A normative ECDH | BrainpoolP384r1 (`ephemeral-session` docs) | Helpers accept any Brainpool IKM length; offers are P256 | Document P384 when using CESS outer on token |
| Cipher-profile cascade AEAD | Token / `cipher-profile` crate | KDF helpers only on host | Host derives keys; cascade runs on token |
| Offer DB | `galdra-core-host` SQLite `ephemeral_offers` | Linux kernel keyring + in-memory store | Different storage; same JSON semantics |

## Verified without hardware

The following are covered by automated tests in this repository:

1. **Session subkeys** — `tests/test_galdralag_session_kdf.py` loads
   `tests/fixtures/galdralag_session_kdf_vectors.json` exported from Galdralag-firmware
   (`export_session_kdf_vectors` example) and asserts bit-identical HKDF output.
2. **Brainpool ECDH IKM** — Same test module regenerates FakeTrng seeds 7/8 key pairs and
   checks `CryptoHelpers.brainpool_ecdh` matches the Rust IKM in the fixture.
3. **CESS HKDF-BLAKE3** — Vectors copied from `crates/cess/src/hkdf_blake3.rs` when PyPI
   `blake3` is installed.
4. **Ephemeral offer lifecycle** — `tests/test_ephemeral_key_store.py` (import, derive, expire,
   fingerprint checks) against the host schema shared with `galdra-core-host`.

Physical Baochip hardware is **not required** for the above. Token wire handshake, NFC, and
cipher-profile cascades on-device remain integration tests for when hardware is available.

## Host workflows

### Out-of-band offers (current)

1. Station A: `python3 scripts/epk_generate.py generate` → `.epk.gpg`
2. Station B: import via `Ephemeral Key Import` block or `epk_generate.py import`
3. Both sides: Brainpool ECDH + `derive_galdralag_session_keys` with consistent initiator/
   responder EPK order (`peer_was_initiator` on the import block).
4. GR-K-GDSS: connect `set_key_out` from **Ephemeral Key Import** or **GDSS Set Key Source**
   with `key_derivation=galdralag`.

See [README.md](../README.md) (Ephemeral Key Import, GDSS Set Key Source) and
[USAGE.md](USAGE.md) for GRC parameters.

### Token wire protocol (future hardware)

When a Baochip token is present, `InitiatorSession` / `ResponderSession` in
`ephemeral-session` perform authenticated ephemeral ECDH on-device. Host `.epk.gpg` offers are
**not** byte-identical to `InitMessage` payloads (different signing preimages). Translate
between formats at a gateway or use the token path end-to-end; do not assume a host offer can
be fed directly into token `InitMessage` verification without conversion.

## Known limitations

- **P256 offers vs P384 CESS:** Host offers use BrainpoolP256r1. CESS Mode A outer envelope
  normatively expects P384 ECDH on the token. Use P384 ephemeral handshakes (or token-native
  sessions) when exercising CESS outer on hardware; P256 session keys still align for GDSS and
  payload subkeys when IKM and EPKs match the handshake actually performed.
- **Session key export in GRC:** GDSS Set Key Source and Ephemeral Key Import currently wire
  `gdss_mask_key` into GR-K-GDSS. Other subkeys (`gdss_sync_key`, `gdss_timing_key`,
  `payload_key_*`, `mac_key`) are available from Python `derive_galdralag_session_keys` for
  custom flowgraphs.
- **No merge with Nitrokey/OpenPGP cipher mixing:** Only the Galdralag stack supports mixing
  cipher modes (ECIES, Shamir, CESS profiles). OpenPGP / Nitrokey paths remain separate.

## Reporting drift

If Galdralag-firmware changes `hkdf_labels.rs`, `ordered_epk_salt`, or offer JSON schema,
update `python/galdralag_session_kdf.py`, re-export fixtures, and extend this matrix. Pin the
firmware commit hash in pull requests when golden vectors change.
