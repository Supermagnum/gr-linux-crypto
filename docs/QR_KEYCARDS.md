# QR codes for GnuPG public keys on physical cards

This guide describes how to print and use QR codes that point to an operator's OpenPGP public key. The private key stays on hardware: a **Nitrokey** (via libnitrokey / OpenPGP card mode) or a **Galdralag Baochip-1x** token running **OpenPGP CCID smart-card** firmware ([Galdralag-firmware](https://github.com/Supermagnum/Galdralag-firmware)). From the host, `gpg --card-status`, `gpg --fingerprint`, and normal signing commands behave the same for both token types.

Generate QR artwork with `scripts/gpg_qr_gen.py` (Python, optional `qrcode[pil]` and `lxml`) or with the `qrencode` shell tool below.

## Use case 1 — Physical key distribution

Print a QR code on a **QSL card**, **business card**, or **ID badge** so contacts can import your public key at hamfests, club meetings, or key-signing events.

**Workflow:** Follow the web-of-trust process already described in the README under [Web of Trust and Key Signing Parties](../README.md#web-of-trust-and-key-signing-parties): distribute fingerprints in person, verify identity, sign each other's keys, and optionally upload to a keyserver (see [Key servers - what are those?](../README.md#key-servers---what-are-those)). The QR code is a convenient way to carry the **fingerprint URI** or a **keyserver search link**, not a substitute for in-person identity checks at signing parties.

**Hardware tokens:** Whether the secret key lives on a Nitrokey or on a Galdralag token in OpenPGP card mode, GnuPG treats it as a smart card. Use `gpg --card-status` to confirm the card is present before signing sessions. The QR encodes only **public** key discovery data; the private key never leaves the token.

**Recommended minimum printed QR size**

| Medium | Minimum size | Notes |
|--------|----------------|-------|
| QSL card | 2.5 x 2.5 cm | Leave quiet zone (white margin) around the code |
| Business card | 2 x 2 cm | Prefer SVG output for crisp print |
| ID badge | 2 x 2 cm | Lamination must not cover the quiet zone |

The generator uses error correction level **H** and a quiet-zone border of **2 modules**, which helps small codes scan reliably.

**Generate with Python (default: SVG, OpenKeychain URI):**

```bash
python3 scripts/gpg_qr_gen.py W1ABC -o w1abc-key.svg
python3 scripts/gpg_qr_gen.py --style keyserver your@email.com -o key.svg
python3 scripts/gpg_qr_gen.py --style callsign W1ABC -o w1abc-search.svg
```

The script prints the encoded payload to stdout before writing the file so you can confirm what will be scanned.

**Generate with qrencode (no Python QR dependencies):**

After obtaining your fingerprint with `gpg --fingerprint YOUR_KEY`, encode the same payload the Python tool would use:

```bash
FPR=$(gpg --list-keys --with-colons --with-fingerprint W1ABC | awk -F: '/^fpr:/ {print $10; exit}')
qrencode -o key.svg -t SVG -l H -m 2 "openpgp4fpr:${FPR}"
```

For a keyserver search link, replace the quoted string with `https://keys.openpgp.org/search?q=0x${FPR}`.

## Use case 2 — Callsign identity verification and anti-piracy

Amateur-radio logging software can **sign each QSO record** (or each ADIF export block) with the operator's OpenPGP key on a hardware token. Peers **verify** incoming records against the sender's public key, discovered via QR code, keyserver, or web-of-trust.

**Why impersonation is hard:** The signature is computed **on the token** (Nitrokey or Galdralag). The private key never crosses the USB bus. A pirate would need both the **physical device** and the **PIN**. On Galdralag, the private key additionally **never leaves the device** even under key-export commands, and PIN lockout after a configurable number of failed attempts (typically **3--10** per the token PIN policy) limits guessing.

**Forward secrecy on Galdralag:** The authenticated ephemeral ECDH session protocol used for radio crypto means that even a **future** compromise of the long-term OpenPGP key does not decrypt **past** ephemeral radio sessions when those sessions used Galdralag key agreement correctly. OpenPGP signatures on archived QSO records remain verifiable against the long-term key that signed them; separate ephemeral link keys retain forward secrecy as documented for Galdralag elsewhere in this project.

**Optional three-factor on Galdralag:** If a future biometric or additional factor is enabled on the token, it adds another layer on top of possession and PIN; that remains a token firmware feature, not part of the QR utility itself.

**Verification in software:** Use `CallsignVerifier` from `gr_linux_crypto.callsign_verifier`:

```python
from gr_linux_crypto.callsign_verifier import CallsignVerifier

verifier = CallsignVerifier()
ok = verifier.verify_signed_log_entry(entry_bytes, detached_sig_bytes, "W1ABC")
```

Verification uses `gpg --verify` via subprocess, consistent with the rest of this module. Integrators should canonicalize log bytes (encoding, line endings, field order) before signing and verifying.

## Token removal and host behaviour

The same removal behaviour described in the README under [What happens if I remove my Nitrokey or GnuPG card?](../README.md#what-happens-if-i-remove-my-nitrokey-or-gnupg-card) applies to a **Galdralag token in OpenPGP card mode**: PIN verification state does not survive removal, the private key never leaves the device, and operations fail until the token is reinserted and unlocked.

## Related README sections

- [Web of Trust and Key Signing Parties](../README.md#web-of-trust-and-key-signing-parties)
- [Key servers - what are those?](../README.md#key-servers---what-are-those)
- [What happens if I remove my Nitrokey or GnuPG card?](../README.md#what-happens-if-i-remove-my-nitrokey-or-gnupg-card)

## Dependencies

- **Required:** `gpg` on PATH
- **Optional (QR generation only):** `pip install 'qrcode[pil]' lxml` — see `requirements.txt`
