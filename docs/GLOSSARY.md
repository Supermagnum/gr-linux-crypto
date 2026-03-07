# Glossary

Technical terms used in gr-linux-crypto and their explanations.

**AES-GCM** — Advanced Encryption Standard in Galois/Counter Mode. A symmetric authenticated encryption scheme that provides confidentiality and integrity. Used in this module for payload encryption in ECIES and for kernel crypto block operations.

**Brainpool** — A family of elliptic curves standardized by the German BSI (Bundesamt für Sicherheit in der Informationstechnik). This module supports brainpoolP256r1, brainpoolP384r1, and brainpoolP512r1. They are used for ECDH, ECDSA, and ECIES and are defined in BSI TR 03111 and RFC 5639.

**BSI TR 03111** — Technical guideline from the German Federal Office for Information Security describing cryptographic procedures and parameters, including the use of Brainpool curves and ECKA-EG style key agreement.

**Callsign** — In this module, a short identifier (e.g. amateur radio callsign like W1ABC) used to look up a recipient's public key in the key store or kernel keyring. Keys can be stored with description `callsign:CALLSIGN` so the multi-recipient encrypt block can resolve them by callsign.

**ChaCha20-Poly1305** — A symmetric authenticated encryption scheme (stream cipher + MAC). Used as an alternative to AES-GCM in this module for payload encryption; often preferred on devices without AES hardware acceleration.

**ECDH** — Elliptic Curve Diffie-Hellman. A key-agreement protocol where two parties derive a shared secret from their key pairs. Used inside ECIES and ECKA-EG.

**ECDSA** — Elliptic Curve Digital Signature Algorithm. Used in this module for signing and verifying (e.g. sender authentication with `encrypt_and_sign` / `verify_and_decrypt`).

**ECIES** — Elliptic Curve Integrated Encryption Scheme. Hybrid encryption: a symmetric session key is agreed via ECDH (often with an ephemeral key), then the payload is encrypted with that key using a symmetric AEAD cipher (e.g. AES-GCM). This module implements single- and multi-recipient ECIES with Brainpool curves.

**ECKA-EG** — Elliptic Curve Key Agreement (German standard). In this module it refers to the BSI-style construction: ECDH shared secret plus HKDF with a domain-separated info string to derive a symmetric key. Implemented as `CryptoHelpers.brainpool_ecka_eg()`.

**GnuPG / GPG** — GNU Privacy Guard. Software for encryption and signing; manages keys and can use OpenPGP Cards (e.g. Nitrokey in OpenPGP mode). This module uses GnuPG for key listing (key IDs, keygrips) and for on-card ECDH when using the C++ block with `key_source="opgp_card"`.

**HKDF** — HMAC-based Key Derivation Function. Used to derive symmetric keys from a shared secret (e.g. after ECDH) with optional salt and info. Used in ECIES and ECKA-EG in this module.

**HPKE** — Hybrid Public Key Encryption. A standard for combining key encapsulation with authenticated encryption. In this module, "HPKE-style" refers to the `HPKEBrainpool` wrapper that offers a simple `seal` / `open` (and authenticated `seal_with_auth` / `open_with_auth`) API on top of multi-recipient ECIES.

**Keygrip** — A 40-character hexadecimal identifier for a key in GnuPG. Used to refer to a key on an OpenPGP Card or in the keyring. In this module you can store a keygrip in the key store instead of a PEM; the block then fetches the public key from the card. Obtain with `gpg --list-secret-keys --with-keygrip`.

**Kernel keyring** — Linux kernel facility for holding keys (e.g. user keys) in a secure way. This module can store and retrieve keys using descriptions such as `callsign:CALLSIGN` so that the multi-recipient encrypt block can resolve recipient keys without a JSON file.

**Multi-recipient** — Encrypting one message for multiple recipients. Each recipient gets an encrypted copy of the same session key (or, in Shamir mode, one share of the session key); the payload is encrypted once. This module supports up to 25 recipients.

**Nitrokey** — Hardware security device that can store keys and perform crypto operations on-device. In OpenPGP mode it behaves like an OpenPGP Card; the C++ decrypt block can use it via GnuPG with `key_source="opgp_card"` and the keygrip.

**OpenPGP Card** — A smart card (or device like Nitrokey in OpenPGP mode) that holds private keys and performs operations on-card. Private keys never leave the device. This module uses GnuPG to perform ECDH with the card for multi-recipient decrypt when `key_source="opgp_card"` is set.

**RFC 5639** — IETF RFC that defines the Brainpool elliptic curves (domain parameters and curve orders). The curve orders are used in this module as the prime field for Shamir secret sharing.

**Session key** — A symmetric key (e.g. 32-byte AES-256 key) used to encrypt a single message or session. In ECIES, a session key is agreed via ECDH (with an ephemeral key) and then used with AES-GCM or ChaCha20-Poly1305 to encrypt the payload.

**Shamir's Secret Sharing** — A scheme to split a secret into N shares so that any K shares (threshold K) can reconstruct the secret. In this module, the secret (or a value that derives the session key) is split over a prime field; the prime is the Brainpool curve order (P256, P384, or P512) for BSI/RFC 5639 alignment. Used for K-of-N quorum decryption via `encrypt_shamir` / `decrypt_shamir`. With Shamir over the session key, no single operator and no coalition smaller than K can read the content; recovery requires K designated operators to contribute their shares. This enforces collective decision-making cryptographically rather than just socially.

**Symmetric cipher** — Encryption algorithm that uses the same key for encryption and decryption (e.g. AES-GCM, ChaCha20-Poly1305). In this module, the payload in ECIES is encrypted with a symmetric cipher; the key is derived from ECDH (or from reconstructed Shamir shares).

**Threshold (K-of-N)** — In Shamir secret sharing, the minimum number K of shares required to reconstruct the secret. For example, 2-of-3 means any two of three recipients can combine their shares to recover the session key and decrypt. Content is only recoverable when K designated operators each contribute their share; no single operator and no coalition smaller than K can read it alone, which enforces collective decision-making cryptographically rather than just socially.
