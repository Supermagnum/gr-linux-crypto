# Multi-Recipient ECIES Key Block Format

## Overview

This document describes the binary format for multi-recipient ECIES encryption, supporting up to 25 recipients. The format uses hybrid encryption: a symmetric key is encrypted for each recipient using ECIES, and the actual data is encrypted with AES-GCM using that symmetric key.

## Format Structure

```
[Header][Recipient Blocks][Encrypted Data]
```

### Header (Fixed Size: 8 bytes)

```
Offset  Size  Field              Description
------  ----  -----------------  -----------------------------------------
0       1     Version            Format version (currently 0x01)
1       1     Curve ID           Brainpool curve identifier:
                                 0x01 = brainpoolP256r1
                                 0x02 = brainpoolP384r1
                                 0x03 = brainpoolP512r1
2       1     Recipient Count    Number of recipients (1-25)
3       1     Cipher ID          Symmetric cipher identifier:
                                 0x01 = AES-256-GCM
                                 0x02 = ChaCha20-Poly1305
4       4     Data Length        Length of encrypted data (big-endian)
```

### Recipient Block (Variable Size)

Each recipient block contains:
- Callsign (null-terminated string, max 15 bytes including null)
- Encrypted symmetric key (ECIES encrypted)

```
Offset  Size  Field                    Description
------  ----  ------------------------ -----------------------------------------
0       1     Callsign Length          Length of callsign (1-14)
1       N     Callsign                Null-terminated callsign string
N+1     2     Encrypted Key Length     Length of ECIES encrypted key (big-endian)
N+3     M     Encrypted Key            ECIES encrypted symmetric key
```

The ECIES encrypted key format matches the single-recipient format:
```
[2 bytes: pubkey_len][pubkey_PEM][12 bytes: IV][2 bytes: ciphertext_len][ciphertext][16 bytes: tag]
```

### Encrypted Data Block

```
[Encrypted Data][Authentication Tag]
```

The encrypted data is encrypted using the symmetric cipher specified in the header (AES-256-GCM or ChaCha20-Poly1305).

## Example Layout

For 2 recipients with callsigns "W1ABC" and "K2XYZ":

```
[Header: 8 bytes]
  Version: 0x01
  Curve: 0x01 (brainpoolP256r1)
  Recipient Count: 0x02
  Cipher: 0x01 (AES-256-GCM) or 0x02 (ChaCha20-Poly1305)
  Data Length: 0x00000100 (256 bytes)

[Recipient 1 Block]
  Callsign Length: 0x05
  Callsign: "W1ABC\0"
  Encrypted Key Length: 0x00AB (171 bytes)
  Encrypted Key: [ECIES encrypted symmetric key]

[Recipient 2 Block]
  Callsign Length: 0x05
  Callsign: "K2XYZ\0"
  Encrypted Key Length: 0x00AB (171 bytes)
  Encrypted Key: [ECIES encrypted symmetric key]

[Encrypted Data]
  [AES-256-GCM encrypted payload]
  [16-byte authentication tag]
```

## Symmetric Key Generation

- Key size: 32 bytes (256 bits) for both AES-256-GCM and ChaCha20-Poly1305
- Generated using cryptographically secure random number generator
- Same key used for all recipients
- Key is never stored in plaintext
- IV/Nonce size: 12 bytes (96 bits) for both ciphers
- Authentication tag size: 16 bytes (128 bits) for both ciphers

## Security Considerations

1. Each recipient's symmetric key is encrypted independently using ECIES
2. The symmetric key is ephemeral and never reused
3. Authenticated encryption (AES-GCM or ChaCha20-Poly1305) provides security for the payload
4. ChaCha20-Poly1305 is recommended for battery-powered devices and software-only implementations
5. AES-GCM is recommended when hardware acceleration (AES-NI) is available
6. Recipient identification via callsign allows efficient key lookup
7. Format supports up to 25 recipients to balance efficiency and flexibility

## Decryption Process

1. Parse header to get recipient count, cipher type, and data length
2. Iterate through recipient blocks to find matching callsign
3. Extract encrypted symmetric key for matching recipient
4. Decrypt symmetric key using recipient's private key (ECIES decryption)
5. Decrypt payload using symmetric key (AES-GCM or ChaCha20-Poly1305 decryption based on cipher ID)
6. Verify authentication tag
