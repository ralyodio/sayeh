# Sayeh — Wire Format v3 (`ZWS3`)

This document is the contract between the Go CLI and the Android app.
Both implementations must agree on it byte for byte.

## 1. Pipeline

```
secret (UTF-8)
   -> DEFLATE (raw, compress/flate | java.util.zip.Deflater(nowrap=true))   [optional]
   -> inner frame  = bodyLen(4) || body || random padding
   -> AES-256-GCM(key, nonce, inner, AAD = header)                          [optional]
   -> container    = header || payload
   -> zero-width codec (B4 or B2)
   -> injected into cover text after the first visible rune
```

Reverse on the way out.

## 2. Container

All integers are **big endian**.

| offset | size | field        | notes                                              |
|--------|------|--------------|----------------------------------------------------|
| 0      | 4    | magic        | ASCII `ZWS3`                                        |
| 4      | 1    | version      | `0x03`                                              |
| 5      | 1    | flags        | bit0 = encrypted, bit1 = compressed, rest reserved |
| 6      | 1    | kdfID        | `0` = none, `1` = PBKDF2-HMAC-SHA256               |
| 7      | 1    | reserved     | `0x00`                                              |

If `flags & 0x01` (encrypted), the following block is present:

| offset | size | field      |
|--------|------|------------|
| 8      | 4    | iterations |
| 12     | 16   | salt       |
| 28     | 12   | nonce      |

Then, always:

| size | field      | notes                          |
|------|------------|--------------------------------|
| 4    | payloadLen | length of `payload` in bytes   |
| N    | payload    | ciphertext+tag, or inner frame |

**`header`** = every byte before `payload`, *including* `payloadLen`.
It is used verbatim as GCM **AAD**, so version, flags, KDF id, iteration
count, salt, nonce and length are all authenticated. Downgrading the KDF or
flipping the "encrypted" bit invalidates the tag.

## 3. Inner frame

| size | field   | notes                                        |
|------|---------|----------------------------------------------|
| 4    | bodyLen | length of `body`                             |
| N    | body    | DEFLATE'd or raw UTF-8 secret                |
| P    | padding | cryptographically random, `P >= 0`           |

The inner frame is padded up to the next multiple of **64 bytes** when
encrypted, so the ciphertext length only leaks the message size in 64-byte
buckets. No padding is added when not encrypted (it would hide nothing).

## 4. Key derivation

```
key = PBKDF2-HMAC-SHA256(password_utf8, salt, iterations, 32 bytes)
```

* salt: 16 random bytes per message
* iterations: 600,000 by default (min accepted on decode: 50,000)
* nonce: 12 random bytes per message, never reused

## 5. Zero-width codecs

`B4` (default, 2 bits per rune):

| bits | rune     | name              |
|------|----------|-------------------|
| `00` | U+200B   | ZERO WIDTH SPACE  |
| `01` | U+200D   | ZERO WIDTH JOINER |
| `10` | U+2060   | WORD JOINER       |
| `11` | U+2064   | INVISIBLE PLUS    |

`B2` (compatibility, 1 bit per rune):

| bit | rune   |
|-----|--------|
| `1` | U+200B |
| `0` | U+200D |

Bits are emitted MSB-first per byte. Any rune outside the active alphabet is
skipped, so visible cover text is transparent to the decoder.

**U+200C (ZWNJ) is deliberately never used** — it is a meaningful character in
Persian/Arabic script (نیم‌فاصله) and carrying data in it would corrupt text.

Decoding tries, in order: `B4` → `B2` → legacy v1/v2 (`STEGO_V1:` /
`STEGO_RAW:` / `STEGO_ENC:` headers over the B2 alphabet). The first one whose
magic/header matches wins.

## 6. Limits

* payloadLen is rejected above 16 MiB.
* Decode allocates only after the length has been validated against the number
  of bytes actually recovered.
