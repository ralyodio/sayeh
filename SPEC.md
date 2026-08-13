# Sayeh wire format v4

- Spec version: **1.0.0-draft.2**
- Wire version: **4**
- Magic: **`SYH4`**

This document is the interoperability contract for Sayeh v4. The spec has its
own version because a crate release and a wire-format change are different
events. Implementations may add user-interface features without changing these
bytes.

The v3 `ZWS3` format is deliberately not accepted. Its PBKDF2 construction is
weaker than the v4 password mode, and its carrier alphabet assigns data to
U+200D, which breaks emoji ZWJ sequences. A decoder that recognizes v3 must
return a specific migration error; it must not attempt to open it as v4.

## 1. Scope and byte order

This spec defines the encrypted container, carrier mappings, cost map,
dense scattered embedding revision 1, and hard limits. It does not define a
transport. Chat applications remain the transport.

All integers are unsigned and big endian. Lengths count bytes unless a field
says otherwise. Text fields are UTF-8. Parsers reject non-zero reserved bits,
unknown enum values, non-canonical lengths, and trailing container bytes.

## 2. Pipeline

```text
payload bytes + metadata
  -> content frame
  -> raw DEFLATE when it is smaller                         optional
  -> encodedLen || encoded frame || random bucket padding
  -> XChaCha20-Poly1305(AAD = complete header)
  -> header || ciphertext || tag
  -> selected carrier alphabet
  -> keyed, cost-ranked gaps in the cover
```

Opening reverses those steps. Every authenticated-open failure has the same
public result, whether the cause was a wrong password, wrong contact, edited
header, changed ciphertext, or invalid sealed plaintext.

## 3. Container header

The fixed prefix is 16 bytes.

| offset | size | field | value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `SYH4` |
| 4 | 1 | wire version | `0x04` |
| 5 | 1 | embedding revision | `0x01` |
| 6 | 1 | mode | `0x01` password, `0x02` contact |
| 7 | 1 | carrier | see section 7 |
| 8 | 1 | flags | bit 0 compressed, bit 1 error correction |
| 9 | 1 | reserved | zero |
| 10 | 2 | header length | complete header, including this prefix |
| 12 | 4 | payload length | sealed payload bytes after the header |

Bits 2 through 7 of `flags` are reserved. Error-corrected payloads are reserved
for a later spec revision; revision 1 readers return `unsupported feature` if
bit 1 is set. The bit is assigned now so the header already expresses whether
correction is present.

The complete header, from magic through the final mode field, is passed
verbatim as AEAD associated data. `header length` is 68 in password mode and 72
in contact mode. Revision 1 rejects other lengths.

### 3.1 Password mode fields

| offset | size | field |
|---:|---:|---|
| 16 | 4 | Argon2 memory in KiB (`m`) |
| 20 | 4 | Argon2 passes (`t`) |
| 24 | 1 | Argon2 lanes (`p`) |
| 25 | 3 | reserved, zero |
| 28 | 16 | random salt |
| 44 | 24 | random XChaCha20 nonce |

The password is its exact UTF-8 byte sequence. It is not normalized and the
empty sequence is valid. The key is the 32-byte Argon2id v1.3 tag with the
stored parameters and no secret value or associated data. An empty password
provides no effective confidentiality against an observer who knows this
format; it is an explicit concealment-only choice.

Readers enforce both a floor and a ceiling before allocating Argon2 memory:

| parameter | minimum | maximum |
|---|---:|---:|
| `m` | 19,456 KiB | 1,048,576 KiB |
| `t` | 2 | 10 |
| `p` | 1 | 8 |

The shipping profile is `m=65,536`, `t=10`, `p=1`, selected by measurement on an
ARM64 Android device. Applications store the chosen values in every message.
The benchmark result and device model belong in release notes; the constants
alone are not a performance claim.

### 3.2 Contact mode fields

| offset | size | field |
|---:|---:|---|
| 16 | 32 | sender's ephemeral X25519 public key |
| 48 | 24 | random XChaCha20 nonce |

Each contact owns a static X25519 identity keypair. Let `S` be the sender's
static secret, `S_pub` its public key, `R_pub` the recipient public key, and `E`
the fresh ephemeral secret for this message.

```text
dh_ephemeral = X25519(E, R_pub)
dh_identity  = X25519(S, R_pub)
ikm          = dh_ephemeral || dh_identity
salt         = nonce
info         = "sayeh/v4/contact/aead" || E_pub || S_pub || R_pub
key          = HKDF-SHA256(salt, ikm, info, 32)
```

The receiver obtains the same values with its static secret and tries each
verified sender public key in the local contact store. All-zero X25519 results
are rejected with a constant-time comparison. The second DH binds a successful
open to the verified sender identity without putting a contact identifier in
the public header. It does not provide forward secrecy; that requires the Tier
2 ratchet.

## 4. Sealed plaintext

The content frame is serialized before optional compression.

| size | field |
|---:|---|
| 1 | frame version, `0x01` |
| 1 | kind: `0x01` UTF-8 text, `0x02` file bytes |
| 2 | file-name length; zero for text |
| 8 | monotonic counter; zero in password mode |
| 8 | creation time as Unix seconds; zero is allowed in test vectors |
| 4 | content length |
| N | UTF-8 file name |
| M | content bytes |

Text content and file names must be valid UTF-8. File names are a label, not a
path: `/`, `\\`, NUL, `.` and `..` are rejected. The maximum decoded content is
16 MiB and the maximum encoded file name is 255 bytes.

Contact-mode counters start at 1. A receiver authenticates and parses the
message before comparing the counter with the stored value for that contact. A
counter less than or equal to the last accepted value is a replay and is not
displayed. Advancing the stored value and displaying the plaintext must be one
application-level transaction.

If raw DEFLATE (RFC 1951, no zlib or gzip wrapper) makes the complete frame
smaller, it replaces the frame and flag bit 0 is set. Otherwise the original
frame is used and the bit is clear.

The encoded frame is wrapped as follows:

```text
encoded_length:u32 || encoded_frame || random_padding
```

The total is padded to the next multiple of 64 bytes, with a minimum of one
64-byte bucket. XChaCha20-Poly1305 appends its 16-byte tag. Decompression is
bounded to the maximum frame size before allocating output.

## 5. Authenticated encryption

XChaCha20-Poly1305 uses the mode's 32-byte key, the 24-byte nonce in the
header, the padded plaintext, and the complete header as AAD. Random nonces and
salts come from the operating-system CSPRNG. A deterministic seeded RNG exists
only in tests and vector generation and is not exposed by product surfaces.

The payload length in the header is the final ciphertext-and-tag length and is
therefore authenticated. Implementations must construct the final header
before sealing.

## 6. Carrier interface and auto-detection

A carrier maps the complete container byte stream to Unicode scalar values.
Bits are consumed most-significant first. A final partial symbol is padded with
zero bits; the authenticated container length makes the padding unambiguous.

Decoders try the four revision 1 carriers and accept only a canonical `SYH4`
header whose carrier field matches the decoder used. A separate read-only v3
detector may look for `ZWS3` with the old alphabets solely to return the
migration error. It must never treat U+200D as removable text.

| id | name | alphabet | bits per scalar |
|---:|---|---|---:|
| `0x01` | zero-width | U+200B, U+2060, U+2062, U+2064 | 2 |
| `0x02` | zero-width compat | U+200B, U+2060 | 1 |
| `0x03` | variation selectors | U+FE00--U+FE0F | 4 |
| `0x04` | Unicode tags | U+E0000--U+E007F | 7 |

For every alphabet, scalar index zero represents the all-zero symbol and the
remaining indices increase numerically.

U+200C is never a raw carrier. It may later participate in a linguistic
carrier only where choosing a valid Persian spelling is the cover operation.
U+200D is ordinary cover text in every revision 1 operation.

An encoder rejects a cover that already contains a scalar from the selected
alphabet. Silent deletion would either corrupt emoji presentation or make
pre-existing text impossible to recover.

## 7. Cost map

Candidate positions are UTF-8 byte offsets between extended grapheme clusters,
never offsets inside one. That rule excludes the interior of emoji ZWJ
sequences and combining sequences by construction.

Each gap receives an integer cost from 0 through 255 or is forbidden. The
revision 1 context rules are applied to the actual neighboring graphemes:

- a gap whose left or right grapheme contains U+200D is forbidden;
- a gap between two Arabic-script letters is forbidden;
- a gap after sentence punctuation has cost 8;
- a gap after other punctuation has cost 16;
- a gap after whitespace has cost 24;
- a boundary between unlike Unicode categories has cost 72;
- a boundary inside a word has cost 224;
- every other eligible boundary has cost 144.

Variation-selector and tag carriers are eligible only after whitespace or
punctuation; their other costs are infinite. Start and end positions are not
candidates. These restrictions are conservative because variation selectors
can change presentation and tag characters participate in some emoji flags.

The rules are intentionally small. Corpus measurements may justify a new
embedding revision; changing costs under revision 1 would make deterministic
vectors lie.

## 8. Capacity and length exposure

Cover length is not a capacity limit. An encoder accepts a non-empty or empty
cover with any content through the 16 MiB hard payload ceiling. It never grows
the cover, refuses a payload, emits a warning, or chunks solely because the
hidden-to-visible ratio is high.

Capacity reports account for the selected mode header, AEAD tag, inner frame,
file-name bytes, 64-byte padding bucket and carrier bit width. They report the
hard payload ceiling and the worst-case carrier expansion at that ceiling.
Transport survival is measured by the probe in section 11; no cover statistic
can establish a transport limit.

This exposes message length and carrier density. That is an accepted threat-
model trade-off: encryption protects the content, while raw Unicode embedding
only hides it from a casual reader. A user pursuing the stronger, optional goal
of concealing payload existence can choose a longer cover, chunking or a
linguistic carrier without changing the default encoder contract.

## 9. Keyed scattered embedding

The encryption key also derives a separate 32-byte embedding seed:

```text
cover_hash = SHA-256(exact UTF-8 cover)
salt       = nonce
info       = "sayeh/v4/embed/rev1" || carrier_id || cover_hash
seed       = HKDF-SHA256(salt, encryption_key, info, 32)
```

A ChaCha20 RNG initialized with `seed` assigns each finite candidate a 64-bit
random value. Its rank is `(cost + random[0..31], random64)`. Candidates are
considered by ascending rank. A candidate adjacent to an already selected gap
is skipped; a second pass permits adjacency until every finite candidate is in
the selected set or no more are needed.

When the carrier stream is longer than the selected set, the encoder places a
run at each selected gap. Every run receives `floor(symbols / gaps)` symbols;
the remainder is assigned to gaps in a keyed random order. With no finite gap,
the entire stream is placed at byte offset zero. The encoder sorts the selected
gaps by byte offset and writes the symbol runs in stream order, so extraction
still reads left to right without a key.

Thus the key chooses the low-cost subset and repeated messages do not reuse a
placement pattern because the nonce changes. Dense output necessarily creates
contiguous carrier runs when the payload has more symbols than eligible gaps;
this length and density exposure is intentional in the default threat model.

## 10. Cleaning

Safe cleaning always removes U+200B, U+2060, U+2062 and U+2064. It never removes
U+200C or U+200D. Variation selectors and tag characters are removed only when
a valid v4 header identifies that alphabet; the encoder's no-pre-existing-
alphabet rule then proves they were inserted by Sayeh.

Aggressive cleaning is a separate operation. It removes Unicode default-
ignorable formatting characters, including ZWNJ, ZWJ, variation selectors and
tags, and must warn that Persian spelling and emoji can change.

## 11. Probe format

The transport probe is visible calibration data, not a covert payload. Version
1 uses this line-oriented form:

```text
SAYEH-PROBE/1
0000|U+200B|A<scalar>Z|A<scalar>Z|A<scalar>Z
...
```

It lists every scalar from all revision 1 alphabets, three times. Analysis
matches the visible index and delimiters, counts exact scalar survival, and
recommends the highest-capacity alphabet for which all three copies of every
required scalar survived. Results are scoped to the named app and path; direct,
forwarded and quoted messages are distinct probe records.

## 12. Limits and errors

- Header parsing performs checked arithmetic and allocates only after lengths
  are validated against recovered bytes.
- Container payloads above 16 MiB are rejected.
- A decompressed frame above 16 MiB plus framing is rejected.
- Argon2 parameters outside the accepted range are rejected before derivation.
- Unknown revisions, modes, carriers, flags and non-zero reserved fields are
  rejected.
- Authenticated-open failures are deliberately indistinguishable.
- `ZWS3` receives a specific refusal explaining that v3 used PBKDF2 and U+200D.

## 13. Test vectors

Files under `vectors/` are part of this specification. `primitive-kats.json`
copies published Argon2id, XChaCha20-Poly1305 and X25519 vectors with source
citations. `carrier-vectors.json` fixes the scalar mappings. Deterministic v4
container vectors are generated with the repository's vector RNG and committed
as `wire-v4.json`; product builds do not compile that RNG.
