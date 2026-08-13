# Security policy and threat model

Sayeh protects message content with authenticated encryption and places the
ciphertext inside user-supplied cover text. Those are separate claims.

## Security goals

- A reader without the password or recipient key should not learn plaintext,
  file bytes, or authenticated metadata.
- Editing the header, nonce, salt, KDF parameters or ciphertext must make the
  message fail with the same public open error.
- Safe carrier removal must preserve Persian U+200C and emoji U+200D.
- Contact-mode counters let a stateful receiver reject a message it has already
  accepted.

The implementation uses Argon2id, XChaCha20-Poly1305, X25519 and HKDF-SHA256
from maintained Rust crates. This repository does not implement cryptographic
primitives.

## Accepted exposure

Default Unicode embedding does not attempt to hide the existence of a payload
from an observer who examines raw text. Message length, carrier density and the
presence of known carrier code points are visible. Sayeh deliberately permits a
large secret in a short cover without refusal, warning, cover growth or forced
chunking. Encryption still protects the content.

Keyed placement and the cost map reduce obvious clustering when the cover has
enough eligible gaps. They cannot remove the carrier characters and dense
payloads necessarily form runs. Natural-ratio covers and future linguistic
carriers are opt-in measures for a stronger concealment goal, not properties of
the default mode.

## Measured carrier limits

The committed NPS Chat measurement contained 230,623 Unicode scalars and zero
occurrences of every v4 carrier alphabet. A detector that only checks for a
known carrier code point identified 100 of 100 embedded samples at every tested
rate: 0.1%, 0.5%, and 1.0%. Sayeh's disclosed statistical heuristic identified
0 of 100 at 0.1%, then 100 of 100 at both 0.5% and 1.0%. All four alphabets had
the same presence-detection outcome.

The experiment is reproducible through `cargo xtask analyse-corpus`; its corpus
hash, method and results are committed under `benchmarks/`. It is evidence
against an undetectability claim, not a bound on a different adversary.

## Out of scope

Sayeh does not protect against:

- a compromised endpoint, keylogger, malicious keyboard, screen capture or
  forensic extraction of an unlocked device;
- coercion, traffic analysis, screenshots, notification history or a chat
  provider retaining the raw message;
- password guessing when the password has low entropy;
- any content secrecy when the optional message password is left empty;
- first-contact impersonation when fingerprints were not verified out of band;
- deletion, reordering or Unicode normalisation by the transport;
- a recipient copying plaintext before expiry;
- denial of service or an observer learning that a message contains carriers.

There is no duress slot in wire revision 1. Concealment alone is not deniability.
The current contact construction also lacks the planned ratchet, so later
compromise of a static identity key may expose recorded contact messages.

## Operational guidance

Verify contact fingerprints in person or through an already authenticated
channel. Measure each app and path with the transport probe; direct messages,
forwards, quotes and notification previews can behave differently. Treat a
failed probe as a transport limitation, not something to bypass.

Use safe stripping unless changing Persian text and emoji is explicitly
acceptable. Keep the local contact store and backups protected by a strong,
unique passphrase. Android screenshots are blocked by `FLAG_SECURE`, but that is
only a UI control and not a defence against a compromised device.

## Reporting a vulnerability

The project has not been published and no public security mailbox exists yet.
Until one is announced, report vulnerabilities privately to the repository
owner and include the affected revision, reproduction input and expected impact.
Do not attach real user secrets or publish an exploit before a fix is available.
