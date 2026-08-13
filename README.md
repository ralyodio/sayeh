# Sayeh

Sayeh puts an encrypted text or small file inside ordinary chat text. The chat
application remains the transport: Sayeh has no account, relay, server,
telemetry, or crash reporting.

This repository is a pre-release v4 implementation. Its wire format is
documented in [SPEC.md](SPEC.md), and the independent data vectors live under
[`vectors/`](vectors/). The older Go and Android v3 implementations remain in
[`legacy/v3/`](legacy/v3/) while v4 stabilises.

## What is protected

Password messages use Argon2id and XChaCha20-Poly1305. Contact messages use a
fresh X25519 ephemeral key, the verified sender identity key, HKDF-SHA256, and
XChaCha20-Poly1305. The complete public header is authenticated. Encryption is
the layer that protects the content.

The password field may be left empty. This is a deliberate concealment-only
mode: the container remains authenticated, but an empty public password gives
no effective confidentiality to someone who recognizes Sayeh. Use a real
password or a verified contact key when content secrecy matters. The encrypted
contact vault still requires a non-empty password.

Unicode embedding has a narrower job: a casual reader sees the supplied cover
instead of the encrypted bytes. It does **not** hide the existence of a payload
from someone who checks message length, carrier density, or known carrier code
points. That trade-off is accepted by the default mode. A short cover such as
`سلام خوبی؟` may carry 500 bytes or more; Sayeh does not grow the cover, reject
the input, or warn about its hidden-to-visible ratio.

Concealing existence is a separate, stronger goal. Keyed scattering and the
cover-derived cost map are available, and users may voluntarily choose a longer
cover, chunking, or—when implemented—linguistic carriers. None of those choices
is forced on the default path.

## Carrier safety

The default alphabet is U+200B, U+2060, U+2062, and U+2064. U+200C is never a
raw data carrier because it is meaningful Persian ZWNJ. U+200D is never a data
carrier because it joins emoji. Safe stripping preserves both. Aggressive
stripping is explicitly destructive and may change Persian spelling and emoji.

Four v4 carrier backends are implemented:

| Carrier | Bits per scalar | Intended use |
|---|---:|---|
| Zero-width | 2 | Default |
| Zero-width compat | 1 | Wider transport survival |
| Variation selectors | 4 | Higher density where measured safe |
| Unicode tags | 7 | Highest density where measured safe |

Do not assume a chat application preserves any of them. Run `sayeh probe`, send
the generated text through the exact path you intend to use, and analyse the
returned copy.

## Measured detectability

The committed NPS Chat experiment used 10,567 posts and 230,623 Unicode
scalars. None of the four carrier alphabets appeared in that baseline. An exact
known-codepoint detector found 100% of samples at 0.1%, 0.5%, and 1.0% embedding
rates. Sayeh's disclosed heuristic found 0% at 0.1% and 100% at 0.5% and 1.0%.
Scattering held the mean longest run to one in those low-rate samples; it did
not defeat exact carrier detection.

These numbers describe one corpus, one implementation and two disclosed
detectors. They are not a claim of undetectability. The full method and raw
results are in
[`benchmarks/steganalysis-nps-chat.md`](benchmarks/steganalysis-nps-chat.md) and
[`benchmarks/steganalysis-nps-chat.json`](benchmarks/steganalysis-nps-chat.json).

## Command line

The workspace declares Rust 1.85 as its MSRV.

```console
cargo build --release -p sayeh-cli
sayeh hide --cover "سلام خوبی؟" --secret "متن محرمانه"
sayeh reveal
sayeh scan
sayeh strip
sayeh analyse
sayeh probe generate
sayeh capacity --carrier zero-width
```

Commands accept files and standard input; run `sayeh <command> --help` for the
complete interface. Password prompts use the terminal rather than command-line
arguments unless explicitly supplied for automation.

## Repository layout

- `sayeh-core`: sync, I/O-free carrier, container, crypto, contact and analysis
  library; unsafe code is forbidden.
- `sayeh-cli`: command-line product, encrypted contact store and fingerprints.
- `sayeh-ffi`: UniFFI bindings used by Android.
- `sayeh-wasm`: wasm-bindgen interface for the local browser demo.
- `android`: Kotlin and Compose application over the Rust library.
- `demo`: browser UI running crypto in a Web Worker.
- `xtask`: vector generation and corpus measurement.
- `fuzz`: container and carrier decoder targets with seed inputs.

The Android application currently exposes the password workflow, scanning and
safe cleaning. Contact-mode primitives and the CLI contact store are present,
but the Android contact-management UI is not yet complete.

The Android Argon2id profile was calibrated on the connected Xiaomi
`23090RA98G` (ARM64, Android 13). With `m=65,536 KiB`, `t=10`, `p=1`, two final
instrumented opens measured 598 ms and 625 ms. This is one device measurement,
not a performance claim for every phone.

Build an ARM64 debug APK after generating the UniFFI Kotlin binding and native
library:

```console
rustup target add aarch64-linux-android
cargo build -p sayeh-ffi --target aarch64-linux-android --release
cd android
./gradlew assembleDebug
```

The Android build requires SDK 36.1, NDK 27 or newer, Java 17 or newer, and an
Android-target linker configured for Cargo. The checked-in Gradle wrapper pins
the Java-side toolchain. Debug APKs use Android's debug certificate; a public
release will use a separately protected release key.

## Build checks

```console
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo xtask vectors
git diff --exit-code -- vectors
```

See [SECURITY.md](SECURITY.md) before relying on Sayeh. Reports that could put a
user at risk should be sent privately using the address in that file rather
than opened as a public issue.

## Licence

Sayeh is available under either the Apache License 2.0 or the MIT licence, at
your option.
