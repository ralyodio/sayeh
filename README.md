# Sayeh

*One message, hidden inside another.*

[فارسی](README.fa.md) · [Wire format](SPEC.md) · [Security](SECURITY.md)

---

Send an ordinary message — "hey, you around?" — and let it quietly carry a
second, private one. Anyone watching the chat sees only "hey, you around?".
The person you're writing to pulls the real message back out.

That's Sayeh: it weaves your data into ordinary text with invisible Unicode
characters. The visible text stays intact and readable; the payload hides
between the letters.

Better still, put a **password** on the hidden message. Now it rides through
any messenger, and however much that company stores and reads your chats, this
one it can't open. Argon2id and XChaCha20-Poly1305 underneath — the same
encryption you'd use for data that matters. Without the password, all it sees
is scrambled bytes.

The password is optional; for a throwaway message it works without one. But when
the content matters, the password is what protects it.

## Try it

```bash
cargo build --release -p sayeh-cli

sayeh hide --cover "hey, you around?" --secret "9pm, back door" --output out.txt
sayeh scan   --input out.txt      # see what's inside, without opening it
sayeh reveal --input out.txt      # open it
```

Open `out.txt` and it reads "hey, you around?" — with a few hundred invisible
characters sitting between the letters, unseen. `hide` asks for the password at
the terminal and never echoes it.

Don't want to install anything? [`demo/`](demo/) is a browser build that runs
entirely in the page — no server, nothing leaving the tab.

## It doesn't fight Persian

Most tools like this mangle Persian text. Sayeh deliberately never touches two
characters: **`U+200C`**, the ZWNJ (نیم‌فاصله), so «می‌روم» and «کتاب‌ها» stay
intact; and **`U+200D`**, the emoji joiner, so a family emoji doesn't fall apart
into separate people. Safe stripping preserves both.

The default rides on four other invisible characters, with three denser carriers
available when you need the room.

## Two ways to lock a message

**With a password.** A phrase you and the other side both know. Great for a
one-off.

**With a contact key.** Exchange public keys once, verify the fingerprint in
person, and after that no shared password is needed — X25519 and HKDF
underneath, built for an ongoing conversation. Complete on the command line; the
Android UI for it is on the way.

## Commands

| Command | What it does |
|---|---|
| `hide` / `reveal` | hide a message and open it |
| `scan` | report what a text is carrying, without opening it |
| `strip` | remove invisible carrier characters from a text |
| `analyse` | measure how easily a payload can be detected |
| `probe` | generate a test text to see which messengers keep the characters alive |
| `capacity` | how much room a given secret needs |
| `identity` / `contact` | your own key and the contact store |

Run `sayeh <command> --help` for the details.

## Android and browser

The Android app is Kotlin and Jetpack Compose over this same Rust core — the
crypto isn't reimplemented in the UI. Argon2id key derivation was measured on a
real phone (Xiaomi, ARM64, Android 13): about 600 ms. The browser build runs
everything through wasm in the page.

## From source

```bash
cargo test  --workspace --all-features
cargo build --release -p sayeh-cli
```

MSRV is Rust 1.85. Building the Android APK:

```bash
rustup target add aarch64-linux-android
cargo build -p sayeh-ffi --target aarch64-linux-android --release
cd android && ./gradlew assembleDebug
```

Needs SDK 36.1, NDK 27+, Java 17+, and a Cargo linker for the Android target.

## Where this stands

A pre-release of the v4 wire format, documented in [SPEC.md](SPEC.md) with
independent test vectors in [`vectors/`](vectors/) so any other implementation
can check itself against them. The older v3 code (Go and Android) is kept in
[`legacy/v3/`](legacy/v3/).

Sayeh makes a message invisible, not undetectable: someone examining the text
closely can tell something is embedded. What is and isn't protected is written
out honestly in [SECURITY.md](SECURITY.md).

## Licence

Your choice of Apache-2.0 or MIT.
