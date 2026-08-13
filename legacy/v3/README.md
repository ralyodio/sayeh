# Sayeh v3

Zero-width steganography that hides a message inside ordinary text, with real
cryptography behind it. Two implementations — a Go command line tool and a
native Android app — that speak the **same wire format**, so a message hidden
on the desktop opens on the phone and back again.

No external dependencies anywhere: Go standard library only, Android framework
only. No Gradle, no Maven, no network.

---

## شروع سریع

```powershell
# ساخت نسخه دسکتاپ
cd C:\Users\will\Desktop\Sayeh\go
go build -o ..\build\sayeh.exe .

# تست کامل رمزنگاری و فرمت
..\build\sayeh.exe selftest

# اجرای منوی تعاملی
..\build\sayeh.exe
```

```powershell
# ساخت APK اندروید (بدون Gradle)
cd C:\Users\will\Desktop\Sayeh\android
.\build.ps1

# نصب روی گوشی وصل‌شده
.\build.ps1 -Install
```

خروجی: `build\Sayeh.apk`

---

## What changed since v2

| | v2 | v3 |
|---|---|---|
| Key derivation | `SHA-256(password)` | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt |
| Header integrity | none | the whole header is GCM additional authenticated data |
| Message length | visible in the payload size | padded to 64-byte buckets |
| Payload size | 8 invisible chars per byte | 4 per byte, plus DEFLATE — see below |
| Persian text | ZWNJ collision risk | U+200C is never used as a carrier |
| Password entry | echoed on screen | no echo (kernel32 / stty) |
| Detection | none | `scan` reports what a text carries without decrypting it |
| Verification | none | `selftest` with RFC 7914 known-answer vectors |
| Platforms | CLI | CLI + Android, byte-compatible |

Measured on this machine, hiding the same secret with and without the v3
pipeline:

| secret | v2 carriers | v3 carriers | |
|---|---|---|---|
| 124 bytes of Persian | 1,064 | 560 | 1.9x smaller — the codec does the work; short non-repetitive text barely compresses |
| 1,224 bytes of English | 9,864 | 464 | 21x smaller — DEFLATE has something to chew on |

So: always about 2x from the 2-bits-per-character codec, and a lot more once
the message is long enough to compress.

The `SHA-256(password)` key derivation in v2 was the weak point: a single fast
hash can be guessed billions of times per second on a GPU. PBKDF2 at 600k
iterations makes each guess roughly six orders of magnitude more expensive.
That is why v3 **refuses** to open v2 `STEGO_ENC:` payloads — carrying them
forward would carry the weakness forward with them. Unencrypted v1/v2 payloads
(`STEGO_V1:`, `STEGO_RAW:`) still decode fine.

---

## Command line

```
sayeh                 interactive menu
sayeh hide    [flags] hide a secret inside a cover text
sayeh reveal  [flags] extract a hidden secret
sayeh scan    [flags] report what a text carries, without decrypting
sayeh strip   [flags] remove every invisible character
sayeh selftest        verify the crypto and the wire format
```

```bash
sayeh hide -coverfile cover.txt -secretfile secret.txt -passfile pw.txt -o out.txt
```

```bash
sayeh reveal -infile out.txt -passfile pw.txt
```

Password sources, in order of preference: `-passfile`, the
`SAYEH_PASS` environment variable, the interactive no-echo prompt, and
finally `-pass` — which is discouraged, because it lands in your shell history
and in the process list.

### Moving payloads around

Zero-width characters are fragile. Terminals, chat clients, web forms and
"smart" text fields strip them regularly. When a payload has to survive a trip
through another program, move it as a **file** (`-o` / `-infile`) rather than
by copy-paste. The `b2` codec (`-codec b2`) is twice as large but survives more
aggressive sanitizers than the default `b4`.

---

## Android app

* Two modes, Hide and Reveal, sharing one screen
* Scan tells you whether a text carries anything before you try to open it
* Clean strips every invisible character out of a text
* Share text from any app straight into Sayeh (`ACTION_SEND`)
* Copy marks the clip sensitive on Android 13+, so it stays out of the
  clipboard preview
* `FLAG_SECURE` keeps secrets out of screenshots, screen recordings and the
  recent-apps thumbnail
* **Zero permissions.** No network access, no storage access, no telemetry.
  Check for yourself: `aapt2 dump badging Sayeh.apk` lists no
  `uses-permission` at all.
* Backups and device-to-device transfer are disabled for the app's data

### Building

`android/build.ps1` drives the SDK tools directly:

```
aapt2 compile -> aapt2 link -> javac -> d8 -> zip -> zipalign -> apksigner
```

There is nothing to download, because the app uses only `android.*`, `java.*`
and `javax.crypto.*`. Requirements: a JDK, Android SDK build-tools 35 and
platform `android-35`.

The APK is signed with a **self-signed local key** at
`android/keystore/sayeh.jks` (store and key password: `sayeh-keystore`),
created automatically on the first build. Keep that file: Android will only
accept an update to an installed app if it is signed with the same key. This
key is fine for personal use and sideloading; it is not a Play Store release
key.

---

## Security notes

**What this protects against.** Someone reading over your shoulder, casual
inspection of a message, an automated filter looking at visible text, and —
with a password — anyone who obtains the payload without the password. The
encryption is AES-256-GCM with a properly stretched key; it is the same
construction you would use for real data at rest.

**What it does not protect against.** Steganography is about *concealment*,
not deniability under scrutiny. Anyone who suspects the trick can detect the
payload instantly — this tool's own `scan` command does exactly that in
milliseconds. The invisible characters are visible to any hex dump. Treat the
concealment as a way to avoid attention, never as a second layer of security.
The encryption is what actually protects the content.

**Length.** Padding hides the message size only in 64-byte buckets. A very
long message is still recognisably long.

**Passwords.** PBKDF2 at 600k iterations buys roughly a factor of a million
against offline guessing, but it cannot save a guessable password. A short
password with a strong KDF is still a short password.

**Metadata.** The header is deliberately not hidden: version, flags, KDF id,
iteration count, salt and nonce are all readable before decryption. They have
to be, to decrypt at all. They reveal *that* a message exists and roughly how
big it is, never what it says.

---

## Layout

```
Sayeh/
  SPEC.md                     the wire format both sides implement
  go/                         command line tool (Go standard library only)
    codec.go                  zero-width codecs
    format.go                 container v3
    crypto.go                 PBKDF2 + AES-256-GCM
    stego.go                  hide / scan / unseal
    ui.go  main.go            CLI and interactive menu
    term_windows.go           no-echo password entry (kernel32)
    term_unix.go              no-echo password entry (stty)
    selftest.go               14 checks, including RFC 7914 vectors
  android/
    java/ir/sayeh/stego/
      ZwCodec.java            mirrors codec.go
      Format.java             mirrors format.go
      Crypto.java             mirrors crypto.go
      Stego.java              mirrors stego.go
      MainActivity.java       the UI (the only file that touches android.*)
      SelfTest.java           desktop-runnable verification of the above
    build.ps1                 Gradle-free APK pipeline
  build/                      binaries and the APK
```

Everything except `MainActivity` uses only `java.*` and `javax.*`, so the exact
code that ships in the APK can be compiled and tested on a desktop JVM:

```powershell
javac -encoding UTF-8 -d build\jvm-classes android\java\com\sayeh\stego\*.java
java -cp build\jvm-classes ir.sayeh.stego.SelfTest
```

Both self-tests pin the same cross-implementation vector, so if Go and Java
ever drift apart on key derivation or on the container layout, they both fail
loudly instead of silently producing payloads the other side cannot open.
