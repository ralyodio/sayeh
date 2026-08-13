# Changelog

All notable changes to Sayeh will be documented here. The format follows Keep
a Changelog, and release versions follow Semantic Versioning.

## [Unreleased]

### Added

- Wire v4 specification and cross-implementation JSON vectors.
- Four carrier backends, keyed cost-ranked scattering, transport probes,
  scanning, safe and aggressive cleaning, and disclosed steganalysis.
- Argon2id/XChaCha20-Poly1305 password containers and X25519 contact containers.
- Rust CLI, UniFFI boundary, WASM worker demo, and bilingual Compose Android app.
- Device tests for a 500-byte file in the two-word cover `سلام خوبی؟` and for an
  empty optional message password.

### Changed

- Cover length is no longer an embedding limit. Sayeh does not grow, reject,
  chunk, or warn based on hidden-to-visible ratio.
- U+200D is no longer a carrier and safe stripping preserves emoji ZWJ and
  Persian U+200C.
- The measured Android Argon2id profile is now 64 MiB, 10 passes, and one lane.

### Security

- An empty message password is accepted as an explicit concealment-only mode;
  it does not provide effective content confidentiality.
