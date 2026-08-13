# Interoperability vectors

These JSON files are data, not Rust fixtures hidden inside test functions.
Implementations should load them and compare bytes exactly.

- `primitive-kats.json` contains published primitive known-answer tests.
- `carrier-vectors.json` fixes bit order and Unicode scalar mappings.
- `wire-v4.json` is generated after the encoder exists and pins complete
  password and contact containers plus their stego text.

Hex strings are lowercase and contain no separators. Code points are uppercase
`U+` notation. The source URLs in the primitive file are archival references,
not network dependencies of the test suite.

