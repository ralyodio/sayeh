# Browser demo

The demo invokes `sayeh-core` through `sayeh-wasm`. Each operation gets a fresh
Web Worker; the worker is terminated when it returns so Argon2 never blocks the
page's main thread and its WebAssembly memory is not retained between jobs.

Build the package and serve this directory over HTTP:

```console
wasm-pack build sayeh-wasm --target web --release --out-dir ../demo/pkg
python -m http.server --directory demo 8080
```

The release profile skips wasm-pack's bundled `wasm-opt`: version 0.13.1 ships a
Binaryen validator that rejects the bulk-memory instructions emitted by the
declared Rust 1.97 toolchain. Rust's release profile still applies LTO and one
codegen unit. Re-enable `wasm-opt` after its bundled validator accepts that
target output.

Opening `index.html` directly does not work because browsers restrict module
workers loaded from `file:` URLs.

The test-cover button exists only to exercise round trips. The default encoder
also accepts a short cover with a large payload; it does not grow the cover or
enforce a hidden-to-visible ratio.
