<!-- Apache-2.0 -->
# swarrm-verify (Rust) — the second, independent verifier

A from-scratch Rust implementation of `evd/bundle/v1` verification. It shares
NO code with the Python verifier — that is the point. Two independent
implementations agreeing on the shared golden suite (`../tests/golden/`) is
real evidence that the wire format is unambiguous, and it hardens the spec:
the leaf-hash prefix bug (RFC 6962 `0x00`) was caught precisely because the
two implementations disagreed on one fixture.

```bash
cargo test                 # runs ../tests/golden/ — must agree with expected.json
```

## Browser (WASM) verifier

```bash
cargo install wasm-pack     # one-time; release artifact uses 0.15.0
wasm-pack build --target web --features wasm
python3 -m http.server      # from verify-rs/; open http://localhost:8000/web/
```

`web/index.html` is a static, client-side-only file-drop page: the bundle
never leaves the browser. The native crate builds without `wasm-bindgen`
(it is an optional dependency behind the `wasm` feature), so `cargo test`
and CI stay lean.

## Coverage

Implements: key-log replay (genesis self-sig, rotation continuity,
revocation, dense `_system` sequence), JWKS-vs-log agreement, DSSE/PAE +
Ed25519, RFC 8785 (JCS) for checkpoint bodies and JWKs, RFC 9162 inclusion
+ consistency, revocation-time checks, and anchor/timestamp-record binding. The
library also verifies RFC 3161 tokens offline against a caller-supplied
certificate chain and verifies `evd/disclosure/v1` packages against an
already-verified bundle. Networked `--live` chain reads remain outside this
Rust/WASM verifier; externally grounded trust must be supplied out of band.
