<!-- Apache-2.0 -->
# swarrm-verify (Rust) — the second implementation

A from-scratch Rust implementation of `evd/bundle/v1`, certificate and
`swarrm-b28/v1` verification. It shares no verifier code with the Python
implementation. Agreement on the shared golden and hostile suites
(`../tests/golden/`) is evidence against implementation drift; it is not an
external trust root or security review. The split has hardened the spec:
the leaf-hash prefix bug (RFC 6962 `0x00`) was caught precisely because the
two implementations disagreed on one fixture.

The committed dependency graph is authoritative. The native verification gate
uses Rust 1.90.0 and refuses to update it:

```bash
rustup toolchain install 1.90.0 --component rustfmt,clippy --target wasm32-unknown-unknown
cargo +1.90.0 test --locked                 # runs ../tests/golden/
cargo +1.90.0 clippy --locked --all-targets -- -D warnings
git diff --exit-code -- Cargo.lock
```

## Browser (WASM) verifier

The committed browser artifact is reproduced in CI on Linux x86-64 with Rust
1.90.0 and the official wasm-pack 0.15.0 release binary. Do not replace that
binary with a floating `cargo install`:

```bash
archive=wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz
curl --fail --location --proto '=https' --tlsv1.2 -o "$archive" \
  "https://github.com/wasm-bindgen/wasm-pack/releases/download/v0.15.0/$archive"
echo "c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a  $archive" \
  | sha256sum --check -
tar -xzf "$archive"
./wasm-pack-v0.15.0-x86_64-unknown-linux-musl/wasm-pack \
  build --target web --features wasm --locked
git diff --exit-code -- Cargo.lock
python3 -m http.server      # from verify-rs/; open http://localhost:8000/web/
```

`web/index.html` is a static, client-side-only file-drop page: a chosen bundle
is read locally and creates no bundle-related network request. The native crate builds without `wasm-bindgen`
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

The B28 export accepts one deterministic-CBOR exchange, one local verification
context, canonical trust-pack bytes and that pack's separately configured
SHA-256 pin. It rejects JWT/JWS, algorithm negotiation, embedded keys and
network discovery. The `1.1.0b1` profile converts every otherwise favourable
candidate to `INDETERMINATE/PASS_DISABLED_BETA` with
`should_execute=false`; the read-only WASM function does not consume replay
state or authorize execution.

Every bundle, certificate, and B28 result is bounded by the evidence supplied
to the local verifier. Internal consistency is not proof that a presented log
or authority checkpoint is globally latest or complete; compare an
independently obtained later checkpoint or high-water before relying on that
claim.
