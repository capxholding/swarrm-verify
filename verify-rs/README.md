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
1.90.0, wasm-pack 0.15.0, wasm-bindgen CLI 0.2.126 and Binaryen 117. The helper
downloads each official release by a repository-pinned SHA-256; no tool is
compiled from a floating Cargo dependency graph:

```bash
tool_bin=$(bash scripts/install-canonical-wasm-tools.sh /tmp/swarrm-wasm-tools)
PATH="$tool_bin:$PATH" bash scripts/build-canonical-wasm.sh web
git diff --exit-code -- Cargo.lock
python3 -m http.server      # from verify-rs/; open http://localhost:8000/web/
```

`web/index.html` is a static, client-side-only file-drop page: a chosen bundle
is read locally and creates no bundle-related network request. The native crate builds without `wasm-bindgen`
(it is an optional dependency behind the `wasm` feature), so `cargo test`
and CI stay lean.

The build helper remaps the absolute source and Cargo cache paths to stable
virtual roots before compilation. This is required because Rust panic metadata
otherwise makes the optimized module depend on the builder's home and checkout
paths even when every compiler and dependency version is identical.

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
network discovery. The launched profile converts every otherwise favourable
candidate to `INDETERMINATE/PASS_NOT_ENABLED` with
`should_execute=false`; the read-only WASM function does not consume replay
state or authorize execution.

Every bundle, certificate, and B28 result is bounded by the evidence supplied
to the local verifier. Internal consistency is not proof that a presented log
or authority checkpoint is globally latest or complete; compare an
independently obtained later checkpoint or high-water before relying on that
claim.
