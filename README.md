# swarrm-verify — the open Swarrm verifier

**Don't trust us. Verify it yourself.** This repository is the public,
open-source Rust/WASM second implementation for [Swarrm](https://swarrm.ai) evidence
bundles (`evd/bundle/v1`), certificates, and the CWT/COSE-only
`swarrm-b28/v1` Counterparty Assurance profile — the same verifier that runs
client-side at [swarrm.ai/verify](https://swarrm.ai/verify).

A Swarrm evidence bundle is a self-contained file: signed receipts of AI-agent
actions, an RFC 6962 Merkle log with inclusion/consistency proofs, signed
checkpoints, and the public-key history. The verifier checks the base E1
integrity core **offline** — zero network and zero accounts. When a bundle also
carries anchor or timestamp material, it verifies the supplied records and
their cryptographic binding; it does not independently establish public-chain
inclusion or timestamp-authority trust without external evidence.

The B28 verifier checks a nonce-bound exact action, organisation-root passport
chain, current proof-bearing authority, and an action-specific authorization
against a separately pinned local trust pack. The public WASM entry point is
deliberately read-only: it does not durably consume replay state and therefore
cannot authorize execution. The current product release forces every otherwise
favourable candidate to `INDETERMINATE/PASS_NOT_ENABLED` with
`should_execute=false` until its external gates close. No trust score or
assurance mark ships.

## Why this exists

Evidence you can only verify by asking the vendor is not evidence. Swarrm
maintains **two separately implemented verifier paths** (this Rust one and a
Python one shipped in the `swarrm` PyPI package) that run the same shared
golden-fixture suite (`tests/golden/`). Divergence between them is treated as
a spec bug. Agreement is divergence evidence, not independent external
assurance; the cross-check has already caught a real defect (a missing
RFC 6962 leaf prefix).

## Layout

```
verify-rs/     the Rust crate (rlib + wasm cdylib)
  src/         JCS/CBOR, RFC 6962, DSSE/COSE/Ed25519, bundle/cert/B28 checks
  tests/       golden-suite runner
  web/         the static drop-a-bundle page + parity test
tests/golden/  shared fixtures: valid + adversarial bundles, expected verdicts
SPEC/          the wire formats (receipt-v1, log-v1, bundle-v1, anchor-v1, …)
fuzz/          bounded libFuzzer targets seeded from the hostile/golden corpus
security/      H22 control boundary and machine-readable OpenVEX statement
```

## Verify a bundle

```bash
cd verify-rs
rustup toolchain install 1.90.0 --component rustfmt,clippy --target wasm32-unknown-unknown
cargo +1.90.0 test --locked # shared valid and hostile suites must agree
cargo +1.90.0 clippy --locked --all-targets -- -D warnings
git diff --exit-code -- Cargo.lock
```

The golden suite includes adversarial fixtures — tampered payloads, forged
anchors, post-revocation forgeries, rewritten history — and asserts each is
rejected with the right error, not just "invalid".

## Build the browser verifier (WASM)

```bash
cd verify-rs
tool_bin=$(bash scripts/install-canonical-wasm-tools.sh /tmp/swarrm-wasm-tools)
PATH="$tool_bin:$PATH" bash scripts/build-canonical-wasm.sh web
shasum -a 256 pkg/swarrm_verify_bg.wasm
```

Compare the hash against `INTEGRITY.txt` on swarrm.ai. Bit-exact reproduction
requires the same toolchain (all tool versions are recorded in the integrity
file); regardless of toolchain, this source is what to audit — the
page at swarrm.ai/verify loads no external code and never uploads your file.
For byte reproduction, follow the fully checksummed toolchain procedure in
[`verify-rs/README.md`](verify-rs/README.md); CI also asserts that `Cargo.lock`
does not change.

Tagged releases use the same pinned rebuild, then publish checksummed source,
browser and Node archives, a validated CycloneDX SBOM, a keyless Sigstore
signature over `SHA256SUMS`, and GitHub-hosted SLSA provenance and SBOM
attestations. See [`security/H22.md`](security/H22.md) for the exact control
boundary and the gates that still require an independent human.

## What verification proves (and doesn't)

See `SPEC/log-v1.md` for evidence levels E0–E3 and `SPEC/bundle-v1.md` for
exact verdict semantics. In short: the offline E1 result means the receipts are
signed by keys witnessed in the log and the log is internally consistent.
Anchor and timestamp records can strengthen that result only when their
external trust assumptions are supplied and validated. Verification does not
prove the *payloads* are true — it proves the recorded actions have not been
altered since they were written.

It also cannot establish global or latest completeness from a producer-chosen
export. An internally valid bundle, key log, or authority-state checkpoint may
still be an older consistent prefix. Before relying on freshness, compare an
independently obtained later checkpoint or signed high-water. B28 similarly
proves identity and authority only at its verified checkpoint; it does not
predict future behaviour, certify an action outcome, or evaluate Node, source,
coverage, history, or post-action evidence readiness in v1.

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party attributions in
[NOTICE](NOTICE). The specs in `SPEC/` are Apache-2.0 as well: implement them,
port them, embed them.
