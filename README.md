# swarrm-verify — the open verifier for Swarrm evidence bundles

**Don't trust us. Verify it yourself.** This repository is the independent,
open-source verifier for [Swarrm](https://swarrm.ai) evidence bundles
(`evd/bundle/v1`) — the same verifier that runs client-side at
[swarrm.ai/verify](https://swarrm.ai/verify).

A Swarrm evidence bundle is a self-contained file: signed receipts of AI-agent
actions, an RFC 6962 Merkle log with inclusion/consistency proofs, signed
checkpoints, the public-key history, and (at evidence level E2) a public
blockchain anchor plus an RFC 3161 timestamp. This verifier checks all of it
**offline** — zero network, zero accounts, zero trust in Swarrm.

## Why this exists

Evidence you can only verify by asking the vendor is not evidence. Swarrm
maintains **two independent verifier implementations** (this Rust one and a
Python one shipped in the `swarrm` PyPI package) that run the same shared
golden-fixture suite (`tests/golden/`). Divergence between them is treated as
a spec bug — this cross-check has already caught a real one (a missing
RFC 6962 leaf prefix).

## Layout

```
verify-rs/     the Rust crate (rlib + wasm cdylib)
  src/         JCS canonicalization, RFC 6962 Merkle, DSSE/Ed25519, bundle walk
  tests/       golden-suite runner
  web/         the static drop-a-bundle page + parity test
tests/golden/  shared fixtures: valid + adversarial bundles, expected verdicts
SPEC/          the wire formats (receipt-v1, log-v1, bundle-v1, anchor-v1, …)
```

## Verify a bundle

```bash
cd verify-rs
cargo test                 # runs the shared golden suite — all fixtures must agree
```

The golden suite includes adversarial fixtures — tampered payloads, forged
anchors, post-revocation forgeries, rewritten history — and asserts each is
rejected with the right error, not just "invalid".

## Build the browser verifier (WASM)

```bash
cd verify-rs
wasm-pack build --release --target web --features wasm
shasum -a 256 pkg/swarrm_verify_bg.wasm
```

Compare the hash against `INTEGRITY.txt` on swarrm.ai. Bit-exact reproduction
requires the same toolchain (rustc + wasm-pack versions are recorded in the
integrity file); regardless of toolchain, this source is what to audit — the
page at swarrm.ai/verify loads no external code and never uploads your file.

## What verification proves (and doesn't)

See `SPEC/log-v1.md` for evidence levels E0–E3 and `SPEC/bundle-v1.md` for
exact verdict semantics. In short: VERIFIED means the receipts are signed by
the keys witnessed in the log, the log is internally consistent, and (E2) its
checkpoint existed no later than the anchored/timestamped instant. It does not
prove the *payloads* are true — it proves the record of actions has not been
altered since it was written.

## License

Apache-2.0 — see [LICENSE](LICENSE). Third-party attributions in
[NOTICE](NOTICE). The specs in `SPEC/` are Apache-2.0 as well: implement them,
port them, embed them.
