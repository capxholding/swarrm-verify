# swarrm-verify — the open Swarrm verifier

**Don't trust us. Verify it yourself.** This repository is the public,
Apache-2.0 Rust/WASM second implementation for [Swarrm](https://swarrm.ai)
evidence bundles (`evd/bundle/v1`), certificates, selective disclosures, and
the CWT/COSE-only `swarrm-b28/v1` Counterparty Assurance profile — the same
compiled verifier that runs client-side at
[swarrm.ai/verify](https://swarrm.ai/verify).

[Verify a bundle](https://swarrm.ai/verify) ·
[Download the sample](https://swarrm.ai/samples/sample_bundle.json) ·
[Read the specifications](SPEC/) ·
[Check the release digests](https://swarrm.ai/INTEGRITY.txt) ·
[Review the security model](security/H22.md)

A Swarrm evidence bundle is a self-contained file: signed receipts of AI-agent
actions, an RFC 6962 Merkle log with inclusion/consistency proofs, signed
checkpoints, and the public-key history. The verifier checks the base E1
integrity core **offline** — zero network and zero accounts.

## Verify a bundle now

1. Download the [public sample bundle](https://swarrm.ai/samples/sample_bundle.json).
2. Open the [browser verifier](https://swarrm.ai/verify).
3. Drop the bundle onto the page.

The verifier reads the file locally, checks the signed evidence and presented
authenticated history, and returns a verdict with a reproducible bundle digest.
The file stays in your browser. Use the built-in tamper control to change one
byte and see the same evidence fail verification.

## Run the browser verifier from this repository

The checked-in browser artifact is ready to run without a build step:

```bash
git clone https://github.com/capxholding/swarrm-verify.git
cd swarrm-verify/verify-rs
python3 -m http.server 8000
```

Open [http://localhost:8000/web/](http://localhost:8000/web/) and choose a
bundle or certificate. The page hardcodes the release digests of both the
JavaScript module and the WASM binary and refuses to execute either unless the
served bytes match.

## What it verifies

| Surface | Verification performed |
|---|---|
| Evidence bundles | Ed25519/DSSE receipt signatures, key lifecycle, JWKS agreement, RFC 6962/9162 Merkle inclusion and consistency, signed checkpoints, and export-manifest state |
| Carried anchor and timestamp material | Anchor-record binding and RFC 3161 timestamp cryptography against trust material supplied by the relying party; live Base confirmation is composed by the report path |
| Certificates | Deterministic-CBOR cores and selective views, identifiers, manifests, embedded bundle and evidence-layer binding, and cross-field recomputation |
| Selective disclosure | Disclosed fields and commitments back to an already verified bundle |
| Counterparty Assurance | Organization-rooted identity, live-key control, current authority, exact action, challenge, authorization, and transcript binding under a pinned local trust pack |
| Hostile inputs | Tampered payloads, forged anchors, rewritten history, post-revocation signatures, malformed encodings, replay conflicts, and bounded-resource cases |

## Evidence levels

Evidence levels are cumulative and describe the basis established for a
recorded action (exact semantics in [`SPEC/log-v1.md`](SPEC/log-v1.md) and
[`SPEC/bundle-v1.md`](SPEC/bundle-v1.md)):

| Level | Basis |
|---|---|
| **E0** | A receipt is present, intact, and signed. |
| **E1** | E0 plus inclusion and consistency in the presented signed, authenticated history. |
| **E2** | E1 plus the same covering checkpoint confirmed live on Base or Base Sepolia and an RFC 3161 timestamp chain terminating at a root selected by the relying party. |
| **E3** | E2 plus matching signatures from the tenant issuer and an active registered-recorder key selected by the relying party. |

The browser verifier establishes the local E1 basis. Rust also exposes trusted
timestamp and recorder-attestation facts. The separate
[Swarrm Python CLI and Evidence Report path](https://pypi.org/project/swarrm/)
performs the live Base or Base Sepolia confirmation and composes those facts to
establish E2 and E3.

## Counterparty Assurance

Counterparty Assurance verifies a nonce-bound presentation before two agents
interact. It checks the presenting agent's organization-rooted passport,
control of its live key, current mandate, exact action authority, challenge,
and transcript binding. The result is a machine-verifiable assurance vector,
not a numerical trust score.

The public WASM entry point is deliberately read-only: it does not durably
consume replay state and therefore cannot authorize execution. The current
product release forces every otherwise favourable candidate to
`INDETERMINATE/PASS_NOT_ENABLED` with `should_execute=false` until its
external gates close. Node, source, coverage, history, and post-action
evidence readiness are outside the v1 vector.

## Two implementations, one evidence model

Swarrm maintains **two separately implemented verifier paths** (this Rust one
and a Python one shipped in the `swarrm` PyPI package) that run the same shared
golden-fixture suite ([`tests/golden/`](tests/golden/)). Divergence between
them is treated as a spec bug. Agreement is divergence evidence, not
independent external assurance; the cross-check has already caught a real
defect (a missing RFC 6962 leaf-domain prefix).

## Test the Rust implementation

The native verification gate uses Rust 1.90.0 and the committed dependency
graph:

```bash
cd verify-rs
rustup toolchain install 1.90.0 --component rustfmt,clippy --target wasm32-unknown-unknown
cargo +1.90.0 fmt --check
cargo +1.90.0 test --locked
cargo +1.90.0 clippy --locked --all-targets -- -D warnings
git diff --exit-code -- Cargo.lock
```

The golden suite includes adversarial fixtures — tampered payloads, forged
anchors, post-revocation forgeries, rewritten history — and asserts each is
rejected with the right error, not just "invalid".

## Reproduce the browser artifact

```bash
cd verify-rs
tool_bin=$(bash scripts/install-canonical-wasm-tools.sh /tmp/swarrm-wasm-tools)
PATH="$tool_bin:$PATH" bash scripts/build-canonical-wasm.sh web
shasum -a 256 pkg/swarrm_verify_bg.wasm
```

Compare the hash against the committed
[`verify-rs/web/INTEGRITY.txt`](verify-rs/web/INTEGRITY.txt) and
[swarrm.ai/INTEGRITY.txt](https://swarrm.ai/INTEGRITY.txt). Bit-exact
reproduction requires the same pinned toolchain on x86-64 Linux (all tool
versions and archive checksums are recorded in the integrity file and
installed by the script); other hosts produce semantically equivalent but
byte-different modules. CI asserts exact-byte reproduction on the canonical
host and that `Cargo.lock` does not change.

## Supply-chain controls

Every pull request runs the Rust gate, a complete-history secret scan, a
RustSec audit with the reviewed VEX exception, CodeQL, policy checks, an
exact-byte canonical Linux x86-64 WASM rebuild, and browser parity checks.
Toolchains, actions, and downloaded build tools are version- or digest-pinned.

Signed releases require a conforming annotated `v*` tag whose commit is an
ancestor of `main` **and** whose own `verifier` workflow run is green — a
release cannot be published from a commit whose checks did not pass. The
release workflow then rebuilds the verifier deterministically and publishes
normalized source, browser, and Node archives; a validated CycloneDX SBOM;
`SHA256SUMS`; a keyless Sigstore bundle; and GitHub-hosted SLSA provenance and
SBOM attestations. See [`security/H22.md`](security/H22.md) for the exact
control boundary and the gates that still require an independent human.

## What verification proves (and doesn't)

The offline E1 result means the receipts are signed by keys witnessed in the
log and the log is internally consistent. Anchor and timestamp records can
strengthen that result only when their external trust assumptions are supplied
and validated. Verification does not prove the *payloads* are true — it proves
the recorded actions have not been altered since they were written.

It also cannot establish global or latest completeness from a producer-chosen
export. An internally valid bundle, key log, or authority-state checkpoint may
still be an older consistent prefix. Before relying on freshness, compare an
independently obtained later checkpoint or signed high-water. B28 similarly
proves identity and authority only at its verified checkpoint; it does not
predict future behaviour, certify an action outcome, or evaluate Node, source,
coverage, history, or post-action evidence readiness in v1.

## Repository map

| Path | Contents |
|---|---|
| [`verify-rs/src/`](verify-rs/src/) | Rust verification engine and WASM exports |
| [`verify-rs/web/`](verify-rs/web/) | Static local-file browser interface and parity test |
| [`verify-rs/pkg/`](verify-rs/pkg/) | Committed, digest-pinned browser release artifact |
| [`tests/golden/`](tests/golden/) | Shared valid and hostile fixtures with expected results |
| [`SPEC/`](SPEC/) | Evidence, log, anchor, certificate, and authority wire formats |
| [`fuzz/`](fuzz/) | Bounded fuzz targets seeded from the hostile corpus |
| [`security/`](security/) | Security boundary, release controls, and OpenVEX statement |

## Security and license

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).
The code and specifications are Apache-2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). The specs in `SPEC/` are Apache-2.0 as well: implement
them, port them, embed them.
