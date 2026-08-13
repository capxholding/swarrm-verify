# Changelog

All notable changes to `swarrm-verify` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.6] - 2026-08-13

### Security

- Reproduce the browser verifier with checksummed release binaries for
  wasm-pack, wasm-bindgen CLI and Binaryen. The build now uses `no-install`
  mode, so it cannot silently compile a tool from a changing Cargo graph.

### Fixed

- Restore release provenance after the coordinated history remediation changed
  the reachable `v1.0.5` revision while the existing release assets retained
  their original commit identity. Version `1.0.6` is built and attested from a
  new immutable tag; the historical release is not overwritten.
- Retain the canonical Linux rebuild when a committed artifact comparison
  fails, making a byte-level provenance drift directly diagnosable.

## [1.0.5] - 2026-08-12

### Security

- Require every signed receipt payload to be strict JSON whose bytes are
  already in exact RFC 8785 canonical form; duplicate members, trailing bytes
  and alternate-but-equivalent encodings now fail before claim evaluation.
- Require receipt-v1 fields, types, tenant binding and signer roles to match the
  closed profile before any signed receipt enters verification.
- Enforce the complete selective-disclosure field/domain registry, exact package
  shape, canonical base64 and minimum nonce strength in native Rust and WASM.

### Fixed

- Preserve the exact uploaded JSON bytes across browser policy re-verification;
  only the deliberate tamper demonstration re-encodes its modified text.
- Add the deterministic CycloneDX `serialNumber` required by `actions/attest`,
  while retaining schema validation, checksum signing, SBOM attestation and
  provenance publication.
- Supersede the unpublished `v1.0.4` tag. Its deterministic build succeeded,
  but publication was stopped after the stale browser re-verification path and
  missing attestation-recognition field were found; the tag remains immutable
  and has no GitHub release.

## [1.0.4] - 2026-08-09

### Added

- Relying-party-rooted post-action E2 verification requiring one exact covering
  checkpoint to be both re-read from Base/Base Sepolia and timestamped under an
  RFC 3161 root supplied outside the bundle.
- Cumulative E3 verification: a receipt must first satisfy E2, then carry the
  evidence-issuer signature and a temporally active non-issuer recorder
  co-signature under relying-party-supplied recorder trust.
- Shared hostile fixtures for duplicate/future/revoked key history, strict
  timestamp chains and same-checkpoint intersection, executed in native Rust
  and browser WASM.
- SHA-pinned Rust and GitHub Actions CodeQL analysis.
- Weekly Dependabot updates and scheduled RustSec monitoring.
- Four bounded cargo-fuzz targets seeded from the committed hostile and golden
  corpus, with 90-day crash retention.
- A private-publication-mode OpenSSF Scorecard workflow pinned to the action
  release containing Scorecard v5.5.0.
- A deterministic tag-release path producing Rust/WASM source and runtime
  archives, CycloneDX SBOM, checksums, keyless Sigstore signature bundle, SLSA
  provenance and SBOM attestations.
- CODEOWNERS and an H22 policy gate for version, VEX, workflow-permission and
  full-action-SHA invariants.

### Security

- Added an OpenVEX `not_affected` statement for RUSTSEC-2023-0071. The verifier
  uses RSA only for public-key signature verification; the advisory concerns
  private-key operations. The dependency remains visible and monitored.

### Fixed

- Enforced complete canonical DER/CMS consumption, certificate algorithm/key
  agreement, bounded deterministic path construction, timestamp-only EKU,
  path-length and critical-extension constraints in parity with Python.
- Tracked wasm-pack's generated package ignore file so the release workflow's
  exact rebuilt-package comparison does not fail on an otherwise identical
  artifact.
- Hardened UTC timestamp digit parsing with checked arithmetic. A first H22
  cargo-fuzz smoke run found that a malformed fractional digit could underflow
  before the timestamp was rejected; the minimized regression now fails closed.
- The hosted TSA fuzz run exposed an aborting upstream X.509 PEM parser on
  arbitrary chain bytes. The target now preserves the canonical chain fixture
  and mutates DER/digest inputs, keeping the fuzz boundary crash-free.
- Aligned the crate, Cargo lockfile, generated package, changelog and next tag
  on `1.0.4`. The historical `v1.0.3` GitHub release was source-only and its
  tagged tree still declared `0.1.0`; it is not rewritten or treated as a
  reproducible binary release.

## [1.0.3] - 2026-08-08

- Source-only GitHub release. It had no downloadable assets, SBOM, signature or
  provenance, and the tagged tree declared crate/package version `0.1.0`.

[Unreleased]: https://github.com/capxholding/swarrm-verify/compare/v1.0.6...HEAD
[1.0.6]: https://github.com/capxholding/swarrm-verify/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/capxholding/swarrm-verify/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/capxholding/swarrm-verify/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/capxholding/swarrm-verify/releases/tag/v1.0.3
