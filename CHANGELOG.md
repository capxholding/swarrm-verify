# Changelog

All notable changes to `swarrm-verify` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.4] - 2026-08-09

### Added

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

- Hardened UTC timestamp digit parsing with checked arithmetic. A first H22
  cargo-fuzz smoke run found that a malformed fractional digit could underflow
  before the timestamp was rejected; the minimized regression now fails closed.
- Aligned the crate, Cargo lockfile, generated package, changelog and next tag
  on `1.0.4`. The historical `v1.0.3` GitHub release was source-only and its
  tagged tree still declared `0.1.0`; it is not rewritten or treated as a
  reproducible binary release.

## [1.0.3] - 2026-08-08

- Source-only GitHub release. It had no downloadable assets, SBOM, signature or
  provenance, and the tagged tree declared crate/package version `0.1.0`.

[Unreleased]: https://github.com/capxholding/swarrm-verify/compare/v1.0.4...HEAD
[1.0.4]: https://github.com/capxholding/swarrm-verify/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/capxholding/swarrm-verify/releases/tag/v1.0.3
