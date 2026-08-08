# Contributing to swarrm-verify

`swarrm-verify` is the independent, open-source (Apache-2.0) verifier for Swarrm
evidence bundles. It exists so that anyone can check Swarrm evidence offline,
without trusting Swarrm or Capx Holding. Contributions that strengthen that
independence — clearer specifications, more adversarial fixtures, additional ports
of the verifier — are welcome.

## Reporting bugs and requesting changes

Open an issue: <https://github.com/capxholding/swarrm-verify/issues>

Please include the version (commit hash), your platform, and — for a verification
bug — a minimal bundle or fixture that reproduces it. For anything
security-sensitive (for example, a bundle that verifies but should not), follow
[SECURITY.md](SECURITY.md) instead of opening a public issue.

## How to contribute code

We use the standard GitHub fork-and-pull-request workflow:

1. Fork the repository and create a branch off `main`.
2. Make your change, with tests.
3. Open a pull request against `main`. Describe what changed and why, and link any
   related issue.
4. A maintainer reviews; CI must be green before merge.

## Requirements for acceptable contributions

A pull request is considered only when all of the following hold (commands run from
`verify-rs/`):

- `cargo fmt --all -- --check` passes — formatting is enforced by `rustfmt.toml`.
- `cargo clippy --all-targets -- -D warnings` is clean.
- `cargo test` passes, and **all golden fixtures agree**: this Rust verifier and the
  reference Python verifier (in the `swarrm` PyPI package) must return the same
  verdict on every fixture in `tests/golden/`. A change that makes them disagree is
  a specification bug, not a feature.
- New behaviour is covered by a fixture, not only a unit test.
- Contributions are licensed under Apache-2.0. By opening a pull request you certify
  you have the right to submit the work under that license (Developer Certificate of
  Origin).

## Changing the wire format

`SPEC/` is normative. A change to `SPEC/log-v1.md`, `SPEC/bundle-v1.md`, or any other
`evd/*` spec must be reflected in both verifier implementations and in the shared
fixtures, in the same pull request. The specifications and the verifier stay in
lockstep.

## Conduct

Be respectful and technical. Discussion happens in issues and pull requests, in
English.
