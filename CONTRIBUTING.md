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

## Hosted runner baseline and upgrades

Mirror workflows select GitHub-hosted `ubuntu-24.04` x64 explicitly. Their first
step refuses a different OS family/version or architecture and records the actual
`ImageVersion` and commit in the job summary. This label fixes the Ubuntu release,
not an immutable weekly image: retain each job's setup log, image release link,
and summary when qualifying a release, and compare them with the previous record.
Do not treat a previously green commit as proof for a different image build.

The original CodeQL warning is retained in [run 38041900550, attempt 1](https://github.com/capxholding/swarrm-verify/actions/runs/38041900550/attempts/1),
commit `149e82e6e888d9a283c63710c4777d2740538bc5`. Both jobs used Ubuntu 24.04.5,
image `20261004.327.1`. GitHub's [migration announcement](https://github.com/actions/runner-images/issues/14748)
schedules the `ubuntu-latest` transition to Ubuntu 26.04 from October 19 through
November 19, 2026 and explicitly supports selecting `ubuntu-24.04`. Keeping this
OS baseline avoids an unreviewed major-version change; it does not establish
Ubuntu 26.04 compatibility.

For an upgrade, use a dedicated pull request to change the explicit labels and
runtime admission assertions together. Preserve the previous warning, workflow
sources, full job logs, image identities, and terminal conclusions. Run `verifier`,
`dependency-audit`, `CodeQL`, and `continuous-fuzz` on the exact candidate; fuzzing
must include all four targets even when path filters would otherwise skip it.
Require Rust tests and Clippy, the canonical WASM rebuild with unchanged committed
bytes and integrity pins, browser golden parity, the existing security policy and
secret scan, RustSec, and both CodeQL languages. A changed artifact or security
failure blocks acceptance; do not repin artifacts or waive checks to admit an OS.
Record the resulting run/attempt, job, commit, OS and image versions and compare
all jobs before approval. Require fresh main runs after merge. Release signing,
publication, and Scorecard have separate acceptance; green verifier workflows do
not claim those operations passed. Never dispatch publication to test an image.

If an image migration reaches a still-open release qualification, escalate to
that release's owner before accepting its evidence. A retry on a different image
is a new qualification attempt, not proof that the earlier environment passed.
