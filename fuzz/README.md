# Continuous fuzzing

The four libFuzzer targets exercise the public bundle, certificate, B28 and
RFC 3161 entrypoints. `scripts/sync-fuzz-corpus.sh` derives each run's seed
corpus from the committed golden and hostile fixtures; generated corpora are
not source artifacts.

Run a target with the same pinned toolchain used in CI:

```sh
rustup toolchain install nightly-2026-08-01 --profile minimal
cargo +nightly-2026-08-01 install cargo-fuzz --version 0.13.2 --locked
tmp_dir=$(mktemp -d)
bash scripts/sync-fuzz-corpus.sh "$tmp_dir"
cargo +nightly-2026-08-01 fuzz run --fuzz-dir fuzz b28_exchange "$tmp_dir/b28_exchange"
```

For a finding, first minimize the retained input with
`cargo +nightly-2026-08-01 fuzz tmin --fuzz-dir fuzz <target> <artifact>`.
Closure requires
the minimized bytes to be promoted into the matching committed hostile corpus
and replayed by a normal locked Rust test. Retaining a CI artifact alone does
not close the defect.

This integration is genuine continuous cargo-fuzz coverage. OpenSSF Scorecard
v5.5.0 recognizes OSS-Fuzz and ClusterFuzzLite, not standalone cargo-fuzz, so
it may continue to score the `Fuzzing` heuristic as zero.
