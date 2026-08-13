#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 web|nodejs [OUTPUT_DIRECTORY]" >&2
  exit 2
fi
target=$1
case $target in
  web) output=${2:-pkg} ;;
  nodejs) output=${2:-pkg-node} ;;
  *) echo "canonical WASM target must be web or nodejs" >&2; exit 2 ;;
esac
if [[ $output == /* || $output == *..* || $output == *//* ]]; then
  echo "canonical WASM output must be a relative directory without traversal" >&2
  exit 2
fi

crate_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
repo_root=$(cd "$crate_dir/.." && pwd -P)
cargo_root=${CARGO_HOME:-${HOME:?HOME is required}/.cargo}
mkdir -p "$cargo_root"
cargo_root=$(cd "$cargo_root" && pwd -P)

[[ $(rustc --version) == 'rustc 1.90.0 (1159e78c4 2025-09-14)' ]]
[[ $(wasm-pack --version) == 'wasm-pack 0.15.0' ]]
[[ $(wasm-bindgen --version) == 'wasm-bindgen 0.2.126' ]]
[[ $(wasm-opt --version) == 'wasm-opt version 117 (version_117)' ]]

# Rust embeds panic-source paths in the optimized module. Map both variable
# roots to stable virtual locations through Cargo's unit-separator encoding so
# workspaces containing spaces remain valid and independent rebuilds converge.
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$repo_root=/swarrm/source"$'\x1f'"--remap-path-prefix=$cargo_root=/swarrm/cargo"
export CARGO_INCREMENTAL=0 LC_ALL=C TZ=UTC

cd "$crate_dir"
wasm-pack build --mode no-install --target "$target" --out-dir "$output" \
  --features wasm --locked
