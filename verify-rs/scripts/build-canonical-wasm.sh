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


# MEASURED 2026-09-09: as bare `[[ ]]` these pins asserted NOTHING on macOS bash
# 3.2.57, where a failed standalone predicate does not stop the script -- and
# verify-rs/README.md tells the reader to run this file with `bash`, which is
# 3.2.57 there. So the canonical WASM module of the PUBLIC verifier could be
# built by a documented command with the wrong rustc, wasm-bindgen or wasm-opt
# and report success. bash 5 and zsh do stop; the defect was invisible to anyone
# on a modern shell.
#
# `observed` is declared and assigned on SEPARATE lines on purpose: a combined
# `local observed=$(...)` returns the status of `local`, not of the command, so
# a tool that fails to run would look like a version mismatch instead.
require_tool_version() {
  local tool=$1 expected=$2
  local observed
  shift 2
  observed=$("$@" 2>&1) || {
    printf 'canonical build: %s could not be run (%s)\n' "$tool" "$*" >&2
    exit 1
  }
  [[ $observed == "$expected" ]] || {
    printf 'canonical build: %s is %s, expected %s\n' "$tool" "$observed" "$expected" >&2
    exit 1
  }
}

require_tool_version rustc 'rustc 1.90.0 (1159e78c4 2025-09-14)' rustc --version
require_tool_version wasm-pack 'wasm-pack 0.15.0' wasm-pack --version
require_tool_version wasm-bindgen 'wasm-bindgen 0.2.126' wasm-bindgen --version
require_tool_version wasm-opt 'wasm-opt version 117 (version_117)' wasm-opt --version

# Rust embeds panic-source paths in the optimized module. Map both variable
# roots to stable virtual locations through Cargo's unit-separator encoding so
# workspaces containing spaces remain valid and independent rebuilds converge.
unset RUSTFLAGS
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=$repo_root=/swarrm/source"$'\x1f'"--remap-path-prefix=$cargo_root=/swarrm/cargo"
export CARGO_INCREMENTAL=0 LC_ALL=C TZ=UTC

cd "$crate_dir"
wasm-pack build --mode no-install --target "$target" --out-dir "$output" \
  --features wasm --locked
