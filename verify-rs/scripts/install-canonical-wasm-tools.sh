#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || $1 != /* ]]; then
  echo "usage: $0 ABSOLUTE_INSTALL_ROOT" >&2
  exit 2
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "the canonical verifier toolchain requires x86_64 Linux" >&2
  exit 2
fi

install_root=$1
bin_dir=$install_root/bin
stage_dir=$install_root/stage
install -d -m 0700 "$install_root" "$stage_dir"
install -d -m 0755 "$bin_dir"

download() {
  local name=$1 url=$2 digest=$3
  local target=$stage_dir/$name
  curl --fail --silent --show-error --location --retry 3 \
    --connect-timeout 15 --max-time 300 --proto '=https' --tlsv1.2 \
    --output "$target" "$url"
  local observed
  observed=$(sha256sum "$target")
  if [[ ${observed%% *} != "$digest" ]]; then
    echo "$name SHA-256 differs from the repository pin" >&2
    exit 1
  fi
}

download \
  wasm-pack-0.15.0.tar.gz \
  https://github.com/wasm-bindgen/wasm-pack/releases/download/v0.15.0/wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz \
  c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a
download \
  wasm-bindgen-0.2.126.tar.gz \
  https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.126/wasm-bindgen-0.2.126-x86_64-unknown-linux-musl.tar.gz \
  64948d58e2d6c0a745216477a639ba696216d6309aaa902939d1b865b1d869d
download \
  binaryen-version_117.tar.gz \
  https://github.com/WebAssembly/binaryen/releases/download/version_117/binaryen-version_117-x86_64-linux.tar.gz \
  3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212

tar -xzf "$stage_dir/wasm-pack-0.15.0.tar.gz" -C "$stage_dir"
tar -xzf "$stage_dir/wasm-bindgen-0.2.126.tar.gz" -C "$stage_dir"
tar -xzf "$stage_dir/binaryen-version_117.tar.gz" -C "$stage_dir"

install -m 0755 \
  "$stage_dir/wasm-pack-v0.15.0-x86_64-unknown-linux-musl/wasm-pack" \
  "$bin_dir/wasm-pack"
for tool in wasm-bindgen wasm-bindgen-test-runner wasm2es6js; do
  install -m 0755 \
    "$stage_dir/wasm-bindgen-0.2.126-x86_64-unknown-linux-musl/$tool" \
    "$bin_dir/$tool"
done
install -m 0755 "$stage_dir/binaryen-version_117/bin/wasm-opt" "$bin_dir/wasm-opt"

[[ $("$bin_dir"/wasm-pack --version) == 'wasm-pack 0.15.0' ]]
[[ $("$bin_dir"/wasm-bindgen --version) == 'wasm-bindgen 0.2.126' ]]
[[ $("$bin_dir"/wasm-opt --version) == 'wasm-opt version 117 (version_117)' ]]
printf '%s\n' "$bin_dir"
