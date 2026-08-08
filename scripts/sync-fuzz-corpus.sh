#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == "/" ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=$1
if [[ "$output" == "$repo_root" ]]; then
  echo "refusing to use the repository root as generated corpus output" >&2
  exit 2
fi

mkdir -p "$output"
for target in bundle_json certificate_cbor b28_exchange tsa; do
  rm -rf "$output/$target"
  mkdir -p "$output/$target"
done
rm -f "$output/SOURCE-MANIFEST.tsv" "$output/MANIFEST.sha256"
printf 'target\tselector\tsource\tsha256\n' > "$output/SOURCE-MANIFEST.tsv"

digest_file() {
  openssl dgst -sha256 -r "$1" | awk '{print $1}'
}

seed_copy() {
  local target=$1
  local selector=$2
  local source=$3
  local digest destination
  digest=$(digest_file "$source")
  destination="$output/$target/${selector}-${digest:0:20}-$(basename "$source")"
  if [[ "$selector" == "raw" ]]; then
    cp "$source" "$destination"
  else
    { printf "\\$(printf '%03o' "$selector")"; cat "$source"; } > "$destination"
  fi
  printf '%s\t%s\t%s\t%s\n' "$target" "$selector" "${source#"$repo_root/"}" "$digest" >> "$output/SOURCE-MANIFEST.tsv"
}

while IFS= read -r source; do
  seed_copy bundle_json raw "$source"
done < <(find "$repo_root/tests/golden/bundles" "$repo_root/tests/golden/fuzz" -type f -name '*.json' 2>/dev/null | LC_ALL=C sort)

while IFS= read -r source; do
  seed_copy certificate_cbor raw "$source"
done < <(find "$repo_root/tests/golden/certificates" "$repo_root/tests/golden/certfuzz" -type f \( -name '*.cbor' -o -name '*.bin' \) | LC_ALL=C sort)

while IFS= read -r source; do
  seed_copy b28_exchange 0 "$source"
done < <(find "$repo_root/tests/golden/b28" -type f \( -name '*.input.cbor' -o -name '*.exchange.cbor' \) | LC_ALL=C sort)
while IFS= read -r source; do
  seed_copy b28_exchange 1 "$source"
done < <(find "$repo_root/tests/golden/b28" -type f \( -name '*.context.cbor' -o -name '*-context.cbor' \) | LC_ALL=C sort)
seed_copy b28_exchange 2 "$repo_root/tests/golden/b28/trust-pack.cbor"

while IFS= read -r source; do
  seed_copy tsa 0 "$source"
done < <(find "$repo_root/tests/golden/bundles" -maxdepth 1 -type f -name 'tsa*.der' | LC_ALL=C sort)
while IFS= read -r source; do
  seed_copy tsa 2 "$source"
done < <(find "$repo_root/tests/golden/bundles" -maxdepth 1 -type f -name 'tsa*chain.pem' | LC_ALL=C sort)
digest_seed="$output/tsa-digest.txt"
printf '%s' '7a5c8e2b9f1d4a6c3e8b0f2d5a7c9e1b4d6f8a0c2e5b7d9f1a3c5e7b9d0f2a4c' > "$digest_seed"
seed_copy tsa 1 "$digest_seed"
rm -f "$digest_seed"

(
  cd "$output"
  find bundle_json certificate_cbor b28_exchange tsa -type f | LC_ALL=C sort | while IFS= read -r path; do
    openssl dgst -sha256 -r "$path" | awk -v path="$path" '{print $1 "  " path}'
  done
) > "$output/MANIFEST.sha256"

for target in bundle_json certificate_cbor b28_exchange tsa; do
  test "$(find "$output/$target" -type f | wc -l | tr -d ' ')" -gt 0
done
