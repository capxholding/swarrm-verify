#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

if grep -R -n -E 'pull_request_target:|permissions:[[:space:]]*write-all' .github/workflows; then
  echo "H22 forbids pull_request_target and write-all workflow permissions" >&2
  exit 1
fi

while IFS= read -r use; do
  [[ "$use" == ./* ]] && continue
  if [[ ! "$use" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$ ]]; then
    echo "GitHub Action is not pinned to a full commit SHA: $use" >&2
    exit 1
  fi
done < <(grep -R -h -E '^[[:space:]]*uses:[[:space:]]*[^[:space:]#]+' .github/workflows | sed -E 's/.*uses:[[:space:]]*//; s/[[:space:]]+#.*$//')

cargo_version=$(awk -F '"' '/^version = "/ { print $2; exit }' verify-rs/Cargo.toml)
lock_version=$(awk -F '"' '/^name = "swarrm-verify"$/ { getline; print $2; exit }' verify-rs/Cargo.lock)
package_version=$(node -e 'process.stdout.write(require("./verify-rs/pkg/package.json").version)')
if [[ -z "$cargo_version" || "$cargo_version" != "$lock_version" || "$cargo_version" != "$package_version" ]]; then
  echo "release identity mismatch: Cargo.toml=$cargo_version Cargo.lock=$lock_version package.json=$package_version" >&2
  exit 1
fi
grep -F "## [$cargo_version]" CHANGELOG.md >/dev/null

node <<'NODE'
const fs = require("fs");
const vex = JSON.parse(fs.readFileSync("security/openvex.json", "utf8"));
if (vex["@context"] !== "https://openvex.dev/ns/v0.2.0") throw new Error("unexpected OpenVEX context");
if (!Array.isArray(vex.statements) || vex.statements.length !== 1) throw new Error("expected one reviewed VEX statement");
const statement = vex.statements[0];
if (statement.vulnerability?.["@id"] !== "https://rustsec.org/advisories/RUSTSEC-2023-0071") throw new Error("wrong advisory in VEX");
if (statement.status !== "not_affected" || statement.justification !== "vulnerable_code_not_in_execute_path") throw new Error("VEX status changed without review");
if (!statement.impact_statement?.includes("public-key signature verification only")) throw new Error("VEX must state the actual execution boundary");
NODE

grep -A2 '^name = "rsa"$' verify-rs/Cargo.lock | grep -F 'version = "0.9.10"' >/dev/null
grep -F 'publish_results: false' .github/workflows/scorecard.yml >/dev/null
test -f .github/CODEOWNERS
test -f .github/dependabot.yml
for target in bundle_json certificate_cbor b28_exchange tsa; do
  test -f "fuzz/fuzz_targets/$target.rs"
done
