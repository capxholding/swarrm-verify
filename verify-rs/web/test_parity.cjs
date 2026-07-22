// Apache-2.0 (public verifier repo)
// WASM parity: the browser verifier (compiled from the same lib.rs) must agree
// with the shared golden suite — the same fixtures the native Rust crate and
// the Python verifier run. Build first:  wasm-pack build --target nodejs --features wasm
//   node verify-rs/web/test_parity.cjs
const fs = require("fs");
const path = require("path");
const { verify_bundle_json } = require("../pkg/swarrm_verify.js");

const dir = path.join(__dirname, "..", "..", "tests", "golden", "bundles");
const expected = JSON.parse(fs.readFileSync(path.join(dir, "expected.json"), "utf8"));

let failures = 0;
for (const [name, want] of Object.entries(expected)) {
  const bundle = fs.readFileSync(path.join(dir, `${name}.json`), "utf8");
  const got = verify_bundle_json(bundle); // "VERIFIED" | "NOT VERIFIED" | "ERROR: ..."
  const norm = got === "VERIFIED" ? "VERIFIED" : "NOT_VERIFIED";
  const ok = norm === want;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} ${name}: wasm=${got} expected=${want}`);
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`\nWASM agrees with all ${Object.keys(expected).length} golden fixtures`);
