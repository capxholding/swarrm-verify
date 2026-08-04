// Apache-2.0 (public verifier repo)
// WASM parity: the browser verifier (compiled from the same lib.rs) must agree
// with the shared golden suite — the same fixtures the native Rust crate and
// the Python verifier run. Build first:  wasm-pack build --target nodejs --features wasm
//   node verify-rs/web/test_parity.cjs
const fs = require("fs");
const path = require("path");
const { verify_bundle_json, verify_certificate_cbor } = require("../pkg-node/swarrm_verify.js");

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

const certDir = path.join(__dirname, "..", "..", "tests", "golden", "certificates");
const certExpected = JSON.parse(fs.readFileSync(path.join(certDir, "expected.json"), "utf8"));
for (const [name, want] of Object.entries(certExpected)) {
  const bytes = fs.readFileSync(path.join(certDir, `${name}.view.cbor`));
  const got = JSON.parse(verify_certificate_cbor(bytes));
  // The browser entry point intentionally receives no out-of-band trust
  // context. A certificate cannot smuggle in its own roots, so every family
  // stays UNMARKED_UNREGISTERED even when the trust-injected native golden is
  // stronger. Cross-check results must still match.
  const publicMark = "UNMARKED_UNREGISTERED";
  const ok = got.mark === publicMark && got.cross_checks_ok === want.cross_checks_ok;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} certificate ${name}: wasm=${got.mark} expected=${publicMark}`);
  if (want.partial !== null) {
    const partial = fs.readFileSync(path.join(certDir, `${name}.partial.cbor`));
    const pgot = JSON.parse(verify_certificate_cbor(partial));
    const pok = pgot.mark === want.partial.mark &&
      pgot.core_present === want.partial.core_present &&
      JSON.stringify(pgot.errors) === JSON.stringify(want.partial.errors);
    if (!pok) failures++;
    console.log(`${pok ? "OK " : "XX "} certificate ${name}.partial: core=${pgot.core_present}`);
  }
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`WASM agrees with all ${Object.keys(certExpected).length} certificate families`);
