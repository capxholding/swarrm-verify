// Apache-2.0 (public verifier repo)
// WASM parity: the browser verifier (compiled from the same lib.rs) must agree
// with the shared golden suite — the same fixtures the native Rust crate and
// the Python verifier run. Build first:  wasm-pack build --target nodejs --features wasm --locked
//   node verify-rs/web/test_parity.cjs
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { derive_vector_json, verify_bundle_json, verify_certificate_cbor, verify_b28_cwt } = require("../pkg-node/swarrm_verify.js");

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
for (const [name, fixture, mutate] of [
  ["boolean leaf index", "valid_e1.json", b => { b.entries[0].leaf_index = false; }],
  ["empty timestamp fraction", "b21_authority_valid.json", b => { b.anchor_records[0].block_ts = "2026-01-01T00:00:00.Z"; }],
  ["impossible Gregorian date", "b21_authority_valid.json", b => { b.anchor_records[0].block_ts = "2026-02-30T00:00:00Z"; }],
]) {
  const bundle = JSON.parse(fs.readFileSync(path.join(dir, fixture), "utf8"));
  mutate(bundle);
  const ok = verify_bundle_json(JSON.stringify(bundle)) === "NOT VERIFIED";
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} hostile ${name}`);
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`\nWASM agrees with all ${Object.keys(expected).length} golden fixtures`);

const sourceProof = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "..", "tests", "golden", "source_proof_full_disclosure.json"),
  "utf8",
));
const clone = value => JSON.parse(JSON.stringify(value));
const sourceSignature = (input, trust) => JSON.parse(derive_vector_json(
  JSON.stringify(input),
  trust ? JSON.stringify(trust) : "",
)).source_signature;
const sourceGot = sourceSignature(sourceProof.verdict_input, sourceProof.trust);
const sourceOk = sourceGot === sourceProof.expected;
if (!sourceOk) failures++;
console.log(`${sourceOk ? "OK " : "XX "} SourceProof full disclosure: wasm=${sourceGot} expected=${sourceProof.expected}`);
const sourceUntrusted = sourceSignature(sourceProof.verdict_input, null);
if (sourceUntrusted !== "NONE") failures++;
console.log(`${sourceUntrusted === "NONE" ? "OK " : "XX "} SourceProof without local trust: wasm=${sourceUntrusted} expected=NONE`);
const macGot = sourceSignature(sourceProof.mac_verdict_input, sourceProof.mac_trust);
if (macGot !== sourceProof.mac_expected) failures++;
console.log(`${macGot === sourceProof.mac_expected ? "OK " : "XX "} SourceProof MAC disclosure: wasm=${macGot} expected=${sourceProof.mac_expected}`);

const selective = clone(sourceProof.verdict_input);
delete selective.source_proofs;
selective.view = { withheld_fields: ["source_proofs"] };
const selectiveGot = sourceSignature(selective, sourceProof.trust);
if (selectiveGot !== "NOT_RECOMPUTED") failures++;
console.log(`${selectiveGot === "NOT_RECOMPUTED" ? "OK " : "XX "} SourceProof selective view: wasm=${selectiveGot} expected=NOT_RECOMPUTED`);

const hostileSourceProofs = [];
for (const [name, mutate] of [
  ["malformed base64", proof => { proof.material = "***not-base64***"; }],
  ["digest mismatch", proof => { proof.material_digest = "00".repeat(32); }],
  ["context mismatch", proof => { proof.signature_context = "vendor-guessed-context"; }],
  ["key mismatch", proof => { proof.key_identity = "other-kid"; }],
]) {
  const input = clone(sourceProof.verdict_input);
  mutate(input.source_proofs[0]);
  hostileSourceProofs.push([name, input]);
}
const family = clone(sourceProof.verdict_input);
family.source_identity.keys[0].algorithm_family = "Ed25519";
hostileSourceProofs.push(["family mismatch", family]);

const duplicate = clone(sourceProof.verdict_input);
let duplicateRaw = Buffer.from(duplicate.source_proofs[0].material, "base64").toString("utf8");
duplicateRaw = duplicateRaw.replace(
  '"event_key": "evt-000000"',
  '"event_key": "evt-000000", "event_key": "evt-000000"',
);
const duplicateBytes = Buffer.from(duplicateRaw, "utf8");
duplicate.source_proofs[0].material = duplicateBytes.toString("base64");
duplicate.source_proofs[0].material_digest = crypto.createHash("sha256").update(duplicateBytes).digest("hex");
hostileSourceProofs.push(["duplicate key material", duplicate]);

const trailing = clone(sourceProof.verdict_input);
const trailingBytes = Buffer.concat([
  Buffer.from(trailing.source_proofs[0].material, "base64"),
  Buffer.from("{}"),
]);
trailing.source_proofs[0].material = trailingBytes.toString("base64");
trailing.source_proofs[0].material_digest = crypto.createHash("sha256").update(trailingBytes).digest("hex");
hostileSourceProofs.push(["trailing JSON value", trailing]);

const oversized = clone(sourceProof.verdict_input);
const oversizedBytes = Buffer.alloc(1024 * 1024 + 1, 0x20);
oversized.source_proofs[0].material = oversizedBytes.toString("base64");
oversized.source_proofs[0].material_digest = crypto.createHash("sha256").update(oversizedBytes).digest("hex");
hostileSourceProofs.push(["oversized material", oversized]);

const overCount = clone(sourceProof.verdict_input);
overCount.source_proofs = Array.from({ length: 129 }, () => clone(overCount.source_proofs[0]));
hostileSourceProofs.push(["proof count cap", overCount]);

for (const [name, input] of hostileSourceProofs) {
  const got = sourceSignature(input, sourceProof.trust);
  const ok = got === "NONE";
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} SourceProof hostile ${name}: wasm=${got} expected=NONE`);
}

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

const b28Dir = path.join(__dirname, "..", "..", "tests", "golden", "b28");
const b28Expected = JSON.parse(fs.readFileSync(path.join(b28Dir, "manifest.json"), "utf8"));
// This is browser configuration, not exchange data. The B28 API separately
// validates these bytes against this pinned digest before examining an input.
const b28TrustPack = fs.readFileSync(path.join(b28Dir, "trust-pack.cbor"));
const b28TrustPackPin = Buffer.from("042b49806fbe4e175828bdbfc96386e8ec88a71d386ed2536d8c30459c25c5cc", "hex");
const verifyB28Exchange = (input, localContext) => verify_b28_cwt(input, localContext, b28TrustPack, b28TrustPackPin);
const presentationContext = fs.readFileSync(path.join(b28Dir, "verify-context.cbor"));
const refusalContext = fs.readFileSync(path.join(b28Dir, "refusal-context.cbor"));
const b28Input = fs.readFileSync(path.join(b28Dir, "verify-input.cbor"));
const b28Got = JSON.parse(verifyB28Exchange(b28Input, presentationContext));
if (JSON.stringify(b28Got) !== JSON.stringify(b28Expected.expected_read_only)) failures++;
console.log(`${JSON.stringify(b28Got) === JSON.stringify(b28Expected.expected_read_only) ? "OK " : "XX "} B28 valid read-only`);
const successorInput = fs.readFileSync(path.join(b28Dir, "successor-input.cbor"));
const successorContext = fs.readFileSync(path.join(b28Dir, "successor-context.cbor"));
const successorGot = JSON.parse(verifyB28Exchange(successorInput, successorContext));
const successorOk = JSON.stringify(successorGot) === JSON.stringify(b28Expected.expected_successor_read_only);
if (!successorOk) failures++;
console.log(`${successorOk ? "OK " : "XX "} B28 valid successor`);
const refusalInput = fs.readFileSync(path.join(b28Dir, "refusal-input.cbor"));
const refusalGot = JSON.parse(verifyB28Exchange(refusalInput, refusalContext));
const refusalOk = JSON.stringify(refusalGot) === JSON.stringify(b28Expected.expected_refusal);
if (!refusalOk) failures++;
console.log(`${refusalOk ? "OK " : "XX "} B28 signed refusal`);
for (const [name, item] of Object.entries(b28Expected.hostile)) {
  const input = fs.readFileSync(path.join(b28Dir, "hostile", `${name}.input.cbor`));
  const got = JSON.parse(verifyB28Exchange(input, presentationContext));
  const ok = JSON.stringify(got) === JSON.stringify(item.expected);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} B28 hostile ${name}`);
}
for (const [name, item] of Object.entries(b28Expected.successor_hostile)) {
  const input = fs.readFileSync(path.join(b28Dir, "successor-hostile", `${name}.input.cbor`));
  const got = JSON.parse(verifyB28Exchange(input, successorContext));
  const ok = JSON.stringify(got) === JSON.stringify(item.expected);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} B28 hostile successor ${name}`);
}
for (const [name, item] of Object.entries(b28Expected.context_hostile)) {
  const context = fs.readFileSync(path.join(b28Dir, "context-hostile", `${name}.context.cbor`));
  const got = JSON.parse(verifyB28Exchange(b28Input, context));
  const ok = JSON.stringify(got) === JSON.stringify(item.expected);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} B28 hostile context ${name}`);
}
for (const [name, item] of Object.entries(b28Expected.refusal_hostile)) {
  const input = fs.readFileSync(path.join(b28Dir, "refusal-hostile", `${name}.exchange.cbor`));
  const context = fs.readFileSync(path.join(b28Dir, "refusal-hostile", `${name}.context.cbor`));
  const got = JSON.parse(verifyB28Exchange(input, context));
  const ok = JSON.stringify(got) === JSON.stringify(item.expected);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} B28 hostile refusal ${name}`);
}
for (const [name, item] of Object.entries(b28Expected.state_hostile)) {
  const input = fs.readFileSync(path.join(b28Dir, "state-hostile", `${name}.exchange.cbor`));
  const context = fs.readFileSync(path.join(b28Dir, "state-hostile", `${name}.context.cbor`));
  const got = JSON.parse(verifyB28Exchange(input, context));
  const ok = JSON.stringify(got) === JSON.stringify(item.expected);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} B28 hostile authority state ${name}`);
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`WASM agrees with B28 valid plus ${Object.keys(b28Expected.hostile).length} presentation, ${Object.keys(b28Expected.context_hostile).length} context, ${Object.keys(b28Expected.refusal_hostile).length} refusal, and ${Object.keys(b28Expected.state_hostile).length} authority-state hostile fixtures`);
