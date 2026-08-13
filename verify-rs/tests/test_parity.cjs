// Apache-2.0 (public verifier repo)
// WASM parity: the browser verifier (compiled from the same lib.rs) must agree
// with the shared golden suite — the same fixtures the native Rust crate and
// the Python verifier run. Build first with the checksummed tools documented in README:
//   wasm-pack build --mode no-install --target nodejs --features wasm --locked
//   node verify-rs/tests/test_parity.cjs
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { isDeepStrictEqual } = require("util");
const wasm = require("../pkg-node/swarrm_verify.js");
const { verify_certificate_cbor, verify_b28_cwt } = wasm;
const bytes = value => Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
const verify_bundle_json = value => wasm.verify_bundle_json(bytes(value));
const derive_vector_json = (input, trust) => wasm.derive_vector_json(bytes(input), bytes(trust));
const verify_disclosure_json = (input, bundle) => wasm.verify_disclosure_json(bytes(input), bytes(bundle));

const dir = path.join(__dirname, "..", "..", "tests", "golden", "bundles");
const expected = JSON.parse(fs.readFileSync(path.join(dir, "expected.json"), "utf8"));
const RESULT_SCHEMA = "evd/browser-bundle-verification-result/v2";
const VALID_E1_DIGEST = "c3c85b1143c937cacf692eb37377b72be4d53941055262623c022c64916e8239";

function parseBundleResult(raw) {
  const result = JSON.parse(raw);
  const fields = result && !Array.isArray(result) ? Object.keys(result).sort().join(",") : "";
  if (fields !== "bundle_digest,error,schema,verdict" || result.schema !== RESULT_SCHEMA ||
      !["VERIFIED", "NOT_VERIFIED", "ERROR"].includes(result.verdict)) {
    throw new Error(`invalid browser verifier result: ${raw}`);
  }
  const hashOk = result.verdict === "VERIFIED"
    ? /^[0-9a-f]{64}$/.test(result.bundle_digest)
    : result.bundle_digest === null;
  const errorOk = result.verdict === "ERROR"
    ? typeof result.error === "string" && result.error.length > 0
    : result.error === null;
  if (!hashOk || !errorOk) throw new Error(`invalid browser verifier result: ${raw}`);
  return result;
}

let failures = 0;
const declarations = fs.readFileSync(path.join(__dirname, "..", "pkg-node", "swarrm_verify.d.ts"), "utf8");
const byteApiOk =
  /verify_bundle_json\(json: Uint8Array\)/.test(declarations) &&
  /derive_vector_json\(verdict_input_json: Uint8Array, trust_json: Uint8Array\)/.test(declarations) &&
  /verify_disclosure_json\(package_json: Uint8Array, bundle_json: Uint8Array\)/.test(declarations);
if (!byteApiOk) failures++;
console.log(`${byteApiOk ? "OK " : "XX "} WASM JSON boundaries require Uint8Array`);
for (const [name, want] of Object.entries(expected)) {
  const bundle = fs.readFileSync(path.join(dir, `${name}.json`), "utf8");
  const got = parseBundleResult(verify_bundle_json(bundle));
  const digestOk = name !== "valid_e1" || got.bundle_digest === VALID_E1_DIGEST;
  const ok = got.verdict === want && digestOk;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} ${name}: wasm=${got.verdict} expected=${want}`);
}
for (const [name, fixture, mutate] of [
  ["boolean leaf index", "valid_e1.json", b => { b.entries[0].leaf_index = false; }],
  ["empty timestamp fraction", "b21_authority_valid.json", b => { b.anchor_records[0].block_ts = "2026-01-01T00:00:00.Z"; }],
  ["impossible Gregorian date", "b21_authority_valid.json", b => { b.anchor_records[0].block_ts = "2026-02-30T00:00:00Z"; }],
]) {
  const bundle = JSON.parse(fs.readFileSync(path.join(dir, fixture), "utf8"));
  mutate(bundle);
  const got = parseBundleResult(verify_bundle_json(JSON.stringify(bundle)));
  const ok = got.verdict === "NOT_VERIFIED" && got.bundle_digest === null;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} hostile ${name}`);
}
const malformed = parseBundleResult(verify_bundle_json("{"));
const malformedOk = malformed.verdict === "ERROR" && malformed.bundle_digest === null;
if (!malformedOk) failures++;
console.log(`${malformedOk ? "OK " : "XX "} malformed JSON result contract`);
const baseBundle = fs.readFileSync(path.join(dir, "valid_e1.json"), "utf8").trimEnd();
const withFragment = fragment => `${baseBundle.slice(0, -1)},${fragment}}`;
for (const [name, raw] of [
  ["UTF-8 BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes(baseBundle)])],
  ["invalid UTF-8 scalar", Buffer.concat([
    bytes(`${baseBundle.slice(0, -1)},"utf8_probe":"`),
    Buffer.from([0xed, 0xa0, 0x80]),
    bytes('"}'),
  ])],
]) {
  const got = parseBundleResult(verify_bundle_json(raw));
  const ok = got.verdict === "ERROR" && got.error === "INVALID_JSON" && got.bundle_digest === null;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} raw byte boundary ${name}`);
}
const numberProfile = JSON.parse(fs.readFileSync(
  path.join(dir, "..", "json_number_profile.json"), "utf8",
));
for (const [name, item] of Object.entries(numberProfile)) {
  const token = item.token || `${item.prefix || ""}${item.repeat.repeat(item.count)}${item.suffix || ""}`;
  const got = parseBundleResult(verify_bundle_json(withFragment(`"number_probe":${token}`)));
  const ok = got.verdict === item.rust_verdict &&
    (item.accepted ? got.bundle_digest !== null : got.bundle_digest === null);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} JSON number profile ${name}`);
}
const duplicateProfile = JSON.parse(fs.readFileSync(
  path.join(dir, "..", "json_duplicate_profile.json"), "utf8",
));
for (const [name, fragment] of Object.entries(duplicateProfile)) {
  const input = withFragment(fragment);
  const got = parseBundleResult(verify_bundle_json(input));
  const ok = got.verdict === "ERROR" && got.error === "INVALID_JSON" && got.bundle_digest === null;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} duplicate JSON ${name}`);
}
const unicodeProfile = JSON.parse(fs.readFileSync(
  path.join(dir, "..", "json_unicode_profile.json"), "utf8",
));
for (const [name, item] of Object.entries(unicodeProfile)) {
  const got = parseBundleResult(verify_bundle_json(withFragment(item.fragment)));
  const ok = got.verdict === (item.accepted ? "VERIFIED" : "ERROR") &&
    (item.accepted ? got.bundle_digest !== null : got.bundle_digest === null);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} Unicode scalar profile ${name}`);
}
const hostileJson = [
  '{"x":1,"x":2}',
  `${'{"x":'.repeat(70)}0${'}'.repeat(70)}`,
  `{"x":1.${"0".repeat(200)}}`,
];
const weakVector = derive_vector_json("{}", "");
const invalidUtf8Object = Buffer.concat([
  bytes('{"probe":"'), Buffer.from([0xed, 0xa0, 0x80]), bytes('"}'),
]);
for (const [name, raw] of [
  ["UTF-8 BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes("{}")])],
  ["invalid UTF-8 scalar", invalidUtf8Object],
]) {
  const ok = derive_vector_json(raw, "") === weakVector;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} verdict-input raw byte boundary ${name}`);
}
for (const [index, hostile] of hostileJson.entries()) {
  const ok = derive_vector_json(hostile, "") === weakVector;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} strict verdict input ${index + 1}`);
}
const verdictDir = path.join(dir, "..", "verdicts");
const verdictInput = fs.readFileSync(path.join(verdictDir, "va_hardware_full_scan.json"), "utf8");
const untrustedVector = derive_vector_json(verdictInput, "");
for (const [name, raw] of [
  ["UTF-8 BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes("{}")])],
  ["invalid UTF-8 scalar", invalidUtf8Object],
]) {
  const ok = derive_vector_json(verdictInput, raw) === untrustedVector;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} local-trust raw byte boundary ${name}`);
}
hostileJson[2] = `{"x":1e${"0".repeat(200)}1}`;
for (const [index, hostile] of hostileJson.entries()) {
  const ok = derive_vector_json(verdictInput, hostile) === untrustedVector;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} strict local trust ${index + 1}`);
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`\nWASM agrees with all ${Object.keys(expected).length} golden fixtures`);

const disclosureBundle = fs.readFileSync(path.join(dir, "disclosure_bundle.json"), "utf8");
const disclosureCases = JSON.parse(fs.readFileSync(path.join(dir, "disclosure_cases.json"), "utf8"));
for (const item of disclosureCases) {
  const got = verify_disclosure_json(JSON.stringify(item.package), disclosureBundle);
  const ok = got === item.expected;
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} disclosure ${item.name}`);
}
const duplicateDisclosure = '{"schema":"evd/disclosure/v1","schema":"evd/disclosure/v1"}';
if (verify_disclosure_json(duplicateDisclosure, disclosureBundle)) failures++;
console.log(`${!verify_disclosure_json(duplicateDisclosure, disclosureBundle) ? "OK " : "XX "} disclosure duplicate-key JSON`);
for (const [name, raw] of [
  ["UTF-8 BOM", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes("{}")])],
  ["invalid UTF-8 scalar", invalidUtf8Object],
]) {
  const ok = !verify_disclosure_json(raw, disclosureBundle);
  if (!ok) failures++;
  console.log(`${ok ? "OK " : "XX "} disclosure raw byte boundary ${name}`);
}

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
const b28DiffDir = process.env.SWARRM_B28_DIFF_DIR;
if (b28DiffDir) {
  const diffManifest = JSON.parse(fs.readFileSync(path.join(b28DiffDir, "manifest.json"), "utf8"));
  if (diffManifest.schema !== "swarrm-b28/differential-corpus/v1" ||
      diffManifest.case_count !== diffManifest.cases.length ||
      diffManifest.seed_count < 90) {
    throw new Error("malformed B28 differential manifest");
  }
  const mutatedSurfaces = new Set(diffManifest.cases.map(item => `${item.seed}\0${item.target}`));
  if (mutatedSurfaces.size !== diffManifest.mutation_surface_count) {
    throw new Error("B28 differential corpus omitted a declared seed surface");
  }
  for (const item of diffManifest.cases) {
    const input = fs.readFileSync(path.join(b28DiffDir, item.exchange));
    const context = fs.readFileSync(path.join(b28DiffDir, item.context));
    const inputHash = crypto.createHash("sha256").update(input).digest("hex");
    const contextHash = crypto.createHash("sha256").update(context).digest("hex");
    const got = JSON.parse(verifyB28Exchange(input, context));
    const exact = inputHash === item.exchange_sha256 &&
      contextHash === item.context_sha256 && isDeepStrictEqual(got, item.expected);
    const readOnly = got.verdict !== "PASS" && got.should_execute === false;
    if (!exact || !readOnly) {
      failures++;
      console.log(`XX B28 differential ${item.name}`);
    }
  }
  console.log(`WASM == Python on ${diffManifest.cases.length} fresh B28 mutations; read-only/no authorization`);
} else {
  console.log("B28 fresh differential skipped: SWARRM_B28_DIFF_DIR unset");
}
if (failures) {
  console.error(`\nPARITY FAILED: ${failures} fixture(s) disagree`);
  process.exit(1);
}
console.log(`WASM agrees with B28 valid plus ${Object.keys(b28Expected.hostile).length} presentation, ${Object.keys(b28Expected.context_hostile).length} context, ${Object.keys(b28Expected.refusal_hostile).length} refusal, and ${Object.keys(b28Expected.state_hostile).length} authority-state hostile fixtures`);
