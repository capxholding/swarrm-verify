// Apache-2.0
// Fail closed if a page edit silently reintroduces text re-encoding between an
// upload and a relying-party-policy re-verification.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const pageFile = process.argv[2] ?? new URL("../verify-rs/web/index.html", import.meta.url);
const page = fs.readFileSync(pageFile, "utf8");
const required = [
  /let currentText = null;\s+let currentBytes = null;/,
  /function rejectInput\(message\) \{\s+currentText = null;\s+currentBytes = null;/,
  /const text = utf8Decoder\.decode\(raw\);\s+currentText = text;\s+currentBytes = raw;\s+show\(text, raw\);/,
  /requireManifest\.onchange = \(\) => \{ if \(currentText\) show\(currentText, currentBytes\); \};/,
  /flip\.onclick = \(\) => presentation\?\.tamper\(currentText, text => handle\(utf8Encoder\.encode\(text\)\)\);/,
];
for (const [index, contract] of required.entries()) {
  if (!contract.test(page)) throw new Error(`browser page raw-byte contract ${index + 1} is missing`);
}

// Exercise the state contract pinned above: policy-only re-verification gets
// the exact uploaded object, while an intentional mutation receives newly
// encoded bytes and cannot reuse the original byte string.
const uploaded = new TextEncoder().encode(JSON.stringify({schema: "evd/bundle/v1", entries: [{envelope: {payload: "AA"}}]}));
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
let currentText = decoder.decode(uploaded);
let currentBytes = uploaded;
const pagePath = pageFile instanceof URL ? fileURLToPath(pageFile) : pageFile;
const rendererSource = fs.readFileSync(path.join(path.dirname(pagePath), "verification_presentation.js"));
const {createPresentation} = await import(`data:text/javascript;base64,${rendererSource.toString("base64")}`);
const element = () => ({style: {}, textContent: "", hidden: false});
const ui = Object.fromEntries(["controls", "flip", "verdict", "detail", "bundleDigest", "disputeFacts", "requireManifest"].map(key => [key, element()]));
ui.requireManifest.checked = false;
const inputs = [];
const presentation = createPresentation(ui, raw => {
  inputs.push(raw);
  const valid = decoder.decode(raw).includes('"payload":"AA"');
  return JSON.stringify({schema: "evd/browser-bundle-verification-result/v3", verdict: valid ? "VERIFIED" : "NOT_VERIFIED",
    bundle_digest: valid ? "a".repeat(64) : null, error: null,
    continuity: valid ? {present: false, ok: false, gaps: 0} : null});
}, () => {throw new Error("unexpected dispute input");}, message => {throw new Error(message);});
assert.equal(presentation.show(currentText, currentBytes), true);
assert.equal(presentation.show(currentText, currentBytes), true);
assert.strictEqual(inputs[0], uploaded);
assert.strictEqual(inputs[1], uploaded, "policy re-verification must preserve uploaded bytes");
presentation.tamper(currentText, text => {
  currentText = text;
  currentBytes = encoder.encode(text);
  assert.equal(presentation.show(currentText, currentBytes), false);
});
const verifierInput = inputs.at(-1);
assert.notStrictEqual(verifierInput, uploaded, "deliberate mutation must allocate new bytes");
assert.notDeepEqual(verifierInput, uploaded, "deliberate mutation must change verifier input");
assert.deepEqual(verifierInput, encoder.encode(currentText));
assert.equal(JSON.parse(currentText).entries[0].envelope.payload, "BA");
assert.equal(ui.bundleDigest.hidden, true, "refusal must clear the previous digest");

console.log("browser page preserves uploaded bytes across policy re-verification and re-encodes deliberate mutations");
