// Apache-2.0
// Fail closed if a page edit silently reintroduces text re-encoding between an
// upload and a relying-party-policy re-verification.
import assert from "node:assert/strict";
import fs from "node:fs";

const pageFile = process.argv[2] ?? new URL("../verify-rs/web/index.html", import.meta.url);
const page = fs.readFileSync(pageFile, "utf8");
const required = [
  /let currentText = null;\s+let currentBytes = null;/,
  /function rejectInput\(message\) \{\s+currentText = null;\s+currentBytes = null;/,
  /const text = utf8Decoder\.decode\(raw\);\s+currentText = text;\s+currentBytes = raw;\s+show\(text, raw\);/,
  /requireManifest\.onchange = \(\) => \{ if \(currentText\) show\(currentText, currentBytes\); \};/,
  /currentText = currentText\.slice\(0, j\) \+ c \+ currentText\.slice\(j \+ 1\);\s+currentBytes = utf8Encoder\.encode\(currentText\);\s+show\(currentText, currentBytes\);/,
];
for (const [index, contract] of required.entries()) {
  if (!contract.test(page)) throw new Error(`browser page raw-byte contract ${index + 1} is missing`);
}

// Exercise the state contract pinned above: policy-only re-verification gets
// the exact uploaded object, while an intentional mutation receives newly
// encoded bytes and cannot reuse the original byte string.
const uploaded = Uint8Array.from([0x7b, 0x22, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0x3a, 0x22, 0x41, 0x41, 0x22, 0x7d]);
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
let currentText = decoder.decode(uploaded);
let currentBytes = uploaded;
let verifierInput = currentBytes;
assert.strictEqual(verifierInput, uploaded, "checkbox re-verification must preserve uploaded bytes");

const index = currentText.indexOf("AA");
assert.notEqual(index, -1);
currentText = `${currentText.slice(0, index)}BA${currentText.slice(index + 2)}`;
currentBytes = encoder.encode(currentText);
verifierInput = currentBytes;
assert.notStrictEqual(verifierInput, uploaded, "deliberate mutation must allocate new bytes");
assert.notDeepEqual(verifierInput, uploaded, "deliberate mutation must change verifier input");
assert.deepEqual(verifierInput, encoder.encode(currentText));

console.log("browser page preserves uploaded bytes across policy re-verification and re-encodes deliberate mutations");
