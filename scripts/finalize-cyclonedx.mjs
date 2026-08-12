// Apache-2.0
// cargo-cyclonedx emits a valid CycloneDX document without serialNumber, while
// actions/attest requires bomFormat + specVersion + serialNumber to recognize
// the format. Add a deterministic RFC 4122 UUIDv5 before validation/signing.
import crypto from "node:crypto";
import fs from "node:fs";

const [file, repository, commit, version] = process.argv.slice(2);
if (!file || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository ?? "") ||
    !/^[0-9a-f]{40}$/.test(commit ?? "") || !/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  throw new Error("usage: finalize-cyclonedx.mjs FILE OWNER/REPO COMMIT VERSION");
}

const bom = JSON.parse(fs.readFileSync(file, "utf8"));
if (bom?.bomFormat !== "CycloneDX" || typeof bom.specVersion !== "string" ||
    !Number.isSafeInteger(bom.version) || bom.version < 1 ||
    bom?.metadata?.component?.name !== "swarrm-verify" ||
    bom?.metadata?.component?.version !== version) {
  throw new Error("unexpected CycloneDX release document");
}

const namespace = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex"); // RFC 4122 URL namespace
const name = Buffer.from(`https://github.com/${repository}@${commit}#swarrm-verify-${version}`, "utf8");
const uuid = crypto.createHash("sha1").update(namespace).update(name).digest().subarray(0, 16);
uuid[6] = (uuid[6] & 0x0f) | 0x50;
uuid[8] = (uuid[8] & 0x3f) | 0x80;
const hex = uuid.toString("hex");
const serialNumber = `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

if (bom.serialNumber != null && bom.serialNumber !== serialNumber) {
  throw new Error("CycloneDX serialNumber does not match the deterministic release identity");
}
bom.serialNumber = serialNumber;
fs.writeFileSync(file, `${JSON.stringify(bom, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
console.log(serialNumber);
