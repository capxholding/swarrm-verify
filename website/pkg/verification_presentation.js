// Apache-2.0 (public verifier repo)
// Shared, integrity-pinned verdict presentation. Verification stays in WASM.
const KNOWN_SCHEMA = "evd/bundle/v1";
const VERIFICATION_RESULT_SCHEMA = "evd/browser-bundle-verification-result/v3";

function validContinuityResult(verdict, continuity) {
  return verdict === "VERIFIED"
    ? continuity && !Array.isArray(continuity) &&
      Object.keys(continuity).sort().join(",") === "gaps,ok,present" &&
      typeof continuity.present === "boolean" && typeof continuity.ok === "boolean" &&
      Number.isSafeInteger(continuity.gaps) && continuity.gaps >= 0
    : continuity === null;
}

function parseVerificationResult(raw) {
  const parsed = JSON.parse(raw);
  const fields = parsed && !Array.isArray(parsed) ? Object.keys(parsed).sort().join(",") : "";
  const digestIsValid = parsed?.verdict === "VERIFIED"
    ? /^[0-9a-f]{64}$/.test(parsed.bundle_digest)
    : parsed?.bundle_digest === null;
  const errorIsValid = parsed?.verdict === "ERROR"
    ? typeof parsed.error === "string" && parsed.error.length > 0
    : parsed?.error === null;
  if (fields !== "bundle_digest,continuity,error,schema,verdict" ||
      parsed.schema !== VERIFICATION_RESULT_SCHEMA || !["VERIFIED", "NOT_VERIFIED", "ERROR"].includes(parsed.verdict) ||
      !digestIsValid || !errorIsValid || !validContinuityResult(parsed.verdict, parsed.continuity)) throw new Error("incompatible verifier result");
  return parsed;
}

function bundleSummary(bundle, r, manifestAbsent, passed, requireManifest) {
  if (!passed) return requireManifest.checked && manifestAbsent
    ? "this relying party requires a signed export manifest; this bundle makes no completeness claim."
    : r.error || "at least one tamper-evidence check failed for this bundle as presented.";
  const completeness = manifestAbsent
    ? " Export completeness is UNPROVEN: no signed export manifest."
    : " Signed export manifest confirms the carried receipt set.";
  const checkpointScope = bundle.checkpoint_chain_profile === "evd/checkpoint-chain/sparse-proof-v1"
    ? " Sparse signed-checkpoint proof checked; intermediate checkpoint history was not carried."
    : " Complete checkpoint chain checked.";
  const prefix = "Tamper-evident presented history (E1): signed receipts, key-log replay and Merkle proofs checked. Anchor and timestamp fields remain recorded claims; use the online CLI --live check for independent chain confirmation." + checkpointScope + completeness;
  if (!r.continuity.ok) return prefix + " Continuity assertions are invalid or leave unexplained intervals; the presented cover is not established.";
  if (!r.continuity.present) return prefix + " No continuity assertions were supplied; no completeness claim is established.";
  return prefix + " Signed continuity assertions cover the presented checkpoint intervals. This does not establish capture or export completeness.";
}

const isDisputeObject = value => value && typeof value === "object" && !Array.isArray(value);
const disputeObjectKeys = value => isDisputeObject(value) ? Object.keys(value).sort().join(",") : "";
function checkDisputeFacts({package_digest, reconciliation: r}) {
  if (!/^[0-9a-f]{64}$/.test(package_digest) ||
      disputeObjectKeys(r) !== "claims,parties,schema,scope,summary" ||
      r.schema !== "evd/two-party-reconciliation/v1" || typeof r.scope !== "string" || !r.scope ||
      !Array.isArray(r.claims) || !isDisputeObject(r.parties) ||
      Object.keys(r.parties).length !== 2 || disputeObjectKeys(r.summary) !== "AGREEMENT,CONFLICT,UNSUPPORTED,contested" ||
      !Object.values(r.summary).every(value => Number.isSafeInteger(value) && value >= 0)) throw new Error("incompatible dispute facts");
}
function parseDisputeResult(raw) {
  const parsed = JSON.parse(raw);
  if (disputeObjectKeys(parsed) !== "package_digest,reconciliation,schema,verdict" ||
      parsed.schema !== "evd/dispute-verification-result/v1" ||
      !["VERIFIED", "NOT_VERIFIED"].includes(parsed.verdict)) throw new Error("incompatible dispute result");
  if (parsed.verdict === "NOT_VERIFIED" && (parsed.reconciliation !== null || parsed.package_digest !== null)) throw new Error("refusal carries unverified facts");
  if (parsed.verdict === "VERIFIED") checkDisputeFacts(parsed);
  return parsed;
}

// Load only the exact bytes admitted by the page's pinned-asset boundary.
export async function loadVerifier(base, pins, fetchPinnedAsset, importVerifiedModule, extraExports = []) {
  const moduleAsset = await fetchPinnedAsset(new URL("swarrm_verify.js", base), pins.module, "verifier module");
  const mod = await importVerifiedModule(moduleAsset.bytes);
  const required = ["default", "verify_bundle_json", "verify_dispute_json", "verify_acknowledgement_json", ...extraExports];
  if (required.some(name => typeof mod[name] !== "function")) {
    throw new Error("verifier module exports are invalid");
  }
  const wasmAsset = await fetchPinnedAsset(new URL("swarrm_verify_bg.wasm", base), pins.wasm, "verifier WASM");
  // Never give wasm-bindgen a mutable URL to fetch after hash admission.
  await mod.default({ module_or_path: wasmAsset.bytes });
  return { mod, wasmAsset };
}

export function createPresentation(elements, verifyBundleJson, verifyDisputeJson, rejectInput) {
  const {controls, flip, verdict, detail, bundleDigest, disputeFacts, requireManifest} = elements;
  function showDispute(packageValue, raw) {
    flip.hidden = true;
    if (typeof verifyDisputeJson !== "function") {
      rejectInput("The loaded verifier does not support complete dispute packages. No dispute was verified.");
      return;
    }
    let r;
    try { r = parseDisputeResult(verifyDisputeJson(raw)); }
    catch { rejectInput("The verifier returned an incompatible dispute result and was refused."); return; }
    const manifestsPresent = packageValue.bundles && Object.values(packageValue.bundles).length === 2 &&
      Object.values(packageValue.bundles).every(bundle => bundle && bundle.export_manifest != null);
    const passed = r.verdict === "VERIFIED" && (!requireManifest.checked || manifestsPresent);
    verdict.className = passed ? "ok" : "bad";
    verdict.textContent = passed ? "DISPUTE PACKAGE: VERIFIED" : "DISPUTE PACKAGE: NOT VERIFIED";
    if (!passed) {
      detail.textContent = r.verdict === "VERIFIED"
        ? "This relying party requires a signed export manifest from both parties."
        : "The carried bundles or reconciliation do not verify as a complete dispute package.";
      return;
    }
    detail.textContent = r.reconciliation.scope + " Labels identify the presented parties; they are not independently authenticated legal identities.";
    bundleDigest.textContent = "Dispute package SHA-256 (JCS): " + r.package_digest;
    bundleDigest.hidden = false;
    disputeFacts.textContent = JSON.stringify(r.reconciliation, null, 2);
    disputeFacts.hidden = false;
  }

  function clearBundleDigest() {
    bundleDigest.textContent = "";
    bundleDigest.hidden = true;
    disputeFacts.textContent = "";
    disputeFacts.hidden = true;
    flip.hidden = false;
  }

  function show(text, raw) {
    clearBundleDigest();
    controls.style.display = "block";
    let bundle;
    try { bundle = JSON.parse(text); }
    catch { rejectInput("That file is not valid JSON."); return false; }
    if (bundle?.schema === "evd/dispute-artifact/v1") { showDispute(bundle, raw); return false; }
    if (bundle?.schema !== KNOWN_SCHEMA) { rejectInput("unknown bundle schema; this verifier understands " + KNOWN_SCHEMA); return false; }
    let r;
    try { r = parseVerificationResult(verifyBundleJson(raw)); }
    catch { rejectInput("The verifier returned an incompatible result and was refused."); return false; }
    const manifestAbsent = bundle.export_manifest == null;
    const passed = r.verdict === "VERIFIED" && !(requireManifest.checked && manifestAbsent);
    verdict.textContent = "VERDICT: " + (passed ? "VERIFIED" : "NOT VERIFIED");
    verdict.className = passed ? "ok" : "bad";
    detail.textContent = bundleSummary(bundle, r, manifestAbsent, passed, requireManifest);
    if (passed) {
      bundleDigest.textContent = "Bundle " + r.bundle_digest.slice(0, 8) + "… — cite this evidence bundle by SHA-256 (JCS): " + r.bundle_digest;
      bundleDigest.hidden = false;
    }
    return passed;
  }
  async function readFileBounded(file, maximum) {
    if (!file || file.size > maximum) throw new Error("bundle exceeds the 64 MiB browser limit");
    return new Uint8Array(await file.arrayBuffer());
  }
  let inputGeneration = 0;
  async function readInput(read, consume, failureMessage = null) {
    const generation = ++inputGeneration;
    rejectInput("Reading selected evidence; no result is available yet.");
    verdict.className = "";
    verdict.textContent = "READING EVIDENCE";
    try {
      const bytes = await read();
      if (generation === inputGeneration) consume(bytes);
    } catch (error) {
      if (generation === inputGeneration) rejectInput(failureMessage || String(error.message || error));
    }
  }
  function tamper(text, consume) {
    if (!text) return;
    let bundle;
    try { bundle = JSON.parse(text); }
    catch { rejectInput("The demo needs a valid JSON bundle; no evidence was changed."); return; }
    const entry = bundle?.entries?.[0]?.envelope;
    if (typeof entry?.payload !== "string" || !entry.payload.length) {
      rejectInput("The demo needs a receipt payload; no evidence was changed."); return;
    }
    entry.payload = (entry.payload[0] === "A" ? "B" : "A") + entry.payload.slice(1);
    consume(JSON.stringify(bundle));
    detail.textContent += " Demo: one receipt payload was changed locally.";
  }
  return {show, clearBundleDigest, readFileBounded, readInput, tamper};
}
