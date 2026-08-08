// Apache-2.0 (public verifier repo)
//! Verdict engine for verified-action-v1: `derive_vector` maps an
//! evd/verdict-input/v1 document to an evd/verdict-vector/v1, and
//! `authority_facts` replays an evd/bundle/v1 into the authority facts
//! block (SPEC/authority-v1.md §4–§7). Mirrors verify/action.py exactly —
//! field for field, weak value for weak value.
//!
//! Weak-claim doctrine: both functions are TOTAL — malformed or missing
//! input degrades to the weak value, never panics.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{body_of, checkpoint_body_hash, ed25519_verify, hex, jcs, key_from_jwk, receipt_hash_hex, replay_key_log, sha256, verify_bundle};

const ID_VALS: [&str; 3] = ["VERIFIED", "NOT_VERIFIED", "CONFLICT"];
const INTENT_VALS: [&str; 3] = ["RECORDED", "NOT_RECORDED", "CONFLICT"];
const KP_METHODS: [&str; 3] = ["DOMAIN_CONTROL", "TRUST_LIST", "EXTERNAL_CA"];
const NODE_BASES: [&str; 3] = ["HARDWARE_ATTESTED", "INDEPENDENTLY_ATTESTED", "LOG_WITNESSED_SOFTWARE"];
const LEGAL: [&str; 5] = ["source_registry", "registry_id", "ultimate_controller", "retrieved_at", "retrieval_proof"];
const POP: [&str; 8] = ["dense_seq_range", "tree_size", "checkpoint_ref", "consistency_proof_ref", "query_descriptor", "result_root", "count", "signature"];
const GATED: [&str; 11] = ["identity", "authority", "intent", "integrity", "linkage", "outcome", "coverage", "coverage_basis", "temporal_binding", "fork_findings", "scitt_receipt"];
const INTENT_CTX: [&str; 6] = ["action_id", "action_class", "grant_id", "grant_version", "binding_id", "policy_version"];
const EST_TYPES: [&str; 2] = ["lineage.born", "lineage.adopted"];
const ELIGIBLE_EXACT: [(&str, &str); 6] = [("identity", "VERIFIED"), ("authority", "VERIFIED"), ("intent", "RECORDED"), ("integrity", "VALID"), ("outcome", "CORROBORATED"), ("coverage", "CLOSED")];
const MAX_SOURCE_PROOFS: usize = 128;
const MAX_VERDICT_INPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_TRUST_CONTEXT_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------- utilities

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str())
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[])
}

fn obj<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k).filter(|x| x.is_object())
}

/// `container.get(key)` with Python semantics: a missing key IS null.
fn g(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or(Value::Null)
}

/// Python truthiness of an optional JSON value. Shared with the certificate
/// layer, which needs the same rule for `verdict_input`'s Python `or []`.
pub(crate) fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::String(x)) => !x.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
    }
}

fn nonempty(v: &Value, k: &str) -> bool {
    truthy(v.get(k))
}

/// Normalize canonical RFC 3339 UTC — fraction padded to six digits so values
/// compare lexicographically. The shared parser owns the Gregorian calendar
/// and exact Z/fraction grammar for both verifier layers.
pub(crate) fn nts(t: &Value) -> Option<String> {
    let t = t.as_str()?;
    if !crate::canonical_utc(t) {
        return None;
    }
    let base = &t[..t.len() - 1];
    let (whole, frac) = base.split_once('.').unwrap_or((base, ""));
    Some(format!("{}.{:0<6}Z", whole, frac))
}

/// strong value if `a`, else mid value if `b`, else the weak value.
fn tri<'a>(a: bool, av: &'a str, b: bool, bv: &'a str, weak: &'a str) -> &'a str {
    if a {
        av
    } else if b {
        bv
    } else {
        weak
    }
}

/// Marker for the cases where the Python engine raises internally and its
/// top-level handler returns the fully weak vector.
struct Raise;

/// Python's `container.get(key) or []` followed by iteration: falsy → empty,
/// list → items, string → characters, dict → keys, other truthy → raises.
fn iter_items(v: Option<&Value>) -> Result<Vec<Value>, Raise> {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(vec![]),
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => Ok(vec![]),
        Some(Value::String(x)) => Ok(x.chars().map(|c| Value::String(c.to_string())).collect()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(Value::Object(m)) => Ok(m.keys().map(|k| Value::String(k.clone())).collect()),
        _ => Err(Raise), // a truthy non-iterable
    }
}

/// Python `repr()` of a JSON value (containers as Python literals).
fn py_repr(v: &Value) -> String {
    match v {
        Value::Null => "None".to_string(),
        Value::Bool(b) => tri(*b, "True", true, "False", "").to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(x) => format!("'{}'", x.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Array(a) => {
            format!("[{}]", a.iter().map(py_repr).collect::<Vec<_>>().join(", "))
        }
        Value::Object(m) => {
            let body: Vec<String> = m.iter().map(|(k, x)| format!("'{}': {}", k, py_repr(x))).collect();
            format!("{{{}}}", body.join(", "))
        }
    }
}

/// Python `str(container.get(key, default))`.
fn py_str(v: Option<&Value>, default: &str) -> String {
    match v {
        None => default.to_string(),
        Some(Value::String(x)) => x.clone(),
        Some(other) => py_repr(other),
    }
}

// ------------------------------------------------ derive_vector (§2.2–2.15)

fn authority_block(vi: &Value) -> (Value, Value) {
    // -> (echoed authority block, {identity, authority, intent, integrity, interval})
    let a = g(vi, "authority");
    let integ = tri(matches!(s(&a, "integrity"), Some("VALID")), "VALID", true, "INVALID", "");
    let pick = |name: &str, allowed: &[&str], weak: &'static str| -> String {
        match s(&a, name) {
            Some(v) if integ == "VALID" && allowed.contains(&v) => v.to_string(),
            _ => weak.to_string(),
        }
    };
    let ii = g(&a, "intent_interval");
    let derived = json!({
        "identity": pick("identity", &ID_VALS, "NOT_VERIFIED"),
        "authority": pick("authority", &ID_VALS, "NOT_VERIFIED"),
        "intent": pick("intent", &INTENT_VALS, "NOT_RECORDED"),
        "integrity": integ,
        "intent_interval": {"lower": g(&ii, "lower"), "upper": g(&ii, "upper")},
    });
    (a, derived)
}

fn bound_source_keys(si: &Value) -> Result<Vec<Value>, Raise> {
    let keys = iter_items(if si.is_object() { si.get("keys") } else { None })?;
    for k in keys.iter().filter(|k| k.is_object()) {
        let kid = g(k, "kid");
        if kid.is_array() || kid.is_object() {
            return Err(Raise); // an unhashable kid cannot enter Python's set
        }
    }
    Ok(keys)
}

fn bound_source_key<'a>(keys: &'a [Value], kid: Option<&str>) -> Option<&'a Value> {
    let mut matches = keys.iter().filter(|key| key.is_object() && s(key, "kid") == kid);
    let first = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn bounded_source_proofs(vi: &Value) -> Option<&[Value]> {
    let Some(value) = vi.get("source_proofs") else { return Some(&[]) };
    let proofs = value.as_array()?;
    if proofs.len() > MAX_SOURCE_PROOFS {
        return None;
    }
    let mut total = 0usize;
    for proof in proofs {
        total = total.checked_add(source_proof_material_size(proof)?)?;
        if total > crate::trust::MAX_SOURCE_PROOF_TOTAL_BYTES {
            return None;
        }
    }
    Some(proofs)
}

fn source_proof_material_size(proof: &Value) -> Option<usize> {
    if !proof.is_object() {
        return Some(0);
    }
    let material = proof.get("material");
    let context = proof.get("signature_context");
    if material.is_none() && context.is_none() {
        return Some(0);
    }
    let attributive = matches!(s(proof, "proof_type"), Some("asymmetric_signature" | "mac"));
    if attributive && (material.is_none() || context.and_then(Value::as_str) != Some(crate::trust::SOURCE_WEBHOOK_SIGNATURE_CONTEXT)) {
        return None;
    }
    let text = material?.as_str()?;
    let decoded = B64.decode(text).ok()?;
    (B64.encode(&decoded) == text && decoded.len() <= crate::trust::MAX_SOURCE_PROOF_MATERIAL_BYTES).then_some(decoded.len())
}

/// Is `field` named in THIS view's withheld set? Shared by the per-view
/// renderings (source_signature, mark) so they agree on what "withheld" means.
fn field_withheld(vi: &Value, field: &str) -> Result<bool, Raise> {
    let view = g(vi, "view");
    let withheld = iter_items(if view.is_object() { view.get("withheld_fields") } else { None })?;
    Ok(withheld.iter().any(|w| py_str(Some(w), "") == field))
}

fn source_signature(vi: &Value, trust: Option<&Value>) -> Result<&'static str, Raise> {
    // The producer's `verified: true` is IGNORED — it is a declaration.
    // ASYMMETRIC requires a signature verifying under a key THIS RELYING PARTY
    // named, and the key must also be pre-bound in SourceIdentity.
    // Per-view, like the mark: a view that WITHHOLDS the source proof cannot
    // recompute it, and NONE there would claim the source did not sign.
    if field_withheld(vi, "source_proofs")? {
        return Ok("NOT_RECOMPUTED");
    }
    let keys = bound_source_keys(&g(vi, "source_identity"))?;
    let Some(proofs) = bounded_source_proofs(vi) else { return Ok("NONE") };
    let mut has_mac = false;
    for p in proofs {
        let kind = source_proof_kind(p, &keys, trust);
        if kind == "ASYMMETRIC" {
            return Ok("ASYMMETRIC");
        }
        has_mac = has_mac || kind == "MAC";
    }
    Ok(tri(has_mac, "SHARED_SECRET", false, "", "NONE")) // possession by SOME holder
}

fn source_proof_kind(p: &Value, keys: &[Value], trust: Option<&Value>) -> &'static str {
    if !p.is_object() {
        return "NOTHING";
    }
    let kid = s(p, "key_identity");
    let key = bound_source_key(keys, kid);
    if p.get("material").is_some() || p.get("signature_context").is_some() {
        return full_source_proof_kind(p, key, kid, trust);
    }
    legacy_source_proof_kind(p, key, kid, trust)
}

fn full_source_proof_kind(p: &Value, key: Option<&Value>, kid: Option<&str>, trust: Option<&Value>) -> &'static str {
    let family = key.and_then(|entry| s(entry, "algorithm_family"));
    if key.is_none() || !crate::trust::source_webhook_verified(trust, kid, family, p) {
        return "NOTHING";
    }
    tri(s(p, "proof_type") == Some("asymmetric_signature"), "ASYMMETRIC", true, "MAC", "")
}

fn legacy_source_proof_kind(p: &Value, key: Option<&Value>, kid: Option<&str>, trust: Option<&Value>) -> &'static str {
    if s(p, "proof_type") == Some("asymmetric_signature") && key.is_some() && crate::trust::verified(trust, "source_keys", kid, "source-proof", p) {
        return "ASYMMETRIC";
    }
    if s(p, "proof_type") == Some("mac") && crate::trust::mac_verified(trust, kid, "source-proof", p) {
        return "MAC";
    }
    "NOTHING"
}

/// (source controller, operator controller) iff evidence complete (2.3).
fn grounded_controllers(ev: &Value) -> Option<(Value, Value)> {
    let le = g(ev, "legal_evidence");
    let kp = g(ev, "key_provenance");
    let method_ok = s(&kp, "method").map(|m| KP_METHODS.contains(&m)).unwrap_or(false);
    let ok = LEGAL.iter().all(|f| nonempty(&le, f)) && method_ok;
    let ok = ok && nonempty(&kp, "evidence") && nonempty(&kp, "valid_from");
    if ok && nonempty(ev, "evaluator") && nonempty(ev, "signature") {
        return Some((g(&le, "ultimate_controller"), g(ev, "operator_ultimate_controller")));
    }
    None
}

fn control_domain(vi: &Value, trust: Option<&Value>) -> Result<&'static str, Raise> {
    let ev = g(vi, "control_evidence");
    let decls = iter_items(vi.get("control_declarations"))?;
    let mut admits = decls.iter().any(|d| d.get("claims_overlap") == Some(&Value::Bool(true)));
    admits = admits || s(&ev, "claimed_control_domain") == Some("OVERLAPPING");
    let grounded = if ev.as_object().map(|m| !m.is_empty()).unwrap_or(false) { grounded_controllers(&ev) } else { None };
    let shared = matches!(&grounded, Some((a, b)) if a == b);
    // An admission of overlap is against interest -> believed without proof.
    // INDEPENDENT is favourable -> the evaluator signature must verify.
    let evaluator_ok = crate::trust::verified(trust, "evaluator_keys", s(&ev, "evaluator"), "control-evidence", &ev);
    Ok(tri(admits || shared, "OVERLAPPING", grounded.is_some() && evaluator_ok, "INDEPENDENT", "UNKNOWN"))
}

/// True iff the signed scan statement is ABOUT this verdict input's batch.
/// The digest binds source, cursor, event root, gaps and a valid ordered period;
/// a missing/malformed digest binds nothing and therefore proves no observation.
fn scan_binds_batch(vi: &Value, scan: &Value) -> bool {
    let Some(declared) = s(scan, "batch_digest").filter(|d| !d.is_empty()) else { return false };
    let Some(batch) = obj(vi, "batch") else { return false };
    let (start, end) = (nts(&g(batch, "period_start")), nts(&g(batch, "period_end")));
    if !matches!((start, end), (Some(start), Some(end)) if start < end) {
        return false;
    }
    let Some(canon) = jcs::canonical_checked(batch) else { return false };
    declared == hex(&sha256(&canon))
}

fn node_dims(vi: &Value, trust: Option<&Value>) -> (&'static str, &'static str, &'static str) {
    let scan = g(vi, "scan");
    let att = g(vi, "node_attestation");
    let observed = flag(&scan, "performed") && flag(&scan, "authenticated_read") && scan_binds_batch(vi, &scan) && crate::trust::verified(trust, "node_keys", s(&scan, "node_id"), "node-scan", &scan);
    let att_ok = crate::trust::verified(trust, "node_roots", s(&att, "attestor"), "node-attestation", &att) && s(&att, "state") == Some("ISSUED") && s(&att, "method").map(|m| NODE_BASES.contains(&m)).unwrap_or(false) && nts(&g(&att, "valid_from")).is_some() && nts(&g(&att, "valid_to")).is_some();
    let basis = match s(&att, "method") {
        Some("HARDWARE_ATTESTED") if att_ok => "HARDWARE_ATTESTED",
        Some("INDEPENDENTLY_ATTESTED") if att_ok => "INDEPENDENTLY_ATTESTED",
        _ => "LOG_WITNESSED_SOFTWARE",
    };
    // ATTESTED used to come from the boolean alone, with no attestation
    // artifact anywhere — the same declaration-vs-proof mistake `node_signed`
    // made one line up. It is only worth the word if the Node signed what it saw.
    let client = tri(flag(vi, "client_attestation_present") && observed, "ATTESTED", false, "", "NONE");
    (tri(observed, "OBSERVED", false, "", "NOT_OBSERVED"), client, basis)
}

fn full_scan(scan: &Value, observed: bool) -> bool {
    flag(scan, "performed") && flag(scan, "complete") && flag(scan, "cursor_gap_free") && observed
}

fn coverage(vi: &Value, node_basis: &str, node_observed: bool, trust: Option<&Value>) -> (&'static str, &'static str) {
    let batch = g(vi, "batch");
    let scan = g(vi, "scan");
    let pp = g(&batch, "population_proof");
    let full_scan = full_scan(&scan, node_observed);
    let pp_ok = flag(&pp, "source_scope_defined") && crate::trust::verified(trust, "population_keys", s(&pp, "source_id"), "population-proof", &pp);
    let basis = if pp_ok {
        "SOURCE_PROVEN_POPULATION" // the source proves a scope IT defines
    } else if full_scan && node_basis == "HARDWARE_ATTESTED" {
        "ATTESTED_NODE_FULL_SCAN" // only a hardware Node is a witness (2.5)
    } else {
        "INSUFFICIENT"
    };
    let mut gapped = nonempty(&batch, "gaps") || flag(vi, "fork_findings_open");
    gapped = gapped || (flag(&scan, "performed") && scan.get("cursor_gap_free") == Some(&Value::Bool(false)));
    gapped = gapped || has_open_finding(vi); // an open finding contradicts CLOSED
    if gapped {
        return ("GAPPED", basis);
    }
    (tri(basis != "INSUFFICIENT", "CLOSED", false, "", "UNKNOWN"), basis)
}

fn match_candidates(vi: &Value) -> Result<Vec<Value>, Raise> {
    let keys = ["echoed_action_id", "immutable_ref_match", "unique_field_match"];
    Ok(iter_items(vi.get("event_matches"))?.into_iter().filter(|m| m.is_object() && keys.iter().any(|k| flag(m, k))).collect())
}

/// Any unresolved finding contradicts a claim of complete coverage.
///
/// A container this cannot read is NOT an absence of findings; it is a
/// coverage question it cannot answer, and the weaker answer is `open`. The
/// same OPEN CRITICAL finding reached CLOSED/ELIGIBLE as a keyed map, as a
/// nested list, and as a JSON string.
fn has_open_finding(vi: &Value) -> bool {
    let Some(field) = vi.get("findings").filter(|f| !f.is_null()) else { return false };
    let Some(items) = field.as_array() else { return true };
    items.iter().any(|f| !f.is_object() || !matches!(s(f, "state").unwrap_or("OPEN").to_ascii_uppercase().as_str(), "RESOLVED" | "CLOSED" | "DISMISSED"))
}

/// The NORMATIVE material floor (SPEC/reconcile-v1.md §5). A producer-named
/// list extends it and may never retract it: the lying-agent fixture
/// (tests/golden/reconcile/lying_agent_value_flip.json, claim 999999.99 vs
/// event 380.99) one added key — source_manifest.material_fields=["currency"] —
/// REPLACED the trio and flipped both engines CONTRADICTED → CORROBORATED.
/// Spelling and order are pinned to verify/action.py::MATERIAL_FLOOR.
pub(crate) const MATERIAL_FLOOR: [&str; 3] = ["value", "currency", "counterparty"];

/// The declared members of AgentActionClaim and SourceEvent
/// (SPEC/cddl/verified-action-v1.cddl) minus the floor — the names a
/// disagreement proves nothing about. `schema` is here because it disagrees on
/// every HONEST pair ("evd/claim/v1" vs "evd/source-event/v1"), so comparing it
/// would flag all nine golden families.
const STRUCTURAL_FIELDS: [&str; 13] = ["action_class", "action_id", "context_commitment", "event_key", "external_ref", "finality", "inputs_commitment", "outcome", "proof_digests", "reference", "schema", "source_effect_time", "source_identity_ref"];

/// The floor, then the producer's additions in the producer's own order.
fn material_fields(vi: &Value) -> Vec<String> {
    let mut fields: Vec<String> = MATERIAL_FLOOR.iter().map(|f| f.to_string()).collect();
    for f in arr(&g(vi, "source_manifest"), "material_fields") {
        let name = f.as_str().map(str::to_string).unwrap_or_else(|| f.to_string());
        if !fields.contains(&name) {
            fields.push(name);
        }
    }
    fields
}

fn field_text(v: &Value, f: &str) -> Option<String> {
    match v.get(f) {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) => Some(t.trim().to_string()),
        Some(other) => Some(other.to_string()),
    }
}

/// (agreements, any mismatch, any one-sided) over EVERY effective field.
///
/// Nothing returns early. Stopping at the first one-sided field let a producer
/// append a field the event does not carry and hide a real `value` disagreement
/// two positions later behind an UNCOMPARABLE — softening CONTRADICTED to
/// CLAIM_ONLY, which SPEC/reconcile-v1.md §5 forbids ("any material
/// disagreement → CONTRADICTED, regardless"). It is also a parity hazard: with
/// the list a UNION, an early return makes the answer depend on iteration order.
fn declared_tally(claim: &Value, event: &Value, fields: &[String]) -> (usize, bool, bool) {
    let (mut compared, mut mismatch, mut uncomparable) = (0, false, false);
    for f in fields {
        match (field_text(claim, f), field_text(event, f)) {
            (None, None) => continue, // not a field this action class carries
            (Some(a), Some(b)) if a == b => compared += 1,
            (Some(_), Some(_)) => mismatch = true,
            _ => uncomparable = true, // one side asserts what the other cannot confirm
        }
    }
    (compared, mismatch, uncomparable)
}

/// A field nobody declared, disagreeing on both sides (the beneficiary_iban
/// class of lie). In production it is material by construction —
/// node/reconcile.py::_attach_material_fields copies the manifest's named
/// fields onto the claim — so it may not corroborate. It may not accuse either:
/// a bare collision between two independently authored vocabularies is
/// possible, and CONTRADICTED is terminal and never softened.
fn undeclared_disagreement(claim: &Value, event: &Value, fields: &[String]) -> bool {
    let Some(members) = claim.as_object() else { return false };
    members.keys().any(|f| !STRUCTURAL_FIELDS.contains(&f.as_str()) && !fields.iter().any(|d| d == f) && matches!((field_text(claim, f), field_text(event, f)), (Some(a), Some(b)) if a != b))
}

/// AGREE / MISMATCH / UNCOMPARABLE. `material_mismatch` is honoured only when
/// TRUE (an adverse admission); a favourable `false` is not evidence.
/// UNCOMPARABLE can never corroborate — you cannot confirm an amount you were
/// never shown. MISMATCH dominates it.
fn material_agreement(vi: &Value, cand: &Value) -> &'static str {
    if flag(cand, "material_mismatch") {
        return "MISMATCH";
    }
    let claim = g(vi, "claim");
    let key = s(cand, "event_key");
    let events = vi.get("events").and_then(|e| e.as_array()).cloned().unwrap_or_default();
    let Some(event) = events.iter().find(|e| e.is_object() && s(e, "event_key") == key) else { return "UNCOMPARABLE" };
    let fields = material_fields(vi);
    let (compared, mismatch, uncomparable) = declared_tally(&claim, event, &fields);
    if mismatch {
        return "MISMATCH";
    }
    if uncomparable || compared == 0 || undeclared_disagreement(&claim, event, &fields) {
        return "UNCOMPARABLE";
    }
    "AGREE"
}

fn linkage_outcome(vi: &Value) -> Result<(&'static str, Value), Raise> {
    let cands = match_candidates(vi)?;
    let linkage = match cands.len() {
        0 => "NONE",
        1 if flag(&cands[0], "echoed_action_id") => "DIRECT",
        1 => "DETERMINISTIC",
        _ => "AMBIGUOUS", // the verifier never picks a winner
    };
    if obj(vi, "claim").is_none() {
        // null iff neither claim nor event; an unclaimed event is an ORPHAN
        let orphan = truthy(vi.get("events"));
        return Ok((linkage, if orphan { json!("ORPHAN") } else { Value::Null }));
    }
    if linkage == "DIRECT" || linkage == "DETERMINISTIC" {
        match material_agreement(vi, &cands[0]) {
            "MISMATCH" => return Ok((linkage, json!("CONTRADICTED"))), // terminal
            "AGREE" if flag(&cands[0], "final") => return Ok((linkage, json!("CORROBORATED"))),
            _ => {}
        }
    }
    Ok((linkage, json!("CLAIM_ONLY")))
}

fn temporal(vi: &Value, trust: Option<&Value>) -> &'static str {
    let Some(t) = obj(vi, "temporal") else { return "UNPROVEN" };
    let echo = g(t, "echo");
    let echoed = ["echoed_intent_digest", "echoed_action_id", "echoed_nonce"];
    if echoed.iter().any(|k| flag(&echo, k)) && crate::trust::verified(trust, "source_keys", s(&echo, "source_id"), "temporal-echo", &echo) {
        return "PROVEN_SOURCE_ECHO"; // the effect causally embeds the intent
    }
    let ib = g(t, "intent_bounds");
    let eb = g(t, "event_bounds");
    if crate::trust::verified(trust, "temporal_keys", s(&ib, "attester"), "temporal-bounds", &ib) && crate::trust::verified(trust, "temporal_keys", s(&eb, "attester"), "temporal-bounds", &eb) {
        if let (Some(iu), Some(el)) = (nts(&g(&ib, "upper")), nts(&g(&eb, "lower"))) {
            if iu < el {
                return "PROVEN_INDEPENDENT";
            }
        }
    }
    "UNPROVEN" // incl. declared clock sync — those clocks are incomparable
}

/// §2.8 derives a surface's sub-verdicts the same way §2.3/§2.6 derive their
/// top-level twins — so the favourable values need the same anchor. They had
/// none: a presentation could carry top-level `control_domain: UNKNOWN` and
/// `coverage: GAPPED` beside a per-surface row saying INDEPENDENT and CLOSED
/// for the same facts. An ADMISSION stays believed
/// without proof; the favourable value needs the controlling party's signature.
fn surface_row(e: &Value, trust: Option<&Value>) -> Value {
    let decl = s(e, "mechanism_declaration");
    let mech = match decl {
        // ENFORCED/OBSERVED only with an evidence source ref; bare → DECLARED
        Some(d @ ("ENFORCED" | "OBSERVED")) => tri(nonempty(e, "evidence_source_ref"), d, true, "DECLARED", ""),
        Some("DECLARED") => "DECLARED",
        _ => "UNKNOWN",
    };
    let grounded = crate::trust::verified(trust, "evaluator_keys", s(e, "controlling_party"), "surface-entry", e);
    let overlap = flag(e, "controller_admits_overlap");
    let independent = grounded && flag(e, "controller_grounded_independent");
    let cd = tri(overlap, "OVERLAPPING", independent, "INDEPENDENT", "UNKNOWN");
    let closed = grounded && flag(e, "coverage_closed");
    let cov = tri(flag(e, "coverage_gap"), "GAPPED", closed, "CLOSED", "UNKNOWN");
    let sid = py_str(e.get("surface_id"), "");
    json!({"surface_id": sid, "mechanism": mech, "control_domain": cd, "coverage": cov})
}

type SurfaceSets = (Vec<Value>, Vec<Value>, Vec<Value>); // (rows, out-of-scope, breaches)

fn surfaces(vi: &Value, trust: Option<&Value>) -> Result<SurfaceSets, Raise> {
    let Some(sur) = obj(vi, "surfaces") else { return Ok((vec![], vec![], vec![])) };
    let manifest = g(sur, "manifest");
    let entries = iter_items(if manifest.is_object() { manifest.get("entries") } else { None })?;
    let decl: Vec<&Value> = entries.iter().filter(|e| e.is_object()).collect();
    // membership below compares the stringified activity class against the
    // RAW declared values, so only string declarations can ever match; an
    // unhashable declared class raises in Python's set build
    if decl.iter().any(|e| matches!(e.get("surface_class"), Some(v) if v.is_array() || v.is_object())) {
        return Err(Raise);
    }
    let declared: BTreeSet<&str> = decl.iter().filter_map(|e| s(e, "surface_class")).collect();
    let (mut oos, mut breaches) = (BTreeSet::new(), BTreeSet::new());
    for a in iter_items(sur.get("activity"))? {
        if !a.is_object() {
            continue;
        }
        let cls = py_str(a.get("surface_class"), "");
        if !declared.contains(cls.as_str()) {
            oos.insert(cls); // explicitly rendered, never implicitly clean
        } else if a.get("explained") != Some(&Value::Bool(true)) {
            breaches.insert(cls); // unexplained activity on a declared surface
        }
    }
    let rows = decl.iter().map(|e| surface_row(e, trust)).collect();
    let to_vals = |set: BTreeSet<String>| set.into_iter().map(Value::String).collect();
    Ok((rows, to_vals(oos), to_vals(breaches)))
}

fn acc_basis(kind: &str) -> Option<usize> {
    // 2.9: binding kinds match exactly — no fuzzy matching in the trust path;
    // rank within UNKNOWN < SPONSOR < PARENT < INSURER < BOND_ESCROW
    ["SPONSOR", "PARENT", "INSURER", "BOND_ESCROW"].iter().position(|k| *k == kind)
}

/// §2.9. Every basis above UNKNOWN says a THIRD PARTY stands behind this agent.
/// The subject wrote all of it: `signed: true` was a boolean, not a signature,
/// so a hostile input reached BONDED_OR_ESCROWED with no external party at all.
fn accountability(vi: &Value, trust: Option<&Value>) -> Result<&'static str, Raise> {
    const ORDER: [&str; 4] = ["SPONSOR_ASSERTED", "PARENT_GUARANTEED", "INSURER_CORROBORATED", "BONDED_OR_ESCROWED"];
    let specifics = ["signed", "agent_specific", "mandate_specific", "value_bounded", "time_bounded"];
    let acc = g(vi, "accountability");
    let bindings = iter_items(if acc.is_object() { acc.get("bindings") } else { None })?;
    let mut best: Option<usize> = None;
    for b in bindings.iter().filter(|b| b.is_object()) {
        let kind = py_str(Some(&g(b, "kind")), "");
        let Some(rank) = acc_basis(&kind) else { continue };
        if !specifics.iter().all(|f| flag(b, f)) {
            continue; // qualifies only if agent-, mandate-, value- and time-specific
        }
        if !crate::trust::verified(trust, "accountability_keys", s(b, "party"), "accountability-binding", b) {
            continue; // `signed` means a signature, not a boolean
        }
        if rank >= 2 && !flag(b, "externally_grounded") {
            continue; // the two external bases need grounding by a non-subject party
        }
        best = Some(best.map_or(rank, |cur: usize| cur.max(rank)));
    }
    Ok(best.map(|r| ORDER[r]).unwrap_or("UNKNOWN"))
}

/// §2.12. DIRECT compared two digests the SAME producer wrote — a producer
/// marking its own homework. A match now earns DIRECT only when the Node signed
/// what it saw; otherwise DETERMINISTIC. A MISMATCH is adverse, so still believed.
fn assurance(vi: &Value, observed: bool) -> &'static str {
    let a = g(vi, "assurance");
    if !nonempty(&a, "intent_digest") {
        return "NONE"; // an action with no handshake is normal and unremarkable
    }
    let cands = a.get("candidates").and_then(Value::as_i64);
    let cands = cands.or(match a.get("candidates") {
        Some(Value::Bool(b)) => Some(*b as i64),
        _ => None,
    });
    if cands.map(|c| c >= 2).unwrap_or(false) {
        return "AMBIGUOUS";
    }
    if nonempty(&a, "presented_transcript_digest") {
        if a.get("presented_transcript_digest") != a.get("intent_digest") {
            return "AMBIGUOUS";
        }
        return tri(observed, "DIRECT", true, "DETERMINISTIC", "");
    }
    tri(cands == Some(1) && flag(&a, "challenge_nonce_match"), "DETERMINISTIC", false, "", "NONE")
}

/// Set of hashable member reprs; None mirrors a Python TypeError (→ UNKNOWN).
fn val_set(v: &Value) -> Option<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    match v {
        Value::Null | Value::Bool(false) => {}
        Value::Number(n) if n.as_f64() == Some(0.0) => {}
        Value::String(x) => out.extend(x.chars().map(|ch| ch.to_string())),
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::String(t) => out.insert(t.clone()),
                    Value::Number(_) | Value::Bool(_) | Value::Null => out.insert(x.to_string()),
                    _ => return None, // unhashable member
                };
            }
        }
        Value::Object(m) => out.extend(m.keys().cloned()), // Python set(dict) = keys
        _ => return None,                                  // not iterable
    }
    Some(out)
}

fn pred_map(v: &Value) -> Map<String, Value> {
    let sel = g(v, "selector");
    sel.get("predicates").and_then(|x| x.as_object()).cloned().unwrap_or_default()
}

/// Descriptors intersect iff classes intersect and no shared selector key is
/// disjoint; None mirrors a Python TypeError (→ UNKNOWN).
fn predicates_intersect(p: &Value, c: &Value) -> Option<bool> {
    let pc = val_set(&g(p, "action_classes"))?;
    let cc = val_set(&g(c, "action_classes"))?;
    if pc.intersection(&cc).next().is_none() {
        return Some(false);
    }
    let (pp, cp) = (pred_map(p), pred_map(c));
    for (k, va) in &pp {
        let Some(vb) = cp.get(k) else { continue };
        if val_set(va)?.intersection(&val_set(vb)?).next().is_none() {
            return Some(false);
        }
    }
    Some(true)
}

fn scope_pair(p: &Value, cand: &Value) -> &'static str {
    let c = g(cand, "scope");
    if !p.is_object() || flag(cand, "scope_digest_only") || !c.is_object() {
        return "UNKNOWN"; // an opaque digest can never yield UNRELATED
    }
    if g(p, "org") != g(&c, "org") {
        return "UNKNOWN";
    }
    if g(&g(p, "selector"), "kind") != g(&g(&c, "selector"), "kind") {
        return "UNKNOWN"; // selector kinds not mechanically comparable
    }
    if g(p, "source_system") != g(&c, "source_system") || g(p, "account") != g(&c, "account") {
        return "UNRELATED"; // provably disjoint on an axis
    }
    match predicates_intersect(p, &c) {
        Some(true) => "RELATED", // detected by comparison, not declaration
        Some(false) => "UNRELATED",
        None => "UNKNOWN",
    }
}

fn scope_relation(vi: &Value) -> Result<Value, Raise> {
    let Some(m) = obj(vi, "mandates") else {
        return Ok(Value::Null);
    }; // null iff absent
    let p = g(m, "presented_scope");
    let cands = iter_items(m.get("candidates"))?;
    let results: Vec<&str> = cands.iter().filter(|c| c.is_object()).map(|c| scope_pair(&p, c)).collect();
    if results.contains(&"RELATED") {
        return Ok(json!("RELATED"));
    }
    let unknown = results.contains(&"UNKNOWN") || results.is_empty();
    Ok(json!(tri(unknown, "UNKNOWN", false, "", "UNRELATED")))
}

/// PROVEN was PRESENCE, not proof: the check accepted `result_root:
/// "not-a-root"` and the literal string "THIS IS NOT A SIGNATURE".
fn population(vi: &Value, trust: Option<&Value>) -> Value {
    let Some(pi) = obj(vi, "population_index") else { return Value::Null };
    let complete = POP.iter().all(|f| pi.get(*f).map(|v| !v.is_null()).unwrap_or(false));
    let canonical_query = pi.get("query_descriptor").map(|q| q.is_object()).unwrap_or(false);
    let signed = crate::trust::verified(trust, "population_keys", s(pi, "source_id"), "population-index", pi);
    json!(tri(complete && canonical_query && signed, "PROVEN", false, "", "INDETERMINATE"))
}

/// A manifest limits a history claim only when the presentation actually makes
/// one. A no-surface presentation (the B28 handshake shape) makes no contrary
/// scope statement, so its named history scope remains intact — exactly as in
/// `verify/action.py::_history_manifest_surface_classes`.
fn history_manifest_surface_classes(vi: &Value) -> Option<BTreeSet<String>> {
    let entries = obj(vi, "surfaces").and_then(|surfaces| obj(surfaces, "manifest")).and_then(|manifest| manifest.get("entries")).and_then(Value::as_array)?;
    if entries.is_empty() {
        return None;
    }
    Some(
        entries
            .iter()
            .filter(|entry| entry.is_object())
            // Python uses str(entry.get("surface_class")); absent/null is
            // therefore "None", not the empty default used for activity rows.
            .map(|entry| py_str(entry.get("surface_class"), "None"))
            .collect(),
    )
}

fn history(vi: &Value) -> Result<Value, Raise> {
    let Some(h) = obj(vi, "history") else { return Ok(Value::Null) };
    if flag(h, "evidenced_history_in_scope") {
        return Ok(Value::Null); // history renders as population-rooted facts
    }
    let mut surfs: Vec<String> = iter_items(h.get("surfaces_closed_since_birth"))?.iter().map(|surface| py_str(Some(surface), "")).collect();
    if let Some(declared) = history_manifest_surface_classes(vi) {
        surfs.retain(|surface| declared.contains(surface));
    }
    if flag(h, "born_with_evidence") && !surfs.is_empty() {
        return Ok(json!({"state": "CLOSED_SINCE_BIRTH", "surfaces": surfs}));
    }
    Ok(json!({"state": "NO_EVIDENCED_HISTORY_IN_PRESENTED_SCOPE", "surfaces": []}))
}

/// §2.14. STILL producer-asserted, deliberately: neutralised by
/// `handshake/verify.py::B28_DISABLED`, which refuses every PASS and names this
/// exact route among the unauthenticated ones its rebuild must close.
fn authority_proof(vi: &Value) -> Value {
    let Some(h) = obj(vi, "handshake_authority") else { return Value::Null };
    json!(match s(h, "construction") {
        Some(c @ "ACTION_SPECIFIC_AUTHORIZATION") if flag(h, "asa_bindings_complete") => c,
        Some(c @ "DISCLOSED_LIMIT") if flag(h, "disclosed_limit_covers") => c,
        _ => "NONE", // a commitment cannot prove a predicate over its own preimage
    })
}

fn eligibility(vi: &Value, v: &Value) -> Result<&'static str, Raise> {
    let view = g(vi, "view");
    let withheld = iter_items(if view.is_object() { view.get("withheld_fields") } else { None })?;
    if withheld.iter().map(|w| py_str(Some(w), "")).any(|w| GATED.contains(&w.as_str())) {
        return Ok("NOT_RECOMPUTED"); // evaluated first — without inputs nothing is knowable
    }
    let interval = g(v, "intent_interval");
    let checks = [
        ELIGIBLE_EXACT.iter().all(|(k, want)| s(v, k) == Some(want)),
        !interval["lower"].is_null() && !interval["upper"].is_null(),
        matches!(s(v, "linkage"), Some("DIRECT") | Some("DETERMINISTIC")), // unique by 2.6
        s(v, "coverage_basis") != Some("INSUFFICIENT"),
        !flag(vi, "fork_findings_open"),
        s(v, "temporal_binding") != Some("UNPROVEN"),
        flag(&g(vi, "registration"), "scitt_receipt_valid"),
    ];
    Ok(tri(checks.iter().all(|c| *c), "ELIGIBLE", false, "", "INELIGIBLE"))
}

fn registration_status(vi: &Value, trust: Option<&Value>) -> &'static str {
    let reg = g(vi, "registration");
    let sr = g(&reg, "scope_registration");
    // REGISTERED is what the commercial model sells, so it is exactly the value
    // a subject most wants to assert: it needs a scope registration signed by a
    // transparency service THIS relying party named, plus a receipt the verifier
    // derived itself (never the producer's own scitt_receipt_valid flag).
    let covered = flag(&sr, "covers_scope") && flag(&sr, "term_valid");
    let registered = covered && sr.get("registration").map(|x| x.is_object()).unwrap_or(false) && flag(&reg, "scitt_receipt_valid") && crate::trust::verified(trust, "scitt_ts_keys", s(&sr, "transparency_service"), "scope-registration", &sr);
    if registered {
        return "REGISTERED";
    }
    let signed_intent = reg.get("intent").map(|x| x.is_object()).unwrap_or(false);
    // a signed intent alone is UNREGISTERED, never pending (2.15)
    tri(signed_intent && truthy(reg.get("attempts")), "PENDING", false, "", "UNREGISTERED")
}

fn mark(te: &str, reg: &str, v: &Value) -> &'static str {
    // 2.15 STRICT precedence, then the two mark paths
    match (te, reg) {
        ("NOT_RECOMPUTED", _) => "NOT_RECOMPUTED",
        (_, "PENDING") => "PENDING_REGISTRATION",
        (_, "UNREGISTERED") => "UNMARKED_UNREGISTERED",
        ("INELIGIBLE", _) => "UNMARKED_TECHNICAL",
        _ => {
            // Both paths read declaration-derived dimensions (source_signature
            // reaches ASYMMETRIC from a `verified: true` boolean + key-NAME
            // equality, never signature bytes; control_domain reaches INDEPENDENT
            // from truthy strings), so a subject could award itself the top mark.
            // Explicit withdrawal, never a silent absence. Mirrors verify/action.py.
            let corroborated = s(v, "source_signature") == Some("ASYMMETRIC") && s(v, "control_domain") == Some("INDEPENDENT");
            let observed = s(v, "node_observation") == Some("OBSERVED") && s(v, "node_integrity_basis") == Some("HARDWARE_ATTESTED");
            tri(corroborated, "UNMARKED_ASSURANCE_WITHDRAWN", observed, "UNMARKED_ASSURANCE_WITHDRAWN", "UNMARKED_TECHNICAL")
        }
    }
}

fn derive_inner(vi: &Value, trust: Option<&Value>) -> Result<Value, Raise> {
    let (ablock, derived) = authority_block(vi);
    let (observed, client, node_basis) = node_dims(vi, trust);
    let (cov, basis) = coverage(vi, node_basis, observed == "OBSERVED", trust);
    let (linkage, outcome) = linkage_outcome(vi)?;
    let (rows, oos, breaches) = surfaces(vi, trust)?;
    let mut v = json!({
        "schema": "evd/verdict-vector/v1",
        "identity": derived["identity"], "authority": derived["authority"],
        "intent": derived["intent"], "outcome": outcome, "linkage": linkage,
        "coverage": cov, "integrity": derived["integrity"],
        "source_signature": source_signature(vi, trust)?, "control_domain": control_domain(vi, trust)?,
        "node_observation": observed, "client_attestation": client,
        "coverage_basis": basis, "node_integrity_basis": node_basis,
        "temporal_binding": temporal(vi, trust), "intent_interval": derived["intent_interval"],
        "surfaces": rows, "out_of_scope_surfaces": oos, "boundary_breaches": breaches,
        "accountability_basis": accountability(vi, trust)?, "assurance_linkage": assurance(vi, observed == "OBSERVED"),
        "scope_relation": scope_relation(vi)?, "population_status": population(vi, trust),
        "history_state": history(vi)?, "authority_proof": authority_proof(vi),
    });
    v["technical_eligibility"] = json!(eligibility(vi, &v)?);
    v["registration_status"] = json!(registration_status(vi, trust));
    v["mark"] = json!(mark(s(&v, "technical_eligibility").unwrap_or(""), s(&v, "registration_status").unwrap_or(""), &v));
    if let Some(ids) = ablock.get("subject_ids").filter(|x| x.is_object()) {
        v["subject_ids"] = ids.clone(); // echoed, never derived here
    }
    Ok(v)
}

/// Derive the complete evd/verdict-vector/v1 for a verdict-input document
/// (SPEC/verified-action-v1.md §2). Total: malformed input yields weak values.
/// Derive the verdict vector with NO trust anchors: every externally-grounded
/// dimension renders its weak value, so an evidence document on its own can
/// never produce a favourable verdict. This is the safe default.
pub fn derive_vector(verdict_input: &Value) -> Value {
    derive_vector_with_trust(verdict_input, None)
}

/// Derive with an `evd/trust-context/v1` naming the roots THIS RELYING PARTY
/// accepts (see `crate::trust`). Passed separately from the evidence precisely
/// so the subject cannot supply its own anchors.
pub fn derive_vector_with_trust(verdict_input: &Value, trust: Option<&Value>) -> Value {
    derive_inner(verdict_input, trust).unwrap_or_else(|_| derive_inner(&json!({}), None).ok().expect("weak derivation is total"))
}

/// JSON/WASM entry point for a verdict input plus the relying party's LOCAL
/// trust context.  The contexts remain separate arguments; exchange data can
/// never smuggle its own roots into the verification call.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn derive_vector_json(verdict_input_json: &str, trust_json: &str) -> String {
    let input = if verdict_input_json.len() <= MAX_VERDICT_INPUT_BYTES { serde_json::from_str::<Value>(verdict_input_json).ok() } else { None };
    let trust = if trust_json.is_empty() || trust_json.len() > MAX_TRUST_CONTEXT_BYTES { None } else { serde_json::from_str::<Value>(trust_json).ok() };
    let vector = derive_vector_with_trust(input.as_ref().unwrap_or(&Value::Null), trust.as_ref());
    serde_json::to_string(&vector).expect("verdict vector is JSON")
}

// ------------------------------------------ authority_facts (authority-v1)

pub(crate) struct Rec {
    leaf: i64,
    agent: String,
    pub(crate) action: String,
    pub(crate) ctx: Value,
    commitments: Value,
    rh: String,
    signer_kids: BTreeSet<String>,
}

pub(crate) fn entry_rows(bundle: &Value) -> Vec<Rec> {
    let mut rows = Vec::new();
    for e in arr(bundle, "entries") {
        let env = g(e, "envelope");
        let (Some(body), Some(rh)) = (body_of(&env), receipt_hash_hex(&env)) else { continue };
        let ctx = obj(&body, "context").cloned().unwrap_or(json!({}));
        let commitments = obj(&body, "commitments").cloned().unwrap_or(json!({}));
        rows.push(Rec { leaf: e.get("leaf_index").and_then(|v| v.as_i64()).unwrap_or(-1), agent: s(&body, "agent_id").unwrap_or("").to_string(), action: s(&body, "action_type").unwrap_or("").to_string(), ctx, commitments, rh, signer_kids: arr(&env, "signatures").iter().filter_map(|sig| s(sig, "keyid").map(String::from)).collect() });
    }
    rows.sort_by_key(|r| r.leaf);
    rows
}

fn dom(action_type: &str) -> Vec<u8> {
    let mut d = b"evd/v1/authority/".to_vec();
    d.extend_from_slice(action_type.as_bytes());
    d.push(0);
    d
}

/// Detached-signature rule (§2): doc minus *_sig fields, JCS, domain prefix.
fn dsig_ok(pub_: &[u8; 32], domain: &[u8], doc: &Value, sig: Option<&Value>) -> bool {
    let Some(sig_b64) = sig.and_then(|x| x.as_str()) else { return false };
    let Some(m) = doc.as_object() else { return false };
    let mut stripped = m.clone();
    stripped.retain(|k, _| !k.ends_with("_sig"));
    let stripped = Value::Object(stripped);
    let Some(canon) = jcs::canonical_checked(&stripped) else { return false };
    let Ok(raw) = B64.decode(sig_b64) else { return false };
    let mut msg = domain.to_vec();
    msg.extend_from_slice(&canon);
    ed25519_verify(pub_, &msg, &raw)
}

/// (kids, raw public keys) witnessed by the log's evd.key.* history (§3.1).
fn witnessed_keys(rows: &[Rec]) -> (BTreeSet<String>, BTreeSet<[u8; 32]>) {
    let (mut kids, mut mats) = (BTreeSet::new(), BTreeSet::new());
    for r in rows {
        if r.agent == "_system" && r.action.starts_with("evd.key.") {
            let jwk = g(&r.ctx, "jwk");
            if let Some(kid) = s(&jwk, "kid") {
                kids.insert(kid.to_string());
            }
            if let Some((mat, _)) = key_from_jwk(&jwk) {
                mats.insert(mat);
            }
        }
    }
    (kids, mats)
}

/// (root_kid, pub, legal_entity) iff the enrolment passes §3.1, else None.
fn valid_enrolment(ctx: &Value, kids: &BTreeSet<String>, mats: &BTreeSet<[u8; 32]>) -> Option<(String, [u8; 32], Value)> {
    // key_from_jwk validates the JWK's own kid binding (public_from_jwk rule)
    let (pub_, derived_kid) = key_from_jwk(&g(ctx, "root_jwk"))?;
    let kid = s(ctx, "root_kid")?;
    // separation of duties: the org root is never a key the log witnessed
    if kid != derived_kid || kids.contains(kid) || mats.contains(&pub_) {
        return None;
    }
    if !dsig_ok(&pub_, &dom("authority.root.enrolled"), ctx, ctx.get("self_sig")) {
        return None; // self_sig = proof of possession
    }
    Some((kid.to_string(), pub_, g(ctx, "legal_entity")))
}

type RootEntry = (i64, String, [u8; 32], Value); // (leaf, kid, pub, legal_entity)

/// Root replay (§5) → (org_id, timeline, conflict). Invalid enrolments are
/// ignored; a valid UNLINKED second enrolment is a CONFLICT.
fn replay_roots(rows: &[Rec]) -> (Option<String>, Vec<RootEntry>, bool) {
    let (kids, mats) = witnessed_keys(rows);
    let (mut org_id, mut timeline, mut conflict): (Option<String>, Vec<RootEntry>, bool) = (None, vec![], false);
    for r in rows {
        if r.agent != "_authority" || r.action != "authority.root.enrolled" {
            continue;
        }
        let Some((kid, pub_, legal)) = valid_enrolment(&r.ctx, &kids, &mats) else { continue };
        let Some(last) = timeline.last() else {
            org_id = Some(r.rh.clone()); // the first valid enrolment fixes org_id
            timeline.push((r.leaf, kid, pub_, legal));
            continue;
        };
        let linked = s(&r.ctx, "prev_root_kid") == Some(last.1.as_str()) && dsig_ok(&last.2, &dom("authority.root.enrolled"), &r.ctx, r.ctx.get("prev_root_sig"));
        if linked {
            timeline.push((r.leaf, kid, pub_, legal)); // supersession chain
        } else {
            conflict = true; // a second unlinked enrolment
        }
    }
    (org_id, timeline, conflict)
}

fn root_at(timeline: &[RootEntry], leaf: i64) -> Option<&RootEntry> {
    timeline.iter().rev().find(|t| t.0 <= leaf)
}

/// `_authority` receipts of one type whose root_sig verifies under the root
/// active at their log position.
fn root_valid_auth<'a>(rows: &'a [Rec], timeline: &[RootEntry], action_type: &str) -> Vec<&'a Rec> {
    rows.iter().filter(|r| r.agent == "_authority" && r.action == action_type && root_at(timeline, r.leaf).map(|root| dsig_ok(&root.2, &dom(action_type), &r.ctx, r.ctx.get("root_sig"))).unwrap_or(false)).collect()
}

/// checkpoint body_hash → EARLIEST independent ts, as (normalized, raw) (§4).
///
/// Both sources are admissible here ONLY because each is now constrained by
/// something signed: a TST's `gen_time` must equal the token's verified
/// genTime, and an anchor's `block_ts` must not precede the signed `ts` of the
/// checkpoint it names (`check_anchor_record`).
fn independent_ts_map(bundle: &Value) -> BTreeMap<String, (String, String)> {
    let mut times: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (list, field) in [("anchor_records", "block_ts"), ("tst_records", "gen_time")] {
        for rec in arr(bundle, list).iter().filter(|r| r.is_object()) {
            let (Some(h), Some(norm)) = (s(rec, "checkpoint_body_hash"), nts(&g(rec, field))) else { continue };
            let raw = s(rec, field).unwrap_or("").to_string();
            if times.get(h).map(|cur| norm < cur.0).unwrap_or(true) {
                times.insert(h.to_string(), (norm, raw));
            }
        }
    }
    times
}

/// (tree_size, normalized, raw) per independently timed checkpoint, ordered by
/// tree_size, each clamped to the EARLIEST time proven for it or for any
/// checkpoint that contains it.
///
/// Checkpoint N is a prefix of every later checkpoint, so a proof that N+1
/// existed by T is equally a proof that N did. An anchor claiming N reached the
/// chain LATER than N+1 contradicts the chain itself. Without the clamp,
/// post-dating one `block_ts` produced an INVERTED interval (lower 2030 > upper
/// 2026), and "authority covers the ENTIRE interval" is vacuously true of an
/// interval that cannot exist — an action taken BEFORE its grant was issued
/// would otherwise be reported as VERIFIED.
fn clamped_times(bundle: &Value) -> Vec<(i64, String, String)> {
    let times = independent_ts_map(bundle);
    let mut rows: Vec<(i64, String, String)> = Vec::new();
    for e in arr(bundle, "checkpoint_chain") {
        let Some(cp) = e.get("checkpoint") else { continue };
        let Some(t) = checkpoint_body_hash(cp).and_then(|h| times.get(&h).cloned()) else {
            continue; // not independently timed
        };
        let size = cp.get("body").and_then(|b| b.get("tree_size")).and_then(|v| v.as_i64());
        let Some(size) = size else { continue };
        rows.push((size, t.0, t.1));
    }
    rows.sort_by_key(|r| r.0); // stable: ties keep bundle order, as in Python
    let mut earliest: Option<(String, String)> = None;
    for row in rows.iter_mut().rev() {
        if let Some(e) = &earliest {
            if e.0 < row.1 {
                row.1 = e.0.clone();
                row.2 = e.1.clone();
            }
        }
        earliest = Some((row.1.clone(), row.2.clone()));
    }
    rows
}

/// §4: lower = LAST independently timed checkpoint with tree_size <= leaf;
/// upper = FIRST with tree_size > leaf; null when none.
fn interval_for(bundle: &Value, leaf: i64) -> Value {
    let (mut lower, mut upper) = (Value::Null, Value::Null);
    for (size, _norm, raw) in clamped_times(bundle) {
        if size <= leaf {
            lower = json!(raw); // raw ts of the LAST checkpoint before the intent
        } else if upper.is_null() {
            upper = json!(raw); // raw ts of the FIRST checkpoint after it
        }
    }
    json!({"lower": lower, "upper": upper})
}

/// (evaluated intent, duplicate?) — action_id None picks the lowest leaf
/// index; duplicate = two or more DISTINCT receipts for that action_id.
fn pick_intent<'a>(rows: &'a [Rec], action_id: Option<&str>) -> Option<(&'a Rec, bool)> {
    let mut intents: Vec<&Rec> = rows.iter().filter(|r| r.action == "action.intent").collect();
    if let Some(aid) = action_id {
        intents.retain(|r| s(&r.ctx, "action_id") == Some(aid));
    }
    let chosen = *intents.first()?; // rows are leaf-ordered
    let aid = g(&chosen.ctx, "action_id");
    let distinct: BTreeSet<&str> = intents.iter().filter(|r| g(&r.ctx, "action_id") == aid).map(|r| r.rh.as_str()).collect();
    Some((chosen, distinct.len() > 1))
}

/// The one signed `action.intent` context for a displayed action identity.
/// Exact duplicate export rows are harmless; distinct receipt hashes conflict.
pub(crate) fn signed_action_context(bundle: &Value, action_id: &str) -> Option<Value> {
    let mut contexts: BTreeMap<String, Value> = BTreeMap::new();
    for row in entry_rows(bundle) {
        if row.action == "action.intent" && s(&row.ctx, "action_id") == Some(action_id) {
            contexts.entry(row.rh).or_insert(row.ctx);
        }
    }
    (contexts.len() == 1).then(|| contexts.into_iter().next().map(|(_, context)| context))?
}

pub(crate) fn has_signed_action_intent(bundle: &Value) -> bool {
    entry_rows(bundle).iter().any(|row| row.action == "action.intent")
}

/// (every action id any signed row names, every class signed for `action_id`).
///
/// The weak binding for a bundle with no `action.intent` receipt at all, whose
/// certificate still displays an identity that was free text until now. Two
/// signed sources say otherwise: a domain receipt's own `action_type` is the
/// signed spelling of what the action WAS, and a grant's
/// `context.action_classes` is the signed set it was permitted to be. The union
/// is required — `forged`/`revoked`/`selectively_disclosed`/`valid` have no
/// domain receipt but `action.intent` (hence the `action.` prefix skip), while
/// `claim_only`/`contradicted`/`gapped`/`stale` have no grant.
pub(crate) fn signed_action_intents(bundle: &Value, action_id: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let (mut ids, mut classes) = (BTreeSet::new(), BTreeSet::new());
    for row in entry_rows(bundle) {
        let aid = s(&row.ctx, "action_id");
        if let Some(aid) = aid.filter(|a| !a.is_empty()) {
            ids.insert(aid.to_string());
        }
        if aid == Some(action_id) {
            if !row.action.starts_with("action.") {
                classes.insert(row.action.clone());
            }
            classes.extend(s(&row.ctx, "action_class").filter(|c| !c.is_empty()).map(str::to_string));
            // EVERY class-contributing row must name THIS action. A grant is
            // scoped to a SUBJECT (`subject_birthtag_id action_classes scope
            // ...`, SPEC/authority-v1.md §3) and names no action_id, so outside
            // this test one grant handed its permitted classes to every action
            // in the bundle — a POSITIVE OVERGRANT, the verifier vouching for
            // authority never tied to this action. The absent `action.intent`
            // row is what would have tied them, so the tie is NOT ESTABLISHED.
            if row.action == "authority.grant.issued" {
                classes.extend(arr(&row.ctx, "action_classes").iter().map(|c| c.as_str().map(str::to_string).unwrap_or_else(|| c.to_string())));
            }
        }
    }
    (ids, classes)
}

fn intent_result(rows: &[Rec], chosen: &Rec, dup: bool) -> &'static str {
    if dup {
        return "CONFLICT"; // two DISTINCT intents for one action_id
    }
    if INTENT_CTX.iter().any(|k| chosen.ctx.get(*k).map(|v| v.is_null()).unwrap_or(true)) {
        return "NOT_RECORDED";
    }
    if chosen.commitments.get("inputs").is_none() || chosen.commitments.get("context_doc").is_none() {
        return "NOT_RECORDED"; // required commitments absent
    }
    let aid = g(&chosen.ctx, "action_id");
    let min_sub = rows.iter().filter(|r| r.action == "action.submitted" && g(&r.ctx, "action_id") == aid).map(|r| r.leaf).min();
    // the intent must sit at a strictly earlier leaf than any submission
    tri(min_sub.map(|m| chosen.leaf >= m).unwrap_or(false), "NOT_RECORDED", false, "", "RECORDED")
}

struct Lineage {
    birthtag_id: String, // the LOCAL establishment receipt hash
    revision_id: String,
    est_ctx: Value,
}

fn agent_lineage(rows: &[Rec], agent_id: &str) -> Option<Lineage> {
    let mine: Vec<&Rec> = rows.iter().filter(|r| r.agent == agent_id).collect();
    let est: Vec<&&Rec> = mine.iter().filter(|r| EST_TYPES.contains(&r.action.as_str())).collect();
    if est.len() != 1 {
        return None; // no establishment, or a duplicate — no lineage claim
    }
    let revs: Vec<&&Rec> = mine.iter().filter(|r| r.action == "lineage.revised").collect();
    let revision = revs.last().map(|r| r.rh.clone()).unwrap_or_else(|| est[0].rh.clone());
    Some(Lineage { birthtag_id: est[0].rh.clone(), revision_id: revision, est_ctx: est[0].ctx.clone() })
}

/// §7: transfer_sig by a passport-log key unrevoked at the transfer's
/// effective_ts (a key ACTIVE in the passport bundle's own key log at export).
fn transfer_sig_ok(passport_bundle: &Value, transfer: &Value) -> bool {
    let entries: Vec<Value> = arr(passport_bundle, "entries").to_vec();
    let pkl = replay_key_log(&entries);
    if !pkl.ok {
        return false;
    }
    let eff = g(transfer, "effective_ts");
    pkl.keys.iter().any(|(kid, pub_)| {
        let unrevoked = match pkl.revoked_at.get(kid) {
            None => true,
            Some(r) => matches!((nts(&eff), nts(&json!(r))), (Some(e), Some(rr)) if e <= rr),
        };
        unrevoked && dsig_ok(pub_, b"evd/v1/passport/transfer\x00", transfer, transfer.get("transfer_sig"))
    })
}

/// §7: passport bundle verifies standalone; birthtag_id is its establishment
/// receipt hash; the transfer names the importing root and its sig verifies.
fn passport_bundle_ok(passport: &Value, imported: &str, timeline: &[RootEntry]) -> bool {
    let Some(pb) = obj(passport, "bundle") else { return false };
    if !verify_bundle(pb) {
        return false;
    }
    let est_ok = entry_rows(pb).iter().any(|r| EST_TYPES.contains(&r.action.as_str()) && r.rh == imported);
    let transfer = g(passport, "transfer");
    if !est_ok || s(&transfer, "birthtag_id") != Some(imported) {
        return false;
    }
    // the transfer must name the importing log's enrolled root
    let named = timeline.last().map(|t| s(&transfer, "successor_root_kid") == Some(t.1.as_str()));
    named.unwrap_or(false) && transfer_sig_ok(pb, &transfer)
}

/// §7 import verification → the imported birthtag_id; None on ANY failure.
fn passport_birthtag<'a>(bundle: &Value, est_ctx: &'a Value, timeline: &[RootEntry]) -> Option<&'a str> {
    let imported = s(est_ctx, "imported_birthtag_id").filter(|x| !x.is_empty())?;
    let passport = obj(bundle, "passport")?;
    let digest = hex(&sha256(&jcs::canonical_checked(passport)?)); // sha256(JCS(passport))
    if s(est_ctx, "passport_digest") != Some(digest.as_str()) {
        return None;
    }
    if s(passport, "birthtag_id") != Some(imported) {
        return None;
    }
    passport_bundle_ok(passport, imported, timeline).then_some(imported)
}

fn windows_conflict(a: &Value, b: &Value) -> bool {
    if g(a, "runtime_kid") != g(b, "runtime_kid") {
        return false;
    }
    let ts: Vec<Option<String>> = [a, b].iter().flat_map(|c| ["valid_from", "valid_to"].map(|f| nts(&g(c, f)))).collect();
    let (Some(af), Some(at), Some(bf), Some(bt)) = (&ts[0], &ts[1], &ts[2], &ts[3]) else {
        return false; // unprovable overlap is not a contradiction
    };
    af <= bt && bf <= at
}

/// §5: two overlapping bindings naming one runtime_kid without MUTUAL
/// concurrent_with declarations — the verifier never picks a winner.
fn binding_conflict(bindings: &[&Rec]) -> bool {
    for (i, a) in bindings.iter().enumerate() {
        for b in &bindings[i + 1..] {
            if !windows_conflict(&a.ctx, &b.ctx) {
                continue;
            }
            let lists = |x: &Rec, other: &str| arr(&x.ctx, "concurrent_with").iter().any(|v| v.as_str() == Some(other));
            if !(lists(a, &b.rh) && lists(b, &a.rh)) {
                return true; // undeclared concurrent bindings, one runtime key
            }
        }
    }
    false
}

fn match_binding<'a>(bindings: &[&'a Rec], lineage: &Lineage, intent: &Rec, interval: &Value) -> Option<&'a Rec> {
    let lo = nts(&interval["lower"])?; // a null bound cannot be covered (§4)
    let up = nts(&interval["upper"])?;
    bindings
        .iter()
        .find(|b| {
            let ctx = &b.ctx;
            let hit = s(ctx, "birthtag_id") == Some(lineage.birthtag_id.as_str()) && s(ctx, "revision_id") == Some(lineage.revision_id.as_str()) && s(ctx, "runtime_kid").map(|k| intent.signer_kids.contains(k)).unwrap_or(false);
            let covers = matches!(
                (nts(&g(ctx, "valid_from")), nts(&g(ctx, "valid_to"))),
                (Some(vf), Some(vt)) if vf <= lo && up <= vt
            );
            hit && covers // the binding covers the ENTIRE intent_interval
        })
        .copied()
}

/// → (result, binding_id | None, birthtag_id | None).
fn derive_identity(rows: &[Rec], bundle: &Value, intent: &Rec, lineage: Option<&Lineage>, timeline: &[RootEntry], root_conflict: bool, interval: &Value) -> (&'static str, Option<String>, Option<String>) {
    let bindings = root_valid_auth(rows, timeline, "authority.principal.bound");
    if root_conflict || binding_conflict(&bindings) {
        return ("CONFLICT", None, None); // never degraded to a pass
    }
    let Some(lineage) = lineage else { return ("NOT_VERIFIED", None, None) };
    let birthtag = if lineage.est_ctx.get("imported_birthtag_id").is_some() {
        match passport_birthtag(bundle, &lineage.est_ctx, timeline) {
            Some(b) => b.to_string(),
            None => return ("NOT_VERIFIED", None, None), // unauthorised/copied passport (§7)
        }
    } else {
        lineage.birthtag_id.clone()
    };
    match match_binding(&bindings, lineage, intent, interval) {
        Some(b) => ("VERIFIED", Some(b.rh.clone()), Some(birthtag)),
        None => ("NOT_VERIFIED", None, Some(birthtag)),
    }
}

fn as_int(v: &Value) -> Option<i64> {
    // Python int(): ints, integral coercion of floats, numeric strings, bools
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::String(x) => x.trim().parse::<i64>().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

/// Distinct revision receipts as sorted (version, prev, hash, ctx); None if
/// any version field is malformed.
fn grant_versions(revs: &[&Rec]) -> Option<Vec<(i64, i64, String, Value)>> {
    let mut rows: BTreeMap<(i64, i64, String), Value> = BTreeMap::new();
    for r in revs {
        let v = as_int(r.ctx.get("grant_version")?)?;
        let pv = as_int(r.ctx.get("prev_grant_version")?)?;
        rows.insert((v, pv, r.rh.clone()), r.ctx.clone());
    }
    Some(rows.into_iter().map(|((v, pv, h), ctx)| (v, pv, h, ctx)).collect())
}

/// §6: follow transfers_grant_id to the head; that receipt hash IS the
/// mandate_id. None when the chain leaves the bundle or cycles.
fn mandate_id(issued: &Rec, issued_all: &[&Rec]) -> Option<String> {
    let by_hash: BTreeMap<&str, &&Rec> = issued_all.iter().map(|r| (r.rh.as_str(), r)).collect();
    let (mut cur, mut seen) = (issued, BTreeSet::new());
    loop {
        let nxt = cur.ctx.get("transfers_grant_id").filter(|v| !v.is_null());
        let Some(nxt) = nxt else { return Some(cur.rh.clone()) };
        let key = nxt.as_str()?; // a non-string ref never resolves
        if !seen.insert(key.to_string()) {
            return None; // cycle — underivable, the weaker claim
        }
        cur = by_hash.get(key)?;
    }
}

fn doc_ok(doc: &Value, action_class: &Value, lo: &str, up: &str) -> bool {
    let window = matches!(
        (nts(&g(doc, "valid_from")), nts(&g(doc, "valid_to"))),
        (Some(vf), Some(vt)) if vf.as_str() <= lo && up <= vt.as_str()
    );
    let classes = doc.get("action_classes").and_then(|c| c.as_array());
    window && classes.map(|c| c.contains(action_class)).unwrap_or(false)
}

/// Status replay (§5): the effective document at EVERY instant of the
/// interval must include the class and cover the whole interval.
fn docs_cover(issued: &Rec, pairs: &[(i64, i64, String, Value)], action_class: &Value, lo: &str, up: &str) -> bool {
    let mut docs: Vec<&Value> = vec![&issued.ctx];
    for (_v, _pv, _h, ctx) in pairs {
        let Some(eff) = nts(&g(ctx, "effective_ts")) else { return false };
        if eff.as_str() <= lo {
            docs[0] = ctx; // the document effective at the interval's lower bound
        } else if eff.as_str() <= up {
            docs.push(ctx); // takes effect inside the interval
        }
    }
    docs.iter().all(|d| doc_ok(d, action_class, lo, up))
}

/// Revision versions must run 2..n with prev = version - 1 (issue is v1).
fn versions_dense(pairs: &[(i64, i64, String, Value)]) -> bool {
    pairs.iter().enumerate().all(|(i, p)| p.0 == i as i64 + 2 && p.1 == p.0 - 1)
}

/// §3.5: revocation is prospective from effective_ts — the grant is revoked
/// at some instant of the interval iff any effective_ts <= upper.
fn revoked_in_interval(rows: &[Rec], timeline: &[RootEntry], gid: &Value, up: &str) -> bool {
    root_valid_auth(rows, timeline, "authority.grant.revoked").iter().any(|r| g(&r.ctx, "grant_id") == *gid && nts(&g(&r.ctx, "effective_ts")).map(|eff| eff.as_str() <= up).unwrap_or(true))
}

fn grant_chain_verified(rows: &[Rec], timeline: &[RootEntry], issued: &Rec, pairs: &[(i64, i64, String, Value)], intent: &Rec, interval: &Value) -> bool {
    let (Some(lo), Some(up)) = (nts(&interval["lower"]), nts(&interval["upper"])) else {
        return false; // a null bound cannot be covered (§4)
    };
    if !versions_dense(pairs) {
        return false;
    }
    if revoked_in_interval(rows, timeline, &json!(issued.rh), &up) {
        return false;
    }
    docs_cover(issued, pairs, &g(&intent.ctx, "action_class"), &lo, &up)
}

/// A grant names the principal binding it was issued FOR. Using it under a
/// DIFFERENT binding of the same subject is an authorization SUBSTITUTION.
///
/// `subject_birthtag_id` alone was the whole test, and a birthtag outlives any
/// one binding — an agent legitimately holds several (key rotation, a second
/// runtime, prod beside staging, a re-bind after a lineage revision). So a grant
/// issued for the quiet binding authorised an action executed under the live one
/// and both engines said authority VERIFIED.
///
/// Enforced only when a binding was actually MATCHED: with none in force
/// identity is already NOT_VERIFIED and eligibility already fails on it.
/// `binding_id` is optional on a grant (SPEC/authority-v1.md §3), and a grant
/// naming none constrains nothing.
fn binding_substituted(issued: &Rec, revised: &[&Rec], binding_id: Option<&str>) -> bool {
    let Some(binding_id) = binding_id else { return false };
    std::iter::once(&issued.ctx).chain(revised.iter().map(|r| &r.ctx)).any(|ctx| matches!(ctx.get("binding_id").and_then(Value::as_str), Some(named) if !named.is_empty() && named != binding_id))
}

fn derive_authority(rows: &[Rec], timeline: &[RootEntry], intent: &Rec, interval: &Value, birthtags: &BTreeSet<String>, binding_id: Option<&str>) -> (&'static str, Map<String, Value>) {
    let gid = g(&intent.ctx, "grant_id");
    let issued_all = root_valid_auth(rows, timeline, "authority.grant.issued");
    let revised: Vec<&Rec> = root_valid_auth(rows, timeline, "authority.grant.revised").into_iter().filter(|r| g(&r.ctx, "grant_id") == gid).collect();
    let pairs = grant_versions(&revised);
    if let Some(p) = &pairs {
        let versions: BTreeSet<i64> = p.iter().map(|x| x.0).collect();
        if versions.len() < p.len() {
            return ("CONFLICT", Map::new()); // grant rewrite: one version, two receipts
        }
    }
    let issued = issued_all.iter().find(|r| Value::String(r.rh.clone()) == gid).copied();
    let subject = issued.map(|r| g(&r.ctx, "subject_birthtag_id"));
    let subject_ok = matches!(&subject, Some(Value::String(b)) if birthtags.contains(b));
    let Some(issued) = issued.filter(|_| subject_ok) else { return ("NOT_VERIFIED", Map::new()) };
    let mut ids = Map::new();
    ids.insert("grant_id".into(), gid.clone());
    if binding_substituted(issued, &revised, binding_id) {
        return ("NOT_VERIFIED", ids);
    }
    if let Some(m) = mandate_id(issued, &issued_all) {
        ids.insert("mandate_id".into(), json!(m));
    }
    let Some(pairs) = pairs else {
        return ("NOT_VERIFIED", ids);
    }; // malformed versions
    let ok = grant_chain_verified(rows, timeline, issued, &pairs, intent, interval);
    (tri(ok, "VERIFIED", false, "", "NOT_VERIFIED"), ids)
}

fn weak_facts(integrity: &str) -> Value {
    json!({
        "identity": "NOT_VERIFIED", "authority": "NOT_VERIFIED", "intent": "NOT_RECORDED",
        "integrity": integrity, "intent_interval": {"lower": null, "upper": null},
    })
}

fn facts(bundle: &Value, action_id: Option<&str>) -> Value {
    let rows = entry_rows(bundle);
    let (org_id, timeline, root_conflict) = replay_roots(&rows);
    let mut out = weak_facts("VALID");
    let mut sids = Map::new();
    if let Some(org) = org_id {
        sids.insert("org_id".into(), json!(org));
    }
    if let Some(last) = timeline.last().filter(|t| !t.3.is_null()) {
        out["operator_entity"] = last.3.clone();
    }
    if let Some((chosen, dup)) = pick_intent(&rows, action_id) {
        let interval = interval_for(bundle, chosen.leaf);
        out["intent_interval"] = interval.clone();
        out["intent"] = json!(intent_result(&rows, chosen, dup));
        if !dup {
            sids.insert("intent_id".into(), json!(chosen.rh));
        }
        let lineage = agent_lineage(&rows, &chosen.agent);
        let (identity, binding_id, birthtag) = derive_identity(&rows, bundle, chosen, lineage.as_ref(), &timeline, root_conflict, &interval);
        out["identity"] = json!(identity);
        if let Some(b) = &binding_id {
            sids.insert("binding_id".into(), json!(b));
        }
        if let Some(b) = &birthtag {
            sids.insert("birthtag_id".into(), json!(b));
        }
        let birthtags: BTreeSet<String> = birthtag.into_iter().chain(lineage.as_ref().map(|l| l.birthtag_id.clone())).collect();
        let (authority, gids) = derive_authority(&rows, &timeline, chosen, &interval, &birthtags, binding_id.as_deref());
        out["authority"] = json!(authority);
        sids.extend(gids);
    }
    if !sids.is_empty() {
        out["subject_ids"] = Value::Object(sids);
    }
    out
}

/// Bundle-derived authority facts (SPEC/authority-v1.md §4–§5, §7): the
/// VerdictInput.authority object. Total: any failure degrades to weak values;
/// integrity INVALID renders everything else at its weak default.
pub fn authority_facts(bundle: &Value, action_id: Option<&str>) -> Value {
    if !verify_bundle(bundle) {
        return weak_facts("INVALID");
    }
    facts(bundle, action_id)
}
