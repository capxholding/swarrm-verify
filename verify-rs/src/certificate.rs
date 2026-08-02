// Apache-2.0 (public verifier repo)
//! Certificate verification (SPEC/certificate-v1.md §4) — B24.3, Rust side.
//!
//! `verify_certificate_cbor` takes raw bytes (bare CertificateCore or a
//! CertificateView envelope, deterministic CBOR per §1) → JSON result
//! `{parse_ok, layers, certificate_id, core_present, cross_checks_ok,
//! vector, mark, errors}`. Caps run BEFORE crypto (H5); hostile bytes never
//! panic. The producer-shaped `verdict_input` is NOT authoritative (§4.4):
//! authority is recomputed via `action::authority_facts`, `event_matches`
//! flags via reconcile-v1 §4/§5 semantics (manifest conventions —
//! `correlation_field`/`unique_fields`/`finality_rule`/`material_fields` —
//! travel inside `coverage_doc`; an absent convention recomputes the weak
//! value), the core's top-level members must echo `verdict_input`
//! (a doctored input could otherwise upgrade the headline unchecked), and
//! `coverage_doc` must sit consistent with `events`/`batch` (event_count ==
//! deduped carried events, event_key_root recomputed over their keys).
//! Any mismatch forces integrity INVALID before the B21 engine derives the
//! vector — never a partial pass. The view's detached `signature` verifies
//! under a bundle key-log key over `b"evd/v1/certificate/view\x00"` +
//! canonical CBOR of the view minus `signature`/`*_sig` (authority-v1 §2
//! prefix rule in this profile's one canonical form). A view without core
//! bytes renders the layer it holds and recomputes nothing.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ciborium::Value as C;
use serde_json::{json, Value as J};
use std::collections::BTreeSet;

use crate::action::{authority_facts, derive_vector};
use crate::cbor::{canonical_cbor, decode_cbor, MAX_BYTES, MAX_DEPTH};
use crate::{ed25519_verify, hex, replay_key_log, sha256, verify_bundle};

const CORE_SCHEMA: &str = "evd/certificate/v1";
const VIEW_SCHEMA: &str = "evd/certificate-view/v1";
const VIEW_DOMAIN: &[u8] = b"evd/v1/certificate/view\x00";
// §4.1 caps (certificate-v1.cddl trailer); the 16 MiB pack cap is cbor::MAX_BYTES.
const MAX_CORE_BYTES: usize = 1024 * 1024;
const MAX_LIST: usize = 10_000;
const MAX_ATTACHMENTS: usize = 1_000;
const MAX_DISCLOSURES: usize = 256;

// ---------------------------------------------------------------- utilities

fn cget<'a>(v: &'a C, key: &str) -> Option<&'a C> {
    let C::Map(m) = v else { return None };
    m.iter().find(|(k, _)| matches!(k, C::Text(t) if t == key)).map(|(_, x)| x)
}

fn ctext<'a>(v: &'a C, key: &str) -> Option<&'a str> {
    match cget(v, key)? { C::Text(t) => Some(t), _ => None }
}

fn cbytes<'a>(v: &'a C, key: &str) -> Option<&'a [u8]> {
    match cget(v, key)? { C::Bytes(b) => Some(b), _ => None }
}

/// Restricted CBOR → the JSON-compatible model; None on bytes/floats/tags
/// (the core is JSON-compatible by §1 — a bstr inside it is malformed).
fn cbor_to_json(v: &C, limit: i64) -> Option<J> {
    if limit < 0 { return None }
    Some(match v {
        C::Null => J::Null,
        C::Bool(b) => J::Bool(*b),
        C::Integer(i) => J::Number(i64::try_from(*i).ok()?.into()),
        C::Text(s) => J::String(s.clone()),
        C::Array(a) => J::Array(a.iter().map(|x| cbor_to_json(x, limit - 1)).collect::<Option<_>>()?),
        C::Map(m) => {
            let mut o = serde_json::Map::new();
            for (k, x) in m {
                let C::Text(key) = k else { return None };
                o.insert(key.clone(), cbor_to_json(x, limit - 1)?);
            }
            J::Object(o)
        }
        _ => return None,
    })
}

/// Python `str()` of an optional member: missing → "", null → "None".
fn pystr(v: Option<&J>) -> String {
    match v {
        None => String::new(),
        Some(J::Null) => "None".into(),
        Some(J::Bool(b)) => (if *b { "True" } else { "False" }).into(),
        Some(J::String(s)) => s.clone(),
        Some(J::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

/// Python `str(container.get(key) or "")` for the CDDL text fields.
fn text_or_empty(v: &J, key: &str) -> String {
    match v.get(key) { None | Some(J::Null) => String::new(), other => pystr(other) }
}

fn report(ok: bool, layers: &[&str], id: Option<&str>, core: bool, cross: bool, vector: J, mark: J, errors: &[&str]) -> J {
    json!({
        "parse_ok": ok, "layers": layers, "certificate_id": id, "core_present": core,
        "cross_checks_ok": cross, "vector": vector, "mark": mark, "errors": errors,
    })
}

// ------------------------------------------------- cross-checks (§4.3–§4.4)

fn check_authority(core: &J, bundle: &J) -> bool {
    let aid = core["subject"].get("action_id").and_then(J::as_str).filter(|a| !a.is_empty());
    core["verdict_input"].get("authority") == Some(&authority_facts(bundle, aid))
}

fn falsy(v: &J) -> bool {
    match v {
        J::Null => true,
        J::Bool(b) => !*b,
        J::String(s) => s.is_empty(),
        J::Array(a) => a.is_empty(),
        J::Object(m) => m.is_empty(),
        J::Number(n) => n.as_f64() == Some(0.0),
    }
}

/// The engine consumes verdict_input while §4.4 recomputes over the core's
/// top-level members — the two carriages must agree, else a doctored
/// verdict_input could upgrade the recomputed headline unchecked. Missing
/// and null compare equal (Python `.get()` semantics).
fn check_input_echo(core: &J) -> bool {
    let vi = &core["verdict_input"];
    let listed = |k: &str| vi.get(k).filter(|v| !falsy(v)).cloned().unwrap_or_else(|| json!([]));
    if core["events"] != listed("events") || core["event_matches"] != listed("event_matches") {
        return false;
    }
    ["claim", "source_identity", "control_evidence", "batch", "scan"].iter().all(|k| {
        core.get(*k).filter(|v| !v.is_null()) == vi.get(*k).filter(|v| !v.is_null())
    })
}

/// Carried events deduped by immutable `event_key` FIRST (reconcile-v1 §4).
fn deduped_events(core: &J) -> Vec<(String, &J)> {
    let (mut seen, mut out) = (BTreeSet::new(), Vec::new());
    for e in core["events"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let k = pystr(e.get("event_key"));
        if e.is_object() && seen.insert(k.clone()) {
            out.push((k, e));
        }
    }
    out
}

/// (echo, immutable-ref, unique-field) — reconcile's `_match_flags` inputs.
fn link_flags(claim: &J, ev: &J, man: &J) -> (bool, bool, bool) {
    let token = text_or_empty(claim, "action_id");
    let reference = pystr(ev.get("reference"));
    let corr = man.get("correlation_field").and_then(J::as_str).unwrap_or("");
    let echo = !token.is_empty()
        && ((!corr.is_empty() && pystr(ev.get(corr)) == token) || reference == token);
    let external = text_or_empty(claim, "external_ref");
    (echo, !external.is_empty() && reference == external, unique_field_match(claim, ev, man))
}

/// Manifest-APPROVED unique-field equality only; both sides non-null and the
/// claim side non-empty (reconcile `_unique_field_match`).
fn unique_field_match(claim: &J, ev: &J, man: &J) -> bool {
    let fields = man.get("unique_fields").and_then(J::as_array);
    for f in fields.map(Vec::as_slice).unwrap_or(&[]).iter().filter_map(J::as_str) {
        let (l, r) = (claim.get(f).filter(|x| !x.is_null()), ev.get(f).filter(|x| !x.is_null()));
        let (Some(l), Some(r)) = (l, r) else { continue };
        let ls = pystr(Some(l));
        if !ls.is_empty() && ls == pystr(Some(r)) { return true }
    }
    false
}

fn is_final(ev: &J, rule: Option<&J>) -> bool {
    let fin = pystr(ev.get("finality"));
    match rule {
        Some(J::String(s)) => fin == *s,
        Some(J::Object(m)) => ["final", "correction"].iter().any(|k| {
            let vals = m.get(*k).and_then(J::as_array);
            vals.map(|a| a.iter().any(|v| pystr(Some(v)) == fin)).unwrap_or(false)
        }),
        _ => false,
    }
}

/// §5 material comparison over the manifest's fields for the claim's class.
/// `source_effect_time` never disagrees here: a CDDL AgentActionClaim cannot
/// state one, and an absent side proves nothing (weak-claim doctrine).
fn material_mismatch(claim: &J, ev: &J, man: &J) -> bool {
    let class = pystr(claim.get("action_class"));
    let fields = man.get("material_fields").and_then(|m| m.get(&class)).and_then(J::as_array);
    for f in fields.map(Vec::as_slice).unwrap_or(&[]).iter().filter_map(J::as_str) {
        let (l, r) = (claim.get(f).filter(|x| !x.is_null()), ev.get(f).filter(|x| !x.is_null()));
        if let (Some(l), Some(r)) = (l, r) {
            if f != "source_effect_time" && pystr(Some(l)) != pystr(Some(r)) { return true }
        }
    }
    false
}

fn flags_equal(m: &J, want: [bool; 5]) -> bool {
    ["echoed_action_id", "immutable_ref_match", "unique_field_match", "final", "material_mismatch"]
        .iter().zip(want).all(|(k, w)| m.get(*k) == Some(&J::Bool(w)))
}

/// §4.4: every carried flag equals its recomputation, and every candidate
/// event appears — a dropped second candidate would fake a unique link.
fn check_matches(core: &J) -> bool {
    let man = &core["coverage_doc"];
    let claim = core.get("claim").filter(|c| c.is_object()).cloned().unwrap_or_else(|| json!({}));
    let events = deduped_events(core);
    let matches = core["event_matches"].as_array().cloned().unwrap_or_default();
    let unique = matches.len() == 1; // material comparison runs on the unique link only
    let mut named: BTreeSet<String> = BTreeSet::new();
    for m in &matches {
        let key = pystr(m.get("event_key"));
        let Some((_, ev)) = events.iter().find(|(k, _)| *k == key) else { return false };
        let (e, i, u) = link_flags(&claim, ev, man);
        let mat = unique && material_mismatch(&claim, ev, man);
        if !flags_equal(m, [e, i, u, is_final(ev, man.get("finality_rule")), mat]) { return false }
        named.insert(key);
    }
    events.iter().all(|(k, ev)| {
        let (e, i, u) = link_flags(&claim, ev, man);
        !(e || i || u) || named.contains(k)
    })
}

fn count_pair_ok(cov: &J, list: &str, count: &str) -> bool {
    match (cov.get(list).and_then(J::as_array), cov.get(count).and_then(J::as_i64)) {
        (Some(a), Some(n)) => n == a.len() as i64,
        _ => cov.get(list).is_none() && cov.get(count).is_none(),
    }
}

/// §4.4: coverage_doc counts/roots internally consistent with events/batch —
/// event_count MUST equal the deduped carried events and event_key_root MUST
/// recompute over their keys (JCS), exactly as verify/certificate.py pins.
fn check_coverage(core: &J) -> bool {
    let cov = &core["coverage_doc"];
    let keys: Vec<J> = deduped_events(core).iter().map(|(k, _)| json!(k)).collect();
    if cov.get("event_count").and_then(J::as_i64) != Some(keys.len() as i64) { return false }
    let Some(root) = crate::jcs::canonical_checked(&json!(keys)) else { return false };
    if cov.get("event_key_root") != Some(&json!(hex(&sha256(&root)))) { return false }
    if !count_pair_ok(cov, "claim_refs", "claim_count") || !count_pair_ok(cov, "orphans", "orphan_count") {
        return false;
    }
    batch_consistent(core.get("batch"), cov)
}

fn batch_consistent(batch: Option<&J>, cov: &J) -> bool {
    let Some(batch) = batch.filter(|b| b.is_object()) else { return true };
    let frame = ["cursor_start", "cursor_end", "filter_digest", "mapping_version", "event_key_root", "finality_watermark"];
    let disagree = |f: &str| match (batch.get(f), cov.get(f)) {
        (Some(b), Some(c)) => pystr(Some(b)) != pystr(Some(c)),
        _ => false, // a side that states nothing proves no disagreement
    };
    if frame.iter().any(|f| disagree(f)) { return false }
    ["gaps", "exclusions"].iter().all(|l| {
        // an omitted batch gap/exclusion would be a silent overclaim
        let doc: BTreeSet<String> = cov.get(*l).and_then(J::as_array)
            .map(|a| a.iter().map(|x| pystr(Some(x))).collect()).unwrap_or_default();
        let items = batch.get(*l).and_then(J::as_array);
        items.map(|a| a.iter().all(|g| doc.contains(&pystr(Some(g))))).unwrap_or(true)
    })
}

// -------------------------------------------------------- view layer checks

/// Detached signature: any bundle key-log key over VIEW_DOMAIN + canonical
/// CBOR of the view minus `signature`/`*_sig` (authority-v1 §2 rule).
fn view_sig_ok(view: &C, bundle: &J) -> bool {
    let C::Map(members) = view else { return false };
    let Some(sig) = ctext(view, "signature").and_then(|s| B64.decode(s).ok()) else { return false };
    let kept: Vec<(C, C)> = members.iter()
        .filter(|(k, _)| !matches!(k, C::Text(t) if t == "signature" || t.ends_with("_sig")))
        .cloned().collect();
    let Some(body) = canonical_cbor(&C::Map(kept)) else { return false };
    let msg = [VIEW_DOMAIN, &body].concat();
    let entries = bundle.get("entries").and_then(J::as_array).cloned().unwrap_or_default();
    let kl = replay_key_log(&entries);
    kl.ok && kl.keys.values().any(|k| ed25519_verify(k, &msg, &sig))
}

fn withheld_fields(view: &C) -> J {
    cget(view, "manifest")
        .and_then(|m| cget(m, "withheld_field_set"))
        .and_then(|w| cbor_to_json(w, MAX_DEPTH))
        .filter(|w| w.is_array())
        .unwrap_or_else(|| json!([]))
}

fn view_checks(view: &C, id: &str, bundle: &J, mark: &J, errors: &mut Vec<&'static str>) {
    if !view_sig_ok(view, bundle) { errors.push("VIEW_SIGNATURE_INVALID") }
    let man = cget(view, "manifest");
    if man.and_then(|m| ctext(m, "certificate_id")) != Some(id) { errors.push("MANIFEST_MISMATCH") }
    // §4.5: the claimed mark_result must equal the recomputed mark
    if man.and_then(|m| ctext(m, "mark_result")) != mark.as_str() { errors.push("MARK_MISMATCH") }
}

// ----------------------------------------------------------------- pipeline

fn core_shape_ok(j: &J) -> bool {
    ["subject", "bundle", "coverage_doc", "verdict_input"]
        .iter().all(|k| j.get(*k).map(|v| v.is_object()).unwrap_or(false))
        && ["events", "event_matches", "open_findings", "proof_digests", "limitations"]
            .iter().all(|k| j.get(*k).map(|v| v.is_array()).unwrap_or(false))
}

fn core_caps_ok(j: &J) -> bool {
    let len = |k: &str| j.get(k).and_then(J::as_array).map(Vec::len).unwrap_or(0);
    len("events") <= MAX_LIST && len("event_matches") <= MAX_LIST
        && len("open_findings") <= MAX_LIST && len("attachments") <= MAX_ATTACHMENTS
}

fn verify_core(id: &str, core: &C, view: Option<&C>) -> J {
    let layers: &[&str] = if view.is_some() { &["core", "view"] } else { &["core"] };
    let held = |errs: &[&str]| report(true, layers, Some(id), true, false, J::Null, J::Null, errs);
    let Some(j) = cbor_to_json(core, MAX_DEPTH).filter(core_shape_ok) else {
        return held(&["CORE_MALFORMED"]);
    };
    if !core_caps_ok(&j) { return held(&["OVER_CAP"]) }
    let bundle = j["bundle"].clone();
    let mut errors: Vec<&'static str> = Vec::new();
    if !verify_bundle(&bundle) { errors.push("BUNDLE_INVALID") } // §4.3
    if !check_authority(&j, &bundle) { errors.push("AUTHORITY_MISMATCH") }
    if !check_input_echo(&j) { errors.push("VERDICT_INPUT_MISMATCH") }
    if !check_matches(&j) { errors.push("EVENT_MATCHES_MISMATCH") }
    if !check_coverage(&j) { errors.push("COVERAGE_INCONSISTENT") }
    let mut vi = j["verdict_input"].clone();
    if let Some(vw) = view {
        // §4.5: withheld fields come from THIS view's manifest, nowhere else
        vi["view"] = json!({ "withheld_fields": withheld_fields(vw) });
    }
    if !errors.is_empty() {
        if !vi["authority"].is_object() { vi["authority"] = json!({}) }
        vi["authority"]["integrity"] = json!("INVALID"); // never a partial pass
    }
    let vector = derive_vector(&vi);
    let mark = vector["mark"].clone();
    if let Some(vw) = view {
        view_checks(vw, id, &bundle, &mark, &mut errors);
    }
    let cross = errors.is_empty();
    report(true, layers, Some(id), true, cross, vector, mark, &errors)
}

fn run_view(view: &C) -> J {
    let held = |id: Option<&str>, errs: &[&str]| report(true, &["view"], id, false, false, J::Null, J::Null, errs);
    let id = ctext(view, "certificate_id");
    if matches!(cget(view, "disclosures"), Some(C::Array(a)) if a.len() > MAX_DISCLOSURES) {
        return held(id, &["OVER_CAP"]);
    }
    let Some(id) = id else { return held(None, &["VIEW_MALFORMED"]) };
    let Some(core_b) = cbytes(view, "core") else {
        // the view layer alone: held, rendered, nothing recomputed (§2)
        return held(Some(id), &[]);
    };
    if core_b.len() > MAX_CORE_BYTES { return held(Some(id), &["OVER_CAP"]) }
    let Some(core) = decode_cbor(core_b, MAX_DEPTH as usize, MAX_CORE_BYTES) else {
        return held(Some(id), &["PARSE"]);
    };
    let both = |errs: &[&str]| report(true, &["core", "view"], Some(id), true, false, J::Null, J::Null, errs);
    if hex(&sha256(core_b)) != id { return both(&["CERTIFICATE_ID_MISMATCH"]) } // §4.2
    if ctext(&core, "schema") != Some(CORE_SCHEMA) { return both(&["CORE_MALFORMED"]) }
    verify_core(id, &core, Some(view))
}

fn run(bytes: &[u8]) -> J {
    // §4.1 caps before crypto: byte/depth caps + canonical-profile decode
    let Some(top) = decode_cbor(bytes, MAX_DEPTH as usize, MAX_BYTES) else {
        return report(false, &[], None, false, false, J::Null, J::Null, &["PARSE"]);
    };
    match ctext(&top, "schema") {
        Some(CORE_SCHEMA) if bytes.len() > MAX_CORE_BYTES => {
            report(true, &["core"], None, true, false, J::Null, J::Null, &["OVER_CAP"])
        }
        Some(CORE_SCHEMA) => verify_core(&hex(&sha256(bytes)), &top, None),
        Some(VIEW_SCHEMA) => run_view(&top),
        _ => report(true, &[], None, false, false, J::Null, J::Null, &["SCHEMA"]),
    }
}

/// Verify certificate bytes (bare core or view envelope) and return the JSON
/// result dict `{parse_ok, layers, certificate_id, core_present,
/// cross_checks_ok, vector, mark, errors}` — same shape as Python's
/// `verify_certificate`. Total on hostile input: never panics. With the
/// `wasm` feature this same symbol is the wasm export for the static page.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_certificate_cbor(bytes: &[u8]) -> String {
    serde_json::to_string(&run(bytes)).unwrap_or_else(|_| {
        // unreachable for this value shape; fail closed rather than panic
        r#"{"parse_ok":false,"layers":[],"certificate_id":null,"core_present":false,"cross_checks_ok":false,"vector":null,"mark":null,"errors":["PARSE"]}"#.into()
    })
}
