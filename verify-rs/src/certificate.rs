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
use std::collections::{BTreeMap, BTreeSet};

use crate::action::{authority_facts, derive_vector_with_trust};
use crate::cbor::{canonical_cbor, decode_cbor, MAX_BYTES, MAX_DEPTH};
use crate::scitt::{hex_to_bytes, verify_scitt_receipt};
use crate::{ed25519_verify, hex, key_from_jwk, replay_key_log, sha256};

const CORE_SCHEMA: &str = "evd/certificate/v1";
const VIEW_SCHEMA: &str = "evd/certificate-view/v1";
const VIEW_DOMAIN: &[u8] = b"evd/v1/certificate/view\x00";
// §4.1 caps (certificate-v1.cddl trailer); the 16 MiB pack cap is cbor::MAX_BYTES.
const MAX_CORE_BYTES: usize = 1024 * 1024;
const MAX_LIST: usize = 10_000;
const MAX_ATTACHMENTS: usize = 1_000;
const MAX_DISCLOSURES: usize = 256;
/// The CertificateCore and subject key sets, CLOSED in the FROZEN
/// SPEC/cddl/certificate-v1.cddl and unenforced until now: both engines
/// accepted subject["display_name"]="ACME BANK NV" + subject["amount"]="EUR
/// 5,000,000" with errors=[] and the top mark, inside a correctly signed view.
/// Attacker text in the identity block earns no vector at all, so this is a
/// GATE. `subject_ids` stays OPTIONAL — five weak families correctly carry
/// none, because `authority_facts` yields them no identity block.
const CORE_KEYS: [&str; 22] = ["schema", "subject", "bundle", "claim", "events", "event_matches", "source_identity", "control_evidence", "batch", "scan", "coverage_doc", "node_attestation", "open_findings", "proof_digests", "assurance_transcript_digest", "presentation_digest", "agent_context_digest", "verdict_input", "limitations", "current_through", "policy_version", "attachments"];
const SUBJECT_KEYS: [&str; 4] = ["action_id", "action_class", "origin", "subject_ids"];
/// SPEC/certificate-v1.md §3 called these "closed text codes" and never
/// enclosed the set; §3 now enumerates exactly these two. The unbound-coverage
/// residual is recorded as prose in §7's claim boundary, NOT as a third code.
const LIMITATION_CODES: [&str; 3] = ["AGENT_CONTEXT_UNBOUND", "ACCEPTED_SOURCE_COLLUSION_OUT_OF_MODEL", "COVERAGE_CONVENTIONS_UNBOUND"];
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------- utilities

fn cget<'a>(v: &'a C, key: &str) -> Option<&'a C> {
    let C::Map(m) = v else { return None };
    m.iter().find(|(k, _)| matches!(k, C::Text(t) if t == key)).map(|(_, x)| x)
}

fn ctext<'a>(v: &'a C, key: &str) -> Option<&'a str> {
    match cget(v, key)? {
        C::Text(t) => Some(t),
        _ => None,
    }
}

fn cbytes<'a>(v: &'a C, key: &str) -> Option<&'a [u8]> {
    match cget(v, key)? {
        C::Bytes(b) => Some(b),
        _ => None,
    }
}

/// Restricted CBOR → the JSON-compatible model; None on bytes/floats/tags
/// (the core is JSON-compatible by §1 — a bstr inside it is malformed).
fn cbor_to_json(v: &C, limit: i64) -> Option<J> {
    if limit < 0 {
        return None;
    }
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

/// Python `str()` of an optional SCALAR member: missing → "", null → "None".
/// A list or map has no spelling `str()` and serde_json share (`['a']` vs
/// `["a"]`), which split the engines' error lists on §4.4 Rule 5 and Rule 6.
/// The serde_json arm below is the agreed one; verify/certificate.py::_pyval
/// reproduces it, so changing either alone re-breaks that parity.
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
    match v.get(key) {
        None | Some(J::Null) => String::new(),
        other => pystr(other),
    }
}

/// The result dict, assembled by NAME rather than by an eight-slot positional
/// call: six of the eight members are bare booleans or JSON nulls, and every
/// early-return site leaves most of them at the "nothing to report" value that
/// `..Default::default()` supplies (false / `&[]` / None / `J::Null`).
#[derive(Default)]
struct Report<'a> {
    parse_ok: bool,
    layers: &'a [&'a str],
    certificate_id: Option<&'a str>,
    core_present: bool,
    cross_checks_ok: bool,
    vector: J,
    mark: J,
    errors: &'a [&'a str],
    /// The bundle's three-state completeness, SURFACED but never gated on
    /// (verify/verifier.py::_check_export_manifest). None on every path that
    /// never reached the bundle, and on every legitimate absence — bundles
    /// predating the manifest, and key-less replica exports.
    export_complete: Option<bool>,
}

impl Report<'_> {
    fn json(self) -> J {
        json!({
            "parse_ok": self.parse_ok, "layers": self.layers, "certificate_id": self.certificate_id,
            "core_present": self.core_present, "cross_checks_ok": self.cross_checks_ok,
            "vector": self.vector, "mark": self.mark, "errors": self.errors, "export_complete": self.export_complete,
        })
    }
}

// ------------------------------------------------- cross-checks (§4.3–§4.4)

fn check_authority(core: &J, bundle: &J) -> bool {
    let aid = core["subject"].get("action_id").and_then(J::as_str).filter(|a| !a.is_empty());
    core["verdict_input"].get("authority") == Some(&authority_facts(bundle, aid))
}

fn subject_origin_matches_bundle(core: &J, bundle: &J) -> bool {
    match (core["subject"].get("origin").and_then(J::as_str), bundle.get("origin").and_then(J::as_str)) {
        (Some(subject), Some(origin)) => subject == origin,
        _ => false,
    }
}

fn subject_action_id_matches_input(core: &J, bundle: &J) -> bool {
    match (core["subject"].get("action_id").and_then(J::as_str), core["verdict_input"].get("action").and_then(|action| action.get("action_id")).and_then(J::as_str)) {
        (Some(subject), Some(input)) => subject == input && (!subject.is_empty() || !crate::action::has_signed_action_intent(bundle)),
        _ => false,
    }
}

fn subject_action_class_matches_input(core: &J, bundle: &J) -> bool {
    match (core["subject"].get("action_class").and_then(J::as_str), core["verdict_input"].get("action").and_then(|action| action.get("action_class")).and_then(J::as_str)) {
        (Some(subject), Some(input)) => subject == input && (!subject.is_empty() || !crate::action::has_signed_action_intent(bundle)),
        _ => false,
    }
}

/// Producer-carried action fields must name signed material.
///
/// A bundle with no `action.intent` returned true outright, so the displayed
/// identity of every intent-free family was free text: both engines verified
/// `claim_only` relabelled to "wire.transfer.high_value", and to action_id
/// "act-DOES-NOT-EXIST", with cross_checks_ok=true and errors=[]. Deleting
/// `valid`'s one `action.intent` row and repairing the two derived members
/// (verdict_input.authority, subject.subject_ids — both pure functions of bytes
/// the attacker holds) walked a STRONG certificate into that branch.
///
/// So the fallback binds to the rows that survive. An empty action_id displays
/// nothing, so `orphan` (id "" AND class "") stays verifiable — but exempting
/// the PAIR let a BLANKED id buy an arbitrary class: orphan relabelled
/// "wire.transfer.high_value", and the same relabel on `valid` with its one
/// action.intent row deleted, both returned ok=true errors=[] over logs whose
/// surviving signed rows say payment.execute. The id may be absent; the class
/// still has to be signed. (`orphan`'s bundle DOES name act-1, so the weaker
/// rule "empty is only OK when the log names no action" breaks it.)
fn input_action_matches_signed_intent(core: &J, bundle: &J) -> bool {
    let action = core["verdict_input"].get("action").cloned().unwrap_or(J::Null);
    let (Some(action_id), Some(action_class)) = (action.get("action_id").and_then(J::as_str), action.get("action_class").and_then(J::as_str)) else { return false };
    if crate::action::has_signed_action_intent(bundle) {
        return crate::action::signed_action_context(bundle, action_id).is_some_and(|context| context.get("action_id").and_then(J::as_str) == Some(action_id) && context.get("action_class").and_then(J::as_str) == Some(action_class));
    }
    let (ids, classes) = crate::action::signed_action_intents(bundle, action_id);
    let class_ok = action_class.is_empty() || classes.contains(action_class);
    class_ok && (action_id.is_empty() || ids.contains(action_id))
}

/// The claim may not disagree with the subject about which action this is.
///
/// `claim` was compared only against `verdict_input` — producer against
/// producer. On `valid`, whose subject IS bound to a signed intent, relabelling
/// claim.action_id to "act-OTHER" and claim.action_class to
/// "wire.transfer.high_value" kept errors=[], identity VERIFIED and the top
/// mark: two action identities in one certificate. It is also the lever for the
/// material lie, since `material_mismatch` looks its field list up under
/// claim.action_class. An ABSENT claim is exempt and must be tested as "not a
/// map": `orphan` carries no `claim` (`? claim` in the CDDL) and the linkage
/// outcome depends on that absence to render ORPHAN.
fn claim_matches_subject(core: &J) -> bool {
    let Some(claim) = core.get("claim").filter(|c| c.is_object()) else { return true };
    ["action_id", "action_class"].iter().all(|k| pystr(claim.get(*k)) == pystr(core["subject"].get(*k)))
}

/// A limitation list is refutable by the core that carries it.
///
/// report/certify.py::_agent_context emits the all-zeros `agent_context_digest`
/// and AGENT_CONTEXT_UNBOUND together or emits neither, so the two carriages
/// are one fact — the doctrine `check_findings_carried` already uses. Stripping
/// the code while leaving the zeros left a certificate reading as "context
/// bound" to any consumer, errors=[] and the top mark in both engines;
/// limitations=["TOTALLY_MADE_UP_CODE", ""] verified clean too. A NON-zero
/// digest stays unverifiable — nothing in evd/bundle/v1 carries the three part
/// digests — so it remains a commitment a presentation must reproduce.
fn limitations_consistent(core: &J, bundle: &J) -> bool {
    let lims = core["limitations"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    // one length test settles all three: a non-text member, a duplicate and an
    // out-of-enum member each drop out of the set
    let codes: BTreeSet<&str> = lims.iter().filter_map(J::as_str).filter(|c| LIMITATION_CODES.contains(c)).collect();
    if codes.len() != lims.len() {
        return false;
    }
    if codes.contains("AGENT_CONTEXT_UNBOUND") != (core.get("agent_context_digest").and_then(J::as_str) == Some(ZERO_DIGEST)) {
        return false;
    }
    // COVERAGE_CONVENTIONS_UNBOUND is MANDATORY and VERIFIER-DERIVED: the engine
    // decides whether the conventions are tied to a signed `evd.coverage.recorded`
    // digest and requires the core to say the same. Both directions are closed — a
    // producer can neither omit the code when it applies (which is how deleting the
    // binding receipt used to make the whole clause pass silently, the producer
    // choosing whether to be checked) nor assert it when they really are bound.
    codes.contains("COVERAGE_CONVENTIONS_UNBOUND") != coverage_conventions_bound(core, bundle)
}

/// When the Node SIGNED a coverage document, the carried one must be it.
///
/// `coverage_doc` is `{ * text => any }` and carries the whole comparison
/// convention block — correlation_field, unique_fields, finality_rule,
/// material_fields — none of it echoed or cross-checked. No floor rule reaches
/// finality, which has no safe normative default (sources spell it
/// "settled"/"booked"/"POSTED"): finality_rule="pending" on `claim_only`
/// against a carried final=true upgraded CLAIM_ONLY → CORROBORATED in both
/// engines. One digest equality binds all four, and node/coverage.py
/// ::record_coverage puts that digest in the receipt's PLAINTEXT context, so no
/// commitment opening is needed. Conditional because none of the nine golden
/// families carries the receipt — "no signed binding → reject" breaks all nine.
fn coverage_doc_bound(core: &J, bundle: &J) -> bool {
    coverage_conventions_bound(core, bundle) || signed_coverage_digests(bundle).is_empty()
}

fn signed_coverage_digests(bundle: &J) -> BTreeSet<String> {
    crate::action::entry_rows(bundle).iter().filter(|r| r.action == "evd.coverage.recorded").filter_map(|r| r.ctx.get("coverage_doc_digest").and_then(J::as_str).map(str::to_string)).collect()
}

/// Whether the four mapping conventions are tied to SIGNED material.
///
/// Derived here rather than believed from the producer, because the certificate
/// must say so either way. `node/coverage.py::build_coverage` emits NONE of
/// correlation_field / unique_fields / finality_rule / material_fields — only the
/// golden generator ever wrote them — so in production the §4.4 material
/// recomputation is VACUOUS, and a certificate silent about that is making a
/// false proof. A limitation is cheaper than a false proof.
fn coverage_conventions_bound(core: &J, bundle: &J) -> bool {
    let signed = signed_coverage_digests(bundle);
    // an uncanonicalizable doc cannot match a signed digest
    !signed.is_empty() && crate::jcs::canonical_checked(&core["coverage_doc"]).is_some_and(|body| signed.contains(&hex(&sha256(&body))))
}

fn subject_ids_match_authority(core: &J, bundle: &J) -> bool {
    let Some(action_id) = core["subject"].get("action_id").and_then(J::as_str) else { return false };
    let subject_ids = core["subject"].get("subject_ids");
    let facts = authority_facts(bundle, Some(action_id));
    let expected = facts.get("subject_ids").and_then(J::as_object);
    match expected {
        Some(expected) if !expected.is_empty() => subject_ids.and_then(J::as_object).is_some_and(|ids| !ids.is_empty() && ids == expected),
        _ => matches!(subject_ids, None | Some(J::Null)),
    }
}

/// The engine consumes verdict_input while §4.4 recomputes over the core's
/// top-level members — the two carriages must agree, else a doctored
/// verdict_input could upgrade the recomputed headline unchecked. Missing
/// and null compare equal (Python `.get()` semantics).
fn check_input_echo(core: &J) -> bool {
    let vi = &core["verdict_input"];
    let listed = |k: &str| vi.get(k).filter(|v| crate::action::truthy(Some(v))).cloned().unwrap_or_else(|| json!([]));
    if core["events"] != listed("events") || core["event_matches"] != listed("event_matches") {
        return false;
    }
    ["claim", "source_identity", "control_evidence", "batch", "scan"].iter().all(|k| core.get(*k).filter(|v| !v.is_null()) == vi.get(*k).filter(|v| !v.is_null()))
}

/// §4.4: every finding the core carries must be one the verdict consumed.
///
/// `open_findings` and `verdict_input.findings` are two carriages for one fact,
/// and only the second gates coverage. A core holding an OPEN CRITICAL finding
/// the verdict input never saw verified CLOSED/ELIGIBLE with the finding absent
/// from the whole report (owner audit 2026-08-05).
fn check_findings_carried(core: &J) -> bool {
    let carried = core["open_findings"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    if carried.is_empty() {
        return true;
    }
    let Some(consumed) = core["verdict_input"].get("findings").and_then(|f| f.as_array()) else { return false };
    carried.iter().all(|f| consumed.contains(f))
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
    let echo = !token.is_empty() && ((!corr.is_empty() && pystr(ev.get(corr)) == token) || reference == token);
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
        if !ls.is_empty() && ls == pystr(Some(r)) {
            return true;
        }
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

/// §5 material comparison over the floor EXTENDED by the coverage doc's fields
/// for the claim's class; an absent side proves nothing (weak-claim doctrine).
///
/// The lookup key is still the producer-chosen `claim.action_class`, but a
/// missing or relabelled key now yields the floor instead of an empty list. On
/// the shipped `contradicted` fixture (claim 100.00, event 90.00), deleting
/// `coverage_doc.material_fields` — or emptying it, narrowing it to
/// ["currency"], or relabelling the class key with one trailing space — made
/// this recomputation agree with a carried `false` and restored errors=[].
/// `source_effect_time` stays skipped: a CDDL AgentActionClaim cannot state one.
fn material_mismatch(claim: &J, ev: &J, man: &J) -> bool {
    let class = pystr(claim.get("action_class"));
    let named = man.get("material_fields").and_then(|m| m.get(&class)).and_then(J::as_array);
    let mut fields: Vec<&str> = crate::action::MATERIAL_FLOOR.to_vec();
    for f in named.map(Vec::as_slice).unwrap_or(&[]).iter().filter_map(J::as_str) {
        if !fields.contains(&f) {
            fields.push(f);
        }
    }
    for f in fields.into_iter().filter(|f| *f != "source_effect_time") {
        let (l, r) = (claim.get(f).filter(|x| !x.is_null()), ev.get(f).filter(|x| !x.is_null()));
        if let (Some(l), Some(r)) = (l, r) {
            if pystr(Some(l)) != pystr(Some(r)) {
                return true;
            }
        }
    }
    false
}

fn flags_equal(m: &J, want: [bool; 5]) -> bool {
    ["echoed_action_id", "immutable_ref_match", "unique_field_match", "final", "material_mismatch"].iter().zip(want).all(|(k, w)| m.get(*k) == Some(&J::Bool(w)))
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
        if !flags_equal(m, [e, i, u, is_final(ev, man.get("finality_rule")), mat]) {
            return false;
        }
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
    if cov.get("event_count").and_then(J::as_i64) != Some(keys.len() as i64) {
        return false;
    }
    let Some(root) = crate::jcs::canonical_checked(&json!(keys)) else { return false };
    if cov.get("event_key_root") != Some(&json!(hex(&sha256(&root)))) {
        return false;
    }
    if !count_pair_ok(cov, "claim_refs", "claim_count") || !count_pair_ok(cov, "orphans", "orphan_count") {
        return false;
    }
    // The counts alone let a doc report CLOSED over a population that does not
    // contain the very action the certificate is about. An ABSENT claim stays
    // exempt — `orphan` has no claim member and its claim_refs is [].
    //
    // An absent claim_refs is NOT exempt. Treating "the doc makes no population
    // statement" as "not contradicted" handed the producer the switch: deleting
    // claim_refs AND claim_count skipped this clause entirely and still reported
    // coverage=CLOSED with a headline byte-identical to the honest certificate. A
    // certified claim not stated to be inside the covered population is NOT
    // ESTABLISHED, and this clause is deliberately independent of the conventions
    // binding so that one omission cannot disarm both.
    if let Some(claim) = core.get("claim").filter(|c| c.is_object()) {
        let Some(refs) = cov.get("claim_refs").and_then(J::as_array) else { return false };
        if !refs.iter().any(|r| pystr(Some(r)) == pystr(claim.get("action_id"))) {
            return false;
        }
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
    if frame.iter().any(|f| disagree(f)) {
        return false;
    }
    ["gaps", "exclusions"].iter().all(|l| {
        // an omitted batch gap/exclusion would be a silent overclaim
        let doc: BTreeSet<String> = cov.get(*l).and_then(J::as_array).map(|a| a.iter().map(|x| pystr(Some(x))).collect()).unwrap_or_default();
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
    let kept: Vec<(C, C)> = members.iter().filter(|(k, _)| !matches!(k, C::Text(t) if t == "signature" || t.ends_with("_sig"))).cloned().collect();
    let Some(body) = canonical_cbor(&C::Map(kept)) else { return false };
    let msg = [VIEW_DOMAIN, &body].concat();
    let entries = bundle.get("entries").and_then(J::as_array).cloned().unwrap_or_default();
    let kl = replay_key_log(&entries);
    kl.ok && kl.keys.values().any(|k| ed25519_verify(k, &msg, &sig))
}

fn withheld_fields(view: &C) -> J {
    cget(view, "manifest").and_then(|m| cget(m, "withheld_field_set")).and_then(|w| cbor_to_json(w, MAX_DEPTH)).filter(|w| w.is_array()).unwrap_or_else(|| json!([]))
}

fn view_checks(view: &C, id: &str, bundle: &J, mark: &J, errors: &mut Vec<&'static str>) {
    if !view_sig_ok(view, bundle) {
        errors.push("VIEW_SIGNATURE_INVALID")
    }
    let man = cget(view, "manifest");
    if man.and_then(|m| ctext(m, "certificate_id")) != Some(id) {
        errors.push("MANIFEST_MISMATCH")
    }
    // §4.5: the DISPLAYED mark must be what anyone recomputes from these bytes,
    // compared against the ANCHOR-FREE derivation — a producer cannot know which
    // roots a relying party supplies and must never mint the anchored verdict.
    if man.and_then(|m| ctext(m, "mark_result")) != mark.as_str() {
        errors.push("MARK_MISMATCH")
    }
}

// ------------------------------------------------- scitt override (SPEC §6)

/// TS trust keys (kid → raw pubkey) from the pack's published ts_jwks.
fn scitt_ts_keys(pack: &J) -> BTreeMap<String, [u8; 32]> {
    let mut keys = BTreeMap::new();
    let set = pack.get("ts_jwks").and_then(|j| j.get("keys")).and_then(J::as_array);
    for jwk in set.map(Vec::as_slice).unwrap_or(&[]) {
        if let Some((raw, kid)) = key_from_jwk(jwk) {
            keys.insert(kid, raw);
        }
    }
    keys
}

/// The certificate's own key-log keys — the issuer set §6.2 verifies the
/// Signed Statement under; empty if the log is unsound.
fn scitt_issuer_keys(bundle: &J) -> BTreeMap<String, [u8; 32]> {
    let entries = bundle.get("entries").and_then(J::as_array).cloned().unwrap_or_default();
    let kl = replay_key_log(&entries);
    if kl.ok {
        kl.keys
    } else {
        BTreeMap::new()
    }
}

/// SPEC §6: `scitt_receipt_valid` is VERIFIER-DERIVED. When the registration
/// layer carries a scitt pack whose `certificate_id` matches, recompute the
/// flag via `verify_scitt_receipt` and OVERRIDE any producer-supplied value
/// BEFORE `derive_vector` — a producer can never self-assert REGISTERED, and a
/// forged/mismatched pack forces the flag false. No pack → the field is untouched.
/// SPEC §6: `scitt_receipt_valid` is VERIFIER-DERIVED — ALWAYS, not only when a
/// pack happens to be carried.
///
/// This returned EARLY when `registration.scitt_pack` was absent, leaving the
/// PRODUCER's own boolean standing. `scitt_receipt_valid` is the last gate on
/// REGISTERED and one of the ANDs on ELIGIBLE, so it is a favourable value, and
/// the trust-anchor doctrine says a favourable value may never derive from an
/// input the subject supplies. No pack means no verified receipt, which is the
/// same thing as a failed one (weak-claim). Python was corrected first; leaving
/// this early return would have made the two engines disagree on every
/// certificate that carries no pack — which, since nothing in production
/// assembles one, is all of them (owner audit 2026-08-05, second pass).
fn apply_scitt_override(vi: &mut J, id: &str, bundle: &J) {
    let pack = match vi.get("registration").and_then(|r| r.get("scitt_pack")) {
        Some(p) if p.is_object() => p.clone(),
        _ => {
            if vi.get("registration").map(J::is_object).unwrap_or(false) {
                vi["registration"]["scitt_receipt_valid"] = json!(false);
            }
            return;
        }
    };
    let ss = pack.get("signed_statement").and_then(J::as_str).and_then(hex_to_bytes);
    let rc = pack.get("receipt").and_then(J::as_str).and_then(hex_to_bytes);
    let ok = pack.get("certificate_id").and_then(J::as_str) == Some(id)
        && match (ss, rc) {
            (Some(ss), Some(rc)) => verify_scitt_receipt(&ss, &rc, &scitt_ts_keys(&pack), &scitt_issuer_keys(bundle), id),
            _ => false,
        };
    vi["registration"]["scitt_receipt_valid"] = json!(ok);
}

// ----------------------------------------------------------------- pipeline

fn core_shape_ok(j: &J) -> bool {
    ["subject", "bundle", "coverage_doc", "verdict_input"].iter().all(|k| j.get(*k).map(|v| v.is_object()).unwrap_or(false)) && ["events", "event_matches", "open_findings", "proof_digests", "limitations"].iter().all(|k| j.get(*k).map(|v| v.is_array()).unwrap_or(false))
}

/// SUBSET only: the existing SUBJECT_*_MISMATCH / CORE_MALFORMED paths already
/// produce closed codes for presence and type, and moving them would change
/// error spellings the hardening tests pin.
fn core_keys_ok(j: &J) -> bool {
    let closed = |v: &J, allowed: &[&str]| v.as_object().is_some_and(|m| m.keys().all(|k| allowed.contains(&k.as_str())));
    closed(j, &CORE_KEYS) && closed(&j["subject"], &SUBJECT_KEYS)
}

fn core_caps_ok(j: &J) -> bool {
    let len = |k: &str| j.get(k).and_then(J::as_array).map(Vec::len).unwrap_or(0);
    // `limitations` had no cap at all: 20 000 entries verified clean
    len("events") <= MAX_LIST && len("event_matches") <= MAX_LIST && len("open_findings") <= MAX_LIST && len("limitations") <= MAX_LIST && len("attachments") <= MAX_ATTACHMENTS
}

/// The §4.3–§4.4 cross-checks in their PINNED order — every way the certificate
/// can disagree with the bundle it embeds. The list is compared element-wise
/// against verify/certificate.py, so a code inserted anywhere but its pinned
/// position breaks parity. Also carries out the bundle's completeness
/// tri-state, which this layer used to compute and discard.
fn cross_check_errors(j: &J, bundle: &J) -> (Vec<&'static str>, Option<bool>) {
    let (bundle_ok, complete) = crate::verify_bundle_report(bundle);
    let checks: [(bool, &'static str); 14] = [
        (bundle_ok, "BUNDLE_INVALID"), // §4.3
        (subject_origin_matches_bundle(j, bundle), "SUBJECT_ORIGIN_MISMATCH"),
        (subject_action_id_matches_input(j, bundle), "SUBJECT_ACTION_ID_MISMATCH"),
        (subject_action_class_matches_input(j, bundle), "SUBJECT_ACTION_CLASS_MISMATCH"),
        (input_action_matches_signed_intent(j, bundle), "ACTION_CONTEXT_MISMATCH"),
        (claim_matches_subject(j), "CLAIM_IDENTITY_MISMATCH"),
        (subject_ids_match_authority(j, bundle), "SUBJECT_IDS_MISMATCH"),
        (check_authority(j, bundle), "AUTHORITY_MISMATCH"),
        (check_input_echo(j), "VERDICT_INPUT_MISMATCH"),
        (check_findings_carried(j), "FINDINGS_NOT_CONSUMED"),
        (check_matches(j), "EVENT_MATCHES_MISMATCH"),
        (check_coverage(j), "COVERAGE_INCONSISTENT"),
        (coverage_doc_bound(j, bundle), "COVERAGE_DOC_MISMATCH"),
        (limitations_consistent(j, bundle), "LIMITATIONS_INCONSISTENT"),
    ];
    (checks.iter().filter(|(ok, _)| !ok).map(|(_, code)| *code).collect(), complete)
}

fn verify_core(id: &str, core: &C, view: Option<&C>, trust: Option<&J>) -> J {
    let layers: &[&str] = if view.is_some() { &["core", "view"] } else { &["core"] };
    let held = |errs: &[&str]| Report { parse_ok: true, layers, certificate_id: Some(id), core_present: true, errors: errs, ..Default::default() }.json();
    let Some(j) = cbor_to_json(core, MAX_DEPTH).filter(core_shape_ok) else { return held(&["CORE_MALFORMED"]) };
    if !core_keys_ok(&j) {
        return held(&["CORE_UNDECLARED_FIELD"]); // pinned gate order: malformed, undeclared, over-cap
    }
    if !core_caps_ok(&j) {
        return held(&["OVER_CAP"]);
    }
    let bundle = j["bundle"].clone();
    let (mut errors, complete) = cross_check_errors(&j, &bundle);
    let mut vi = j["verdict_input"].clone();
    if let Some(vw) = view {
        // §4.5: withheld fields come from THIS view's manifest, nowhere else
        vi["view"] = json!({ "withheld_fields": withheld_fields(vw) });
    }
    if !errors.is_empty() {
        if !vi["authority"].is_object() {
            vi["authority"] = json!({})
        }
        vi["authority"]["integrity"] = json!("INVALID"); // never a partial pass
    }
    apply_scitt_override(&mut vi, id, &bundle); // SPEC §6: DERIVE scitt_receipt_valid
    let vector = derive_vector_with_trust(&vi, trust);
    // The DISPLAYED mark is cross-checked against the ANCHOR-FREE derivation:
    // a producer cannot know which roots a relying party will supply, and must
    // never be able to mint the anchored verdict (mirrors verify/certificate.py).
    let baseline = if trust.is_some() { derive_vector_with_trust(&vi, None) } else { vector.clone() };
    let mark = vector["mark"].clone();
    if let Some(vw) = view {
        view_checks(vw, id, &bundle, &baseline["mark"], &mut errors);
    }
    let cross = errors.is_empty();
    Report { parse_ok: true, layers, certificate_id: Some(id), core_present: true, cross_checks_ok: cross, vector, mark, errors: &errors, export_complete: complete }.json()
}

fn run_view(view: &C, trust: Option<&J>) -> J {
    let held = |id: Option<&str>, errs: &[&str]| Report { parse_ok: true, layers: &["view"], certificate_id: id, errors: errs, ..Default::default() }.json();
    let id = ctext(view, "certificate_id");
    if matches!(cget(view, "disclosures"), Some(C::Array(a)) if a.len() > MAX_DISCLOSURES) {
        return held(id, &["OVER_CAP"]);
    }
    let Some(id) = id else { return held(None, &["VIEW_MALFORMED"]) };
    let Some(core_b) = cbytes(view, "core") else {
        // The issuer key log is carried by the withheld core. Without it (or
        // a future separately supplied view-key trust input), neither the
        // detached signature nor manifest is authenticated. Shape is not a
        // pass.
        return held(Some(id), &["VIEW_SIGNATURE_UNVERIFIED"]);
    };
    if withheld_fields(view).as_array().map(|v| !v.is_empty()).unwrap_or(false) {
        // A manifest cannot label bytes withheld while carrying the complete
        // core that contains them. Reject this leaky producer output before
        // parsing or crypto; it is not selective disclosure.
        return Report { parse_ok: true, layers: &["core", "view"], certificate_id: Some(id), core_present: true, errors: &["WITHHELD_CORE_PRESENT"], ..Default::default() }.json();
    }
    if core_b.len() > MAX_CORE_BYTES {
        return held(Some(id), &["OVER_CAP"]);
    }
    let Some(core) = decode_cbor(core_b, MAX_DEPTH as usize, MAX_CORE_BYTES) else { return held(Some(id), &["PARSE"]) };
    let both = |errs: &[&str]| Report { parse_ok: true, layers: &["core", "view"], certificate_id: Some(id), core_present: true, errors: errs, ..Default::default() }.json();
    if hex(&sha256(core_b)) != id {
        return both(&["CERTIFICATE_ID_MISMATCH"]);
    } // §4.2
    if ctext(&core, "schema") != Some(CORE_SCHEMA) {
        return both(&["CORE_MALFORMED"]);
    }
    verify_core(id, &core, Some(view), trust)
}

fn run(bytes: &[u8], trust: Option<&J>) -> J {
    // §4.1 caps before crypto: byte/depth caps + canonical-profile decode
    let Some(top) = decode_cbor(bytes, MAX_DEPTH as usize, MAX_BYTES) else { return Report { parse_ok: false, errors: &["PARSE"], ..Default::default() }.json() };
    match ctext(&top, "schema") {
        Some(CORE_SCHEMA) if bytes.len() > MAX_CORE_BYTES => Report { parse_ok: true, layers: &["core"], core_present: true, errors: &["OVER_CAP"], ..Default::default() }.json(),
        Some(CORE_SCHEMA) => verify_core(&hex(&sha256(bytes)), &top, None, trust),
        Some(VIEW_SCHEMA) => run_view(&top, trust),
        _ => Report { parse_ok: true, errors: &["SCHEMA"], ..Default::default() }.json(),
    }
}

/// Verify certificate bytes (bare core or view envelope) and return the JSON
/// result dict `{parse_ok, layers, certificate_id, core_present,
/// cross_checks_ok, vector, mark, errors}` — same shape as Python's
/// `verify_certificate`. Total on hostile input: never panics. With the
/// `wasm` feature this same symbol is the wasm export for the static page.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_certificate_cbor(bytes: &[u8]) -> String {
    verify_certificate_cbor_with_trust(bytes, None)
}

/// As above, with an `evd/trust-context/v1` naming the roots THIS RELYING PARTY
/// accepts. Passed separately from the certificate bytes so the subject cannot
/// supply its own anchors; with `None` every externally-grounded dimension
/// renders weak (mirror of `verify/certificate.py`).
pub fn verify_certificate_cbor_with_trust(bytes: &[u8], trust: Option<&J>) -> String {
    serde_json::to_string(&run(bytes, trust)).unwrap_or_else(|_| {
        // unreachable for this value shape; fail closed rather than panic
        r#"{"parse_ok":false,"layers":[],"certificate_id":null,"core_present":false,"cross_checks_ok":false,"vector":null,"mark":null,"errors":["PARSE"],"export_complete":null}"#.into()
    })
}
