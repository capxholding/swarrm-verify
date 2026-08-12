// Apache-2.0 (public verifier repo)
//! The Rust twin of tests/test_certificate_binding.py — the producer-supplied
//! fields the verifier used to consume as authoritative.
//!
//! Certificate subjects must be immutable while reporting verified. This module
//! verifies the same rule in the second engine: which fields count as
//! material, whether the comparison can be steered by field ORDER or by a field
//! no manifest names, the displayed action identity when the bundle carries no
//! `action.intent`, whether the `claim` may name a different action than the
//! `subject`, whether the covered population contains the certified claim,
//! whether the convention block is the one the Node signed, whether a
//! `limitations` list may retract what the core's own digest asserts, and
//! whether a key outside the CLOSED CDDL key sets may ride inside `subject`.
//!
//! Every case verified CLEAN at a2cac48 in BOTH engines with errors=[]. The
//! error SPELLINGS asserted here are byte-identical to the Python module's, so
//! a divergence in either engine fails this file.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[path = "../src/cbor.rs"]
#[allow(dead_code)]
mod cbor;
#[path = "../src/cbor_wire.rs"]
#[allow(dead_code)]
mod cbor_wire;
#[path = "../src/jcs.rs"]
#[allow(dead_code)]
mod jcs;

use ciborium::Value as C;

fn golden(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden").join(sub)
}

fn trust(sub: &str) -> J {
    serde_json::from_str(&fs::read_to_string(golden(sub).join("trust_context.json")).unwrap()).unwrap()
}

/// The restricted CBOR the certificate profile allows (§1: the core is
/// JSON-compatible), so a fixture can be mutated as JSON and re-encoded with
/// `cbor::canonical_from_json`.
fn to_json(v: &C) -> J {
    match v {
        C::Null => J::Null,
        C::Bool(b) => json!(b),
        C::Integer(i) => json!(i64::try_from(*i).unwrap()),
        C::Text(t) => json!(t),
        C::Array(a) => J::Array(a.iter().map(to_json).collect()),
        C::Map(m) => J::Object(m.iter().map(|(k, x)| (k.as_text().unwrap().to_string(), to_json(x))).collect()),
        other => panic!("out-of-profile CBOR in a golden fixture: {other:?}"),
    }
}

fn core(name: &str) -> J {
    let raw = fs::read(golden("certificates").join(format!("{name}.core.cbor"))).unwrap();
    to_json(&cbor::decode_cbor(&raw, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).expect("golden core parses"))
}

fn verify(core: &J) -> J {
    let bytes = cbor::canonical_from_json(core).expect("mutated core is canonicalizable");
    serde_json::from_str(&swarrm_verify::certificate::verify_certificate_cbor_with_trust(&bytes, Some(&trust("certificates")))).unwrap()
}

fn errors(res: &J) -> Vec<String> {
    res["errors"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()).collect()
}

fn has_error(res: &J, code: &str) -> bool {
    errors(res).iter().any(|e| e == code)
}

/// Clear the adverse admission on both carriages of every match row: a carried
/// `material_mismatch: true` is believed outright, so leaving it set would let
/// the fixture pass for the wrong reason.
fn flag_false(core: &mut J) {
    for path in [vec!["event_matches"], vec!["verdict_input", "event_matches"]] {
        let mut node = &mut core[path[0]];
        for key in &path[1..] {
            node = &mut node[*key];
        }
        for row in node.as_array_mut().unwrap() {
            row["material_mismatch"] = json!(false);
        }
    }
}

fn outcome(vi: &J) -> String {
    swarrm_verify::action::derive_vector_with_trust(vi, Some(&trust("reconcile")))["outcome"].as_str().unwrap().to_string()
}

fn lying_agent() -> J {
    serde_json::from_str(&fs::read_to_string(golden("reconcile").join("lying_agent_value_flip.json")).unwrap()).unwrap()
}

// -- Rule 1: the material floor extends, it never retracts --------------------

#[test]
fn a_producer_named_field_list_cannot_retract_the_floor() {
    // The lying-agent fixture demonstrates this claim:
    // value 999999.99 against event value 380.99. At HEAD one added key —
    // `source_manifest.material_fields: ["currency"]` — REPLACED the default
    // trio and both engines answered CORROBORATED.
    let mut vi = lying_agent();
    assert_eq!(outcome(&vi), "CONTRADICTED");
    for row in vi["event_matches"].as_array_mut().unwrap() {
        row["material_mismatch"] = json!(false);
    }
    assert_eq!(outcome(&vi), "CONTRADICTED");
    vi["source_manifest"] = json!({"material_fields": ["currency"]});
    assert_eq!(outcome(&vi), "CONTRADICTED");
}

#[test]
fn the_producer_tail_still_widens_the_comparison() {
    // Appending is the point: node/reconcile.py names class-specific fields
    // outside the trio, and those must keep being compared.
    let mut vi = lying_agent();
    for row in vi["event_matches"].as_array_mut().unwrap() {
        row["material_mismatch"] = json!(false);
    }
    vi["claim"]["value"] = vi["events"][0]["value"].clone();
    assert_eq!(outcome(&vi), "CORROBORATED");
    vi["claim"]["reference"] = json!("ref-A");
    vi["events"][0]["reference"] = json!("ref-B");
    vi["source_manifest"] = json!({"material_fields": ["reference"]});
    assert_eq!(outcome(&vi), "CONTRADICTED");
}

#[test]
fn the_coverage_doc_cannot_disarm_the_material_recomputation() {
    // §4.4 recomputes `material_mismatch` over an UNSIGNED, unechoed map. On
    // the `contradicted` core (claim 100.00 vs event 90.00) each of
    // these made the recomputation agree with a carried `false` and restored
    // errors=[] — deleting the member, emptying it, narrowing it to a subset
    // of the floor, or relabelling the class key by one trailing space.
    let mutations: [(&str, J); 4] = [("deleted", J::Null), ("emptied", json!({})), ("narrowed", json!({"payment.execute": ["currency"]})), ("key_relabelled", json!({"payment.execute ": ["value", "currency"]}))];
    for (id, replacement) in mutations {
        let mut c = core("contradicted");
        if replacement.is_null() {
            c["coverage_doc"].as_object_mut().unwrap().remove("material_fields");
        } else {
            c["coverage_doc"]["material_fields"] = replacement;
        }
        flag_false(&mut c);
        let res = verify(&c);
        assert_eq!(errors(&res), ["EVENT_MATCHES_MISMATCH"], "{id}");
        assert_eq!(res["cross_checks_ok"], json!(false), "{id}");
        assert_eq!(res["vector"]["outcome"], json!("CONTRADICTED"), "{id}");
    }
}

#[test]
fn the_two_disarms_combined_still_fail() {
    // R1 and R2 together: the certificate-layer recomputation silenced by the
    // coverage doc AND the engine-layer comparison narrowed by the manifest.
    let mut c = core("contradicted");
    c["coverage_doc"].as_object_mut().unwrap().remove("material_fields");
    flag_false(&mut c);
    c["verdict_input"]["source_manifest"] = json!({"material_fields": ["currency"]});
    let res = verify(&c);
    assert_eq!(errors(&res), ["EVENT_MATCHES_MISMATCH"]);
    assert_eq!(res["vector"]["outcome"], json!("CONTRADICTED"));
}

// -- Rule 2: order-free, and MISMATCH dominates UNCOMPARABLE ------------------

/// The minimal honest shape the reconcile gates accept, so a single field can
/// carry the whole experiment.
fn pair(claim_extra: J, event_extra: J, manifest: Option<J>) -> J {
    let mut claim = json!({"schema": "evd/claim/v1", "action_id": "act_1", "action_class": "payment.execute"});
    let mut event = json!({"schema": "evd/source-event/v1", "event_key": "ev_1", "finality": "final"});
    for (target, extra) in [(&mut claim, claim_extra), (&mut event, event_extra)] {
        for (k, v) in extra.as_object().unwrap() {
            target[k] = v.clone();
        }
    }
    let mut vi = json!({
        "schema": "evd/verdict-input/v1",
        "action": {"action_id": "act_1", "action_class": "payment.execute"},
        "claim": claim, "events": [event],
        "event_matches": [{"event_key": "ev_1", "echoed_action_id": true, "immutable_ref_match": false, "unique_field_match": false, "final": true, "material_mismatch": false}],
    });
    if let Some(man) = manifest {
        vi["source_manifest"] = man;
    }
    vi
}

#[test]
fn a_one_sided_field_cannot_mask_a_real_disagreement() {
    // Returning on the first one-sided field made the answer depend on
    // iteration order: a producer appends `memo`, present only on the claim,
    // and the `value` disagreement two positions later never gets evaluated —
    // CONTRADICTED softened to CLAIM_ONLY, which SPEC/reconcile-v1.md §5 forbids.
    let vi = pair(json!({"memo": "x", "value": "100.00", "currency": "EUR"}), json!({"value": "90.00", "currency": "EUR"}), Some(json!({"material_fields": ["memo", "value"]})));
    assert_eq!(outcome(&vi), "CONTRADICTED");
}

#[test]
fn a_one_sided_field_alone_is_still_uncomparable() {
    // Order-freedom must not turn absence into agreement.
    let vi = pair(json!({"memo": "x", "value": "100.00", "currency": "EUR"}), json!({"value": "100.00", "currency": "EUR"}), Some(json!({"material_fields": ["memo"]})));
    assert_eq!(outcome(&vi), "CLAIM_ONLY");
}

// -- Rule 3: an undeclared disagreement never corroborates --------------------

#[test]
fn an_undeclared_common_field_that_disagrees_cannot_corroborate() {
    // The beneficiary_iban class of lie: a field carried on BOTH sides that the
    // CDDL does not declare and no manifest names. In production
    // node/reconcile.py::_attach_material_fields copies the manifest's named
    // fields onto the claim, so such a field is material by construction — and
    // a bare name collision is still possible, so it may never ACCUSE.
    let vi = pair(json!({"value": "100.00", "currency": "EUR", "beneficiary_iban": "DE…001"}), json!({"value": "100.00", "currency": "EUR", "beneficiary_iban": "DE…009"}), None);
    assert_eq!(outcome(&vi), "CLAIM_ONLY");
    assert_ne!(outcome(&vi), "CONTRADICTED");
}

#[test]
fn schema_disagreement_is_structural_and_must_not_weaken_anything() {
    // `schema` is common to every honest pair and ALWAYS differs
    // ("evd/claim/v1" vs "evd/source-event/v1"). Comparing it would flag all
    // nine golden families — which is why it is in STRUCTURAL_FIELDS.
    let vi = pair(json!({"value": "100.00", "currency": "EUR"}), json!({"value": "100.00", "currency": "EUR"}), None);
    assert_ne!(vi["claim"]["schema"], vi["events"][0]["schema"]);
    assert_eq!(outcome(&vi), "CORROBORATED");
}

#[test]
fn the_out_of_floor_lie_reaches_the_certificate_layer() {
    // End to end on a real core with every producer knob turned: the headline
    // is WEAKER (CORROBORATED → CLAIM_ONLY), never a false accusation, and
    // cross_checks_ok stays true — a weaker claim is not an error.
    let mut c = core("contradicted");
    let honest = c["events"][0]["value"].clone();
    for path in [["claim"], ["verdict_input"]] {
        let side = if path[0] == "claim" { &mut c["claim"] } else { &mut c["verdict_input"]["claim"] };
        side["value"] = honest.clone();
        side["beneficiary_iban"] = json!("DE00000000000000000001");
    }
    c["events"][0]["beneficiary_iban"] = json!("DE00000000000000000009");
    c["verdict_input"]["events"][0]["beneficiary_iban"] = json!("DE00000000000000000009");
    c["coverage_doc"].as_object_mut().unwrap().remove("material_fields");
    flag_false(&mut c);
    let res = verify(&c);
    assert_eq!(res["cross_checks_ok"], json!(true), "{:?}", errors(&res));
    assert!(errors(&res).is_empty());
    assert_eq!(res["vector"]["outcome"], json!("CLAIM_ONLY"));
}

// -- Rule 4: the displayed action identity binds to surviving signed rows -----

#[test]
fn an_intent_free_family_cannot_relabel_its_action_class() {
    // No `action.intent` receipt meant `return true`, so the displayed class of
    // every intent-free family was attacker prose.
    for family in ["claim_only", "contradicted", "gapped", "stale"] {
        let mut c = core(family);
        c["subject"]["action_class"] = json!("wire.transfer.high_value");
        c["claim"]["action_class"] = json!("wire.transfer.high_value");
        c["verdict_input"]["claim"]["action_class"] = json!("wire.transfer.high_value");
        c["verdict_input"]["action"]["action_class"] = json!("wire.transfer.high_value");
        assert!(has_error(&verify(&c), "ACTION_CONTEXT_MISMATCH"), "{family}");
    }
}

#[test]
fn an_intent_free_family_cannot_invent_an_action_id() {
    let mut c = core("claim_only");
    c["subject"]["action_id"] = json!("act-DOES-NOT-EXIST");
    c["claim"]["action_id"] = json!("act-DOES-NOT-EXIST");
    c["verdict_input"]["claim"]["action_id"] = json!("act-DOES-NOT-EXIST");
    c["verdict_input"]["action"]["action_id"] = json!("act-DOES-NOT-EXIST");
    c["coverage_doc"]["claim_refs"] = json!(["act-DOES-NOT-EXIST"]);
    assert!(has_error(&verify(&c), "ACTION_CONTEXT_MISMATCH"));
}

#[test]
fn orphan_keeps_its_empty_identity_exemption() {
    // `orphan` displays "" while its bundle DOES name act-1, so "empty is only
    // OK when the log names no action" would break it. The exemption is
    // unconditional on the EMPTY value, exactly as HEAD relied on.
    let res = verify(&core("orphan"));
    assert!(errors(&res).is_empty(), "{:?}", errors(&res));
    assert_eq!(res["cross_checks_ok"], json!(true));
    assert_eq!(res["vector"]["outcome"], json!("ORPHAN"));
}

#[test]
fn stripping_the_signed_intent_and_repairing_the_derived_members_now_fails() {
    // The R5 chain. Deleting `valid`'s one `action.intent` row moved a STRONG
    // certificate into the free-text branch; `verdict_input.authority` and
    // `subject.subject_ids` are pure functions of bytes the attacker holds, so
    // repairing them cleared the two checks that used to catch it, and the
    // relabelled class then verified with errors=[]. The surviving rows still
    // say otherwise: `action.submitted` names act-1, the grant names
    // payment.execute, and neither spells "wire.transfer.high_value".
    let mut c = core("valid");
    let before = c["bundle"]["entries"].as_array().unwrap().len();
    let kept: Vec<J> = c["bundle"]["entries"].as_array().unwrap().iter().filter(|e| action_type_of(e).as_deref() != Some("action.intent")).cloned().collect();
    assert_eq!(kept.len(), before - 1);
    c["bundle"]["entries"] = J::Array(kept);
    let facts = swarrm_verify::action::authority_facts(&c["bundle"], Some("act-1"));
    c["verdict_input"]["authority"] = facts.clone();
    match facts.get("subject_ids").filter(|s| s.as_object().map(|m| !m.is_empty()).unwrap_or(false)) {
        Some(ids) => c["subject"]["subject_ids"] = ids.clone(),
        None => {
            c["subject"].as_object_mut().unwrap().remove("subject_ids");
        }
    }
    c["subject"]["action_class"] = json!("wire.transfer.high_value");
    c["claim"]["action_class"] = json!("wire.transfer.high_value");
    c["verdict_input"]["claim"]["action_class"] = json!("wire.transfer.high_value");
    c["verdict_input"]["action"]["action_class"] = json!("wire.transfer.high_value");
    assert!(has_error(&verify(&c), "ACTION_CONTEXT_MISMATCH"));
}

fn action_type_of(entry: &J) -> Option<String> {
    let payload = B64.decode(entry["envelope"]["payload"].as_str()?).ok()?;
    let body: J = serde_json::from_slice(&payload).ok()?;
    Some(body.get("action_type")?.as_str()?.to_string())
}

// -- Rule 5: the claim may not disagree with the subject ----------------------

#[test]
fn the_claim_cannot_name_a_different_action_than_the_subject() {
    // On `valid` — subject already bound to a signed intent — this kept the TOP
    // mark, identity VERIFIED and errors=[]: two action identities in one
    // certificate, one signature-backed and one not.
    let mut c = core("valid");
    c["claim"]["action_id"] = json!("act-OTHER");
    c["claim"]["action_class"] = json!("wire.transfer.high_value");
    c["verdict_input"]["claim"] = c["claim"].clone();
    assert!(has_error(&verify(&c), "CLAIM_IDENTITY_MISMATCH"));
}

#[test]
fn relabelling_the_claim_class_no_longer_disarms_the_value_check() {
    // R6d: the value lie whose class relabel made `material_mismatch` look up a
    // key that does not exist, so the §4.4 recomputation collapsed to false.
    let mut c = core("valid");
    c["claim"]["value"] = json!("999999.00");
    c["claim"]["action_class"] = json!("wire.transfer.high_value");
    c["verdict_input"]["claim"] = c["claim"].clone();
    assert_eq!(errors(&verify(&c)), ["CLAIM_IDENTITY_MISMATCH", "EVENT_MATCHES_MISMATCH"]);
}

#[test]
fn an_absent_claim_is_exempt_not_an_empty_one() {
    // `? claim` in the CDDL. Comparing a missing claim's absent members against
    // subject's "" would break `orphan`, whose ORPHAN outcome depends on the
    // member being absent.
    assert!(core("orphan").get("claim").is_none());
    assert!(errors(&verify(&core("orphan"))).is_empty());
}

// -- Rule 6: the certified claim must be inside the covered population --------

#[test]
fn the_covered_population_must_contain_the_certified_claim() {
    // `count_pair_ok` only asserted claim_count == len(claim_refs), so a doc
    // could report CLOSED over a population without the certified action in it.
    let mut c = core("valid");
    c["coverage_doc"]["claim_refs"] = json!(["act-SOMETHING-ELSE"]);
    assert!(has_error(&verify(&c), "COVERAGE_INCONSISTENT"));
}

#[test]
fn a_coverage_doc_making_no_population_statement_is_not_established() {
    // Treating "coverage_doc is an open CDDL map, so an absent claim_refs is
    // not a lie" as a pass hands the producer the
    // switch: deleting claim_refs AND claim_count skipped the population clause
    // entirely and still reported coverage=CLOSED with a headline byte-identical
    // to the honest certificate. A producer-selectable omission must yield NOT
    // ESTABLISHED, never a silently satisfied clause.
    let mut c = core("valid");
    let doc = c["coverage_doc"].as_object_mut().unwrap();
    doc.remove("claim_refs");
    doc.remove("claim_count");
    assert!(has_error(&verify(&c), "COVERAGE_INCONSISTENT"));
}

// -- Rule 7: a signed coverage document binds the whole convention block ------

/// None of the nine golden families carries `evd.coverage.recorded`, so the
/// binding needs a receipt of its own to be provable at all. `entry_rows` reads
/// the receipt's PLAINTEXT context out of the DSSE payload, so the digest is
/// reachable without a signature — which is exactly why an unsigned bundle
/// still exercises this rule: the check under test is the DIGEST equality, and
/// the surrounding BUNDLE_INVALID is asserted around, not through.
fn with_coverage_receipt(c: &mut J) {
    let digest = hex_sha256(&jcs::canonical_checked(&c["coverage_doc"]).unwrap());
    let tenant = c["bundle"]["origin"].as_str().unwrap().rsplit('/').next().unwrap();
    let body = json!({
        "schema": "evd/receipt/v1", "tenant_id": tenant, "agent_id": "_node", "seq": 9999,
        "action_type": "evd.coverage.recorded", "commitments": {},
        "context": {"coverage_doc_digest": digest}, "parents": [],
        "ts_client": "2026-01-01T00:00:00Z", "ts_server": "2026-01-01T00:00:00Z",
        "idempotency_key": "hostile-coverage-binding"
    });
    let payload = B64.encode(serde_json::to_vec(&body).unwrap());
    c["bundle"]["entries"].as_array_mut().unwrap().push(json!({"leaf_index": 9999, "envelope": {"payload": payload}}));
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_signed_coverage_document_verifies_as_carried() {
    let mut c = core("valid");
    with_coverage_receipt(&mut c);
    assert!(!has_error(&verify(&c), "COVERAGE_DOC_MISMATCH"), "{:?}", errors(&verify(&c)));
}

#[test]
fn no_convention_may_differ_from_the_signed_coverage_document() {
    // One digest equality binds all four. `finality_rule` is the one no floor
    // rule can reach — sources spell finality "settled"/"booked"/"POSTED", so
    // there is no safe normative default — and setting it to "pending" against
    // a carried final=true upgraded CLAIM_ONLY → CORROBORATED at HEAD.
    for convention in ["finality_rule", "material_fields", "correlation_field", "unique_fields"] {
        let mut c = core("valid");
        with_coverage_receipt(&mut c);
        c["coverage_doc"][convention] = if convention == "finality_rule" { json!("pending") } else { json!(["x"]) };
        assert!(has_error(&verify(&c), "COVERAGE_DOC_MISMATCH"), "{convention}");
    }
}

#[test]
fn no_signed_coverage_receipt_means_no_coverage_binding() {
    // Conditional by design: a "no signed binding → reject" rule would break
    // all nine golden families, none of which carries `evd.coverage.recorded`.
    for family in families() {
        assert!(!has_error(&verify(&core(&family)), "COVERAGE_DOC_MISMATCH"), "{family}");
    }
}

fn families() -> Vec<String> {
    let expected: J = serde_json::from_str(&fs::read_to_string(golden("certificates").join("expected.json")).unwrap()).unwrap();
    expected.as_object().unwrap().keys().cloned().collect()
}

// -- Rule 8: a limitation list is refutable by the core that carries it -------

#[test]
fn a_limitations_list_cannot_contradict_the_core_that_carries_it() {
    // `limitations` appeared exactly ONCE in each engine — an is-a-list gate —
    // and nowhere else. Retracting AGENT_CONTEXT_UNBOUND while leaving the
    // all-zeros `agent_context_digest` produced a certificate that reads as
    // "context bound" to any consumer, with errors=[] and the top mark.
    let cases: [(&str, J); 5] = [("retracted", json!([])), ("fabricated", json!(["TOTALLY_MADE_UP_CODE", "NOT_IN_ANY_SPEC_ENUM", ""])), ("duplicated", json!(["AGENT_CONTEXT_UNBOUND", "AGENT_CONTEXT_UNBOUND"])), ("non_text", json!(["AGENT_CONTEXT_UNBOUND", 7])), ("legal_code_wrong_pairing", json!(["ACCEPTED_SOURCE_COLLUSION_OUT_OF_MODEL"]))];
    for (id, limitations) in cases {
        let mut c = core("valid");
        c["limitations"] = limitations;
        assert!(has_error(&verify(&c), "LIMITATIONS_INCONSISTENT"), "{id}");
    }
}

#[test]
fn the_biconditional_holds_in_the_other_direction_too() {
    // A non-zero digest with the code still asserted is equally self-refuting.
    let mut c = core("valid");
    c["agent_context_digest"] = json!("ab".repeat(32));
    assert!(has_error(&verify(&c), "LIMITATIONS_INCONSISTENT"));
}

#[test]
fn a_bound_context_legitimately_carries_no_limitation() {
    // AGENT_CONTEXT_UNBOUND must be ABSENT once the context is bound, so
    // "limitations must be non-empty" is the wrong rule. `valid`'s bundle
    // carries no `evd.coverage.recorded`, so the verifier derives the coverage
    // conventions as unbound and that code stays mandatory — the list a fully
    // context-bound certificate carries here is exactly that one code.
    let mut c = core("valid");
    c["agent_context_digest"] = json!("cd".repeat(32));
    c["limitations"] = json!(["COVERAGE_CONVENTIONS_UNBOUND"]);
    assert!(!has_error(&verify(&c), "LIMITATIONS_INCONSISTENT"));
}

#[test]
fn limitations_now_has_a_member_count_cap() {
    // No cap in either engine: 20 000 entries verified clean, bounded only by
    // the 1 MiB core cap.
    let mut c = core("valid");
    c["limitations"] = J::Array(vec![json!("AGENT_CONTEXT_UNBOUND"); 10_001]);
    assert_eq!(errors(&verify(&c)), ["OVER_CAP"]);
}

// -- Rule 9: the CDDL key sets are CLOSED, and now enforced -------------------

#[test]
fn a_key_outside_the_closed_cddl_sets_earns_no_vector() {
    // certificate-v1.cddl closes both maps; neither engine ever compared a key
    // SET. Attacker-authored text riding inside the identity block rendered a
    // clean pass and the top mark, inside a correctly signed view.
    for id in ["subject_extras", "top_level"] {
        let mut c = core("valid");
        if id == "subject_extras" {
            c["subject"]["display_name"] = json!("ACME BANK NV");
            c["subject"]["amount"] = json!("EUR 5,000,000");
        } else {
            c["totally_unknown_top_level"] = json!("hello");
        }
        let res = verify(&c);
        assert_eq!(errors(&res), ["CORE_UNDECLARED_FIELD"], "{id}");
        assert_eq!(res["vector"], J::Null, "{id}"); // a gate, not a cross-check
        assert_eq!(res["mark"], J::Null, "{id}");
    }
}

#[test]
fn subject_ids_stays_optional() {
    // Five weak families correctly carry none: `authority_facts` yields them no
    // identity block. A "subject must always carry subject_ids" closure would
    // destroy exactly the unregistered families the format is meant to represent.
    for family in ["claim_only", "contradicted", "gapped", "orphan", "stale"] {
        let c = core(family);
        assert!(c["subject"].get("subject_ids").is_none(), "{family}");
        assert!(errors(&verify(&c)).is_empty(), "{family}");
    }
}

#[test]
fn the_gate_order_is_malformed_then_undeclared_then_over_cap() {
    // Pinned: both engines must report the same single code for a core that
    // trips more than one gate.
    let mut c = core("valid");
    c["subject"] = json!("not-a-map");
    c["extra"] = json!(1);
    assert_eq!(errors(&verify(&c)), ["CORE_MALFORMED"]);
    let mut c = core("valid");
    c["extra"] = json!(1);
    c["open_findings"] = J::Array(vec![json!("f"); 10_001]);
    assert_eq!(errors(&verify(&c)), ["CORE_UNDECLARED_FIELD"]);
}

// -- Rule 10: completeness is SURFACED at the certificate layer, never gated --

#[test]
fn the_result_carries_the_completeness_tri_state() {
    // The engine computed `verify_bundle(bundle)` and threw the tri-state away,
    // so a certificate consumer got a bare "VERIFIED" where a bundle consumer
    // got "VERIFIED (completeness unproven)".
    // asserted through `.get`, never `[]`: a MISSING member also indexes to
    // null, so `res["export_complete"] == null` passes on an engine that never
    // emits the member at all.
    let res = verify(&core("valid"));
    assert_eq!(res.get("export_complete"), Some(&J::Null));
    assert_eq!(res["cross_checks_ok"], json!(true)); // absence NEVER gates the engine
}

#[test]
fn the_completeness_tri_state_agrees_with_the_python_engine() {
    // None of the nine certificate families carries an export manifest, so the
    // tri-state would be null everywhere and prove nothing. These bundles do
    // carry one; the expectations are verify/verifier.py's own
    // `BundleReport.export_complete` for the SAME bytes, measured against the
    // patched Python engine. The surrounding certificate is invalid for these
    // bundles — irrelevant, because completeness NEVER gates.
    let expected = [("export_manifest_bad_ts", false), ("export_manifest_dropped", false), ("export_manifest_recorder", false), ("export_manifest_recorder_child", false), ("export_manifest_recorder_rotation", false), ("export_manifest_rotated_issuer", true), ("export_manifest_valid", true)];
    for (name, want) in expected {
        let mut c = core("valid");
        c["bundle"] = serde_json::from_str(&fs::read_to_string(golden("bundles").join(format!("{name}.json"))).unwrap()).unwrap();
        assert_eq!(verify(&c)["export_complete"], json!(want), "{name}");
    }
}

#[test]
fn a_path_that_never_reaches_the_bundle_reports_null() {
    let bare: J = serde_json::from_str(&swarrm_verify::certificate::verify_certificate_cbor(&[0xa0])).unwrap();
    assert_eq!(bare.get("export_complete"), Some(&J::Null));
    let mut c = core("valid");
    c["subject"] = json!("not-a-map");
    assert_eq!(verify(&c).get("export_complete"), Some(&J::Null));
}

#[test]
fn a_blanked_action_id_cannot_buy_an_arbitrary_action_class() {
    // The empty-id carve-out exempted the PAIR, so blanking the id bought a
    // free-text class on every intent-free family — and `valid` reached that
    // branch by deleting its one `action.intent` row, which leaves every
    // remaining signature and inclusion proof valid. `orphan` is the reason the
    // carve-out exists (it displays id "" AND class ""), so it must keep
    // verifying untouched. Twin of tests/test_certificate_binding.py::
    // test_a_blanked_action_id_cannot_buy_an_arbitrary_action_class.
    for family in ["valid", "claim_only", "contradicted", "gapped", "stale", "orphan", "revoked", "forged", "selectively_disclosed"] {
        let mut c = core(family);
        assert_eq!(verify(&c)["cross_checks_ok"], json!(true), "{family} clean");

        c["subject"]["action_id"] = json!("");
        c["subject"]["action_class"] = json!("wire.transfer.high_value");
        c["verdict_input"]["action"]["action_id"] = json!("");
        c["verdict_input"]["action"]["action_class"] = json!("wire.transfer.high_value");

        let res = verify(&c);
        assert_eq!(res["cross_checks_ok"], json!(false), "{family} relabelled");
        assert!(has_error(&res, "ACTION_CONTEXT_MISMATCH"), "{family}: {:?}", errors(&res));
    }
}

#[test]
fn the_container_spelling_both_engines_share_is_pinned() {
    // A CDDL `text` member holding a LIST or MAP had no spelling the engines
    // shared: Python str(["a"]) is "['a']" while pystr here falls through to
    // serde_json and renders ["a"]. §4.4 Rule 5 and the Rule 6 population clause
    // both compare producer values through it, so the split reached the error
    // list on 200 cores, in BOTH directions. scripts/gen_differential.py only
    // emits text action_id/action_class, so nothing pinned this until now.
    // Twin of tests/test_certificate_binding.py::
    // test_the_container_spelling_both_engines_share_is_pinned.
    let mut c = core("valid");
    c["claim"]["action_id"] = json!(["a"]);
    c["verdict_input"]["claim"]["action_id"] = json!(["a"]);
    c["coverage_doc"]["claim_refs"] = json!([["a"]]);
    assert!(!has_error(&verify(&c), "COVERAGE_INCONSISTENT"), "{:?}", errors(&verify(&c)));

    // the Python-only spelling must NOT satisfy it
    c["coverage_doc"]["claim_refs"] = json!(["['a']"]);
    assert!(has_error(&verify(&c), "COVERAGE_INCONSISTENT"));
}

#[test]
fn a_cbor_byte_string_anywhere_in_the_core_is_malformed_in_both_engines() {
    // §1 makes the core JSON-compatible, so a bstr inside it is malformed —
    // which cbor_to_json's `_ => return None` arm has always said. Python's
    // decoder accepted them, so the engines disagreed about the same bytes on
    // 11 of 11 probes. "Pre-existing" does not make an 11/11 divergence in the
    // trust path smaller. Twin of tests/test_certificate_binding.py.
    for family in ["valid", "claim_only", "orphan"] {
        // A JSON string cannot express a bstr, so mutate at the CBOR level. Only
        // one VALUE is replaced, so the canonical key order of the golden map is
        // untouched and the core still decodes as canonical — otherwise the
        // encoding gate would fire first and prove nothing about the bstr rule.
        let raw = fs::read(golden("certificates").join(format!("{family}.core.cbor"))).unwrap();
        let C::Map(mut entries) = cbor::decode_cbor(&raw, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).unwrap() else { panic!("core is a map") };
        for (key, value) in entries.iter_mut() {
            if matches!(key, C::Text(t) if t == "policy_version") {
                *value = C::Bytes(vec![0x01, 0x02]);
            }
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&C::Map(entries), &mut bytes).unwrap();

        let res: J = serde_json::from_str(&swarrm_verify::certificate::verify_certificate_cbor(&bytes)).unwrap();
        assert_eq!(res["cross_checks_ok"], json!(false), "{family}");
        assert!(has_error(&res, "CORE_MALFORMED"), "{family}: {:?}", errors(&res));
    }
}
