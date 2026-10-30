// Apache-2.0 (public verifier repo)
//! Recompute the complete two-party package; a bundle signature is not a statement proof.
use crate::{body_of, collect_key_entries, hex, jcs, receipt_hash_hex, sha256, trust, verify_bundle_facts, MAX_BUNDLE_BYTES};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const FIELDS: &[&str] = &["action_type", "external_ref", "value", "amount", "amount_band", "currency", "counterparty", "counterparty_class", "recipient", "status", "result", "mandate_present"];
const SCOPE: &str = "This reconciliation reports what each party's independently verified bundle can support. It does not determine fault, intent, liability, or which party's record reflects what actually happened. Absence of a receipt from a presented export is absence of support, not proof that no event occurred.";
const CONFLICT: &str = "Both parties' verified bundles carry receipts for this claim; the named material fields do not carry the same values. This reconciliation reports the disagreement; it does not determine which record is accurate.";
const ONE_SIDED: &str = "Both parties' verified bundles carry receipts for this claim, but one or more named material fields are carried by only one side. The presented evidence therefore cannot establish material agreement.";
const AGREEMENT: &str = "Both parties' verified bundles carry receipts for this claim and every material field carried by both sides matches.";

type Claims = BTreeMap<String, Vec<Value>>;
type DisputeInputs<'a> = ([&'a str; 2], &'a Map<String, Value>, Vec<&'a str>);
struct Party {
    claims: Claims,
    facts: Value,
}

fn nonempty(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

fn header(package: &Value) -> Option<()> {
    let object = package.as_object()?;
    let fields = ["schema", "case_ref", "party_labels", "contested_claims", "bundles", "reconciliation"];
    if object.len() != fields.len() || !fields.iter().all(|field| object.contains_key(*field)) || package["schema"] != "evd/dispute-artifact/v1" {
        return None;
    }
    nonempty(&package["case_ref"])?;
    package["reconciliation"].as_object()?;
    Some(())
}

fn labels(package: &Value) -> Option<[&str; 2]> {
    let labels = package["party_labels"].as_array()?;
    if labels.len() != 2 {
        return None;
    }
    let labels = [nonempty(&labels[0])?, nonempty(&labels[1])?];
    let bundles = package["bundles"].as_object()?;
    if labels[0] == labels[1] || bundles.len() != 2 || !labels.iter().all(|label| bundles.get(*label).is_some_and(Value::is_object)) {
        return None;
    }
    Some(labels)
}

fn inputs(package: &Value) -> Option<DisputeInputs<'_>> {
    header(package)?;
    let labels = labels(package)?;
    let claims: Vec<_> = package["contested_claims"].as_array()?.iter().map(nonempty).collect::<Option<_>>()?;
    if !claims.windows(2).all(|pair| pair[0] < pair[1]) {
        return None;
    }
    Some((labels, package["bundles"].as_object()?, claims))
}

fn party(bundle: &Value) -> Option<Party> {
    let verified = verify_bundle_facts(bundle, None);
    if !verified.ok {
        return None;
    }
    let entries = bundle["entries"].as_array()?;
    let keys = collect_key_entries(entries);
    let root = receipt_hash_hex(keys.first()?.1)?;
    let mut claims = Claims::new();
    let mut uncorrelated = 0;
    for entry in entries {
        let body = body_of(&entry["envelope"])?;
        if body["agent_id"].as_str()?.starts_with('_') {
            continue;
        }
        let Some(id) = nonempty(&body["context"]["action_id"]) else {
            uncorrelated += 1;
            continue;
        };
        let mut view = Map::new();
        view.insert("action_type".into(), body["action_type"].clone());
        for field in &FIELDS[1..] {
            if let Some(value) = body["context"].get(*field) {
                view.insert((*field).into(), value.clone());
            }
        }
        view.insert("_receipt_hash".into(), json!(receipt_hash_hex(&entry["envelope"])?));
        claims.entry(id.into()).or_default().push(Value::Object(view));
    }
    let facts = json!({"origin": bundle["origin"], "trust_root": root, "export_complete": verified.complete,
        "claims": claims.len(), "uncorrelated_receipts": uncorrelated});
    Some(Party { claims, facts })
}

// v1 orders distinct material values by Python json.dumps(sort_keys=True),
// including ASCII escapes and its float exponent spelling. This is not JCS.
fn ascii_string(text: &str) -> String {
    let encoded = serde_json::to_string(text).expect("JSON string serialization");
    let mut out = String::new();
    for ch in encoded.chars() {
        if ch.is_ascii() && ch != '\u{7f}' {
            out.push(ch);
        } else {
            for unit in ch.encode_utf16(&mut [0; 2]) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn float_text(number: &serde_json::Number) -> Option<String> {
    let raw = number.to_string();
    let (mantissa, exponent) = raw.split_once('e').unwrap_or((&raw, "0"));
    let exponent: i32 = exponent.parse().ok()?;
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches('-');
    let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32;
    let digits = mantissa.replace('.', "");
    let zeros = digits.bytes().take_while(|byte| *byte == b'0').count();
    if zeros == digits.len() {
        return Some(if negative { "-0.0" } else { "0.0" }.into());
    }
    let power = point + exponent - zeros as i32 - 1;
    let digits = digits[zeros..].trim_end_matches('0');
    let sign = if negative { "-" } else { "" };
    if !(-4..16).contains(&power) {
        let fraction = if digits.len() > 1 { format!(".{}", &digits[1..]) } else { String::new() };
        return Some(format!("{sign}{}{fraction}e{power:+03}", &digits[..1]));
    }
    let point = power + 1;
    let body = if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else if point as usize >= digits.len() {
        format!("{digits}{}.0", "0".repeat(point as usize - digits.len()))
    } else {
        format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
    };
    Some(format!("{sign}{body}"))
}

pub(crate) fn value_key(value: &Value) -> Option<String> {
    Some(match value {
        Value::String(text) => ascii_string(text),
        Value::Number(number) if number.is_f64() => float_text(number)?,
        Value::Array(items) => format!("[{}]", items.iter().map(value_key).collect::<Option<Vec<_>>>()?.join(", ")),
        Value::Object(items) => {
            let pairs = items.iter().map(|(key, value)| Some(format!("{}: {}", ascii_string(key), value_key(value)?))).collect::<Option<Vec<_>>>()?;
            format!("{{{}}}", pairs.join(", "))
        }
        _ => value.to_string(),
    })
}

fn values(views: &[Value], field: &str) -> Option<Vec<Value>> {
    let mut unique = BTreeMap::new();
    for view in views {
        if let Some(value) = view.get(field) {
            unique.insert(value_key(value)?, value.clone());
        }
    }
    Some(unique.into_values().collect())
}

fn compare(a: &[Value], b: &[Value], labels: [&str; 2]) -> Option<(Value, &'static str, &'static str)> {
    let mut agreed = Vec::new();
    let mut conflicts = Map::new();
    let mut one_sided = Map::new();
    for field in FIELDS {
        let (va, vb) = (values(a, field)?, values(b, field)?);
        match (va.is_empty(), vb.is_empty()) {
            (true, true) => {}
            (false, false) => {
                if va.iter().map(value_key).collect::<Option<Vec<_>>>()? == vb.iter().map(value_key).collect::<Option<Vec<_>>>()? {
                    agreed.push(*field);
                } else {
                    conflicts.insert((*field).into(), json!({labels[0]: va, labels[1]: vb}));
                }
            }
            _ => {
                one_sided.insert((*field).into(), json!(labels[usize::from(va.is_empty())]));
            }
        }
    }
    let (outcome, statement) = if !conflicts.is_empty() {
        ("CONFLICT", CONFLICT)
    } else if !one_sided.is_empty() {
        ("UNSUPPORTED", ONE_SIDED)
    } else {
        ("AGREEMENT", AGREEMENT)
    };
    Some((json!({"agreed_fields": agreed, "conflicting_fields": conflicts, "one_sided_fields": one_sided}), outcome, statement))
}

fn statement(id: &str, parties: [&Party; 2], labels: [&str; 2]) -> Option<Value> {
    let views = [parties[0].claims.get(id).map(Vec::as_slice).unwrap_or(&[]), parties[1].claims.get(id).map(Vec::as_slice).unwrap_or(&[])];
    let supported: Vec<_> = (0..2).filter(|i| !views[*i].is_empty()).collect();
    let mut result = json!({"claim_id": id, "supported_by": supported.iter().map(|i| labels[*i]).collect::<Vec<_>>(),
        "unsupported_by": (0..2).filter(|i| views[*i].is_empty()).map(|i| labels[i]).collect::<Vec<_>>(),
        "receipt_hashes": {labels[0]: views[0].iter().map(|v| &v["_receipt_hash"]).collect::<Vec<_>>(), labels[1]: views[1].iter().map(|v| &v["_receipt_hash"]).collect::<Vec<_>>()}});
    let (outcome, text) = match supported.as_slice() {
        [_, _] => {
            let (comparison, outcome, text) = compare(views[0], views[1], labels)?;
            result.as_object_mut()?.extend(comparison.as_object()?.clone());
            (outcome, text.to_owned())
        }
        [holder] => {
            let lacking = 1 - holder;
            let note = if parties[lacking].facts["export_complete"].is_null() { "its export makes no completeness claim" } else { "its signed export manifest proves the presented set intact, not that the party's log holds nothing else" };
            ("UNSUPPORTED", format!("{}'s verified bundle carries a receipt for this claim; {}'s verified bundle contains none, and {note}. Absence of support is not proof that no event occurred.", labels[*holder], labels[lacking]))
        }
        _ => ("UNSUPPORTED", "Neither party's verified bundle carries a receipt supporting this claim.".into()),
    };
    result["outcome"] = json!(outcome);
    result["statement"] = json!(text);
    result["contested"] = json!(outcome != "AGREEMENT");
    Some(result)
}

pub(crate) fn reverify(package: &Value) -> Option<Value> {
    let (labels, bundles, contested) = inputs(package)?;
    let (a, b) = (party(&bundles[labels[0]])?, party(&bundles[labels[1]])?);
    if a.facts["origin"] == b.facts["origin"] || a.facts["trust_root"] == b.facts["trust_root"] {
        return None;
    }
    let population: BTreeSet<&str> = a.claims.keys().chain(b.claims.keys()).map(String::as_str).chain(contested).collect();
    let claims: Vec<_> = population.into_iter().map(|id| statement(id, [&a, &b], labels)).collect::<Option<_>>()?;
    let mut summary = Map::new();
    for outcome in ["AGREEMENT", "CONFLICT", "UNSUPPORTED"] {
        summary.insert(outcome.into(), json!(claims.iter().filter(|claim| claim["outcome"] == outcome).count()));
    }
    summary.insert("contested".into(), json!(claims.iter().filter(|claim| claim["contested"] == true).count()));
    let recomputed = json!({"schema": "evd/two-party-reconciliation/v1", "scope": SCOPE,
        "parties": {labels[0]: a.facts, labels[1]: b.facts}, "claims": claims, "summary": summary});
    // Compare types as well as values; JSON booleans must not stand in for counts.
    (value_key(&recomputed)? == value_key(&package["reconciliation"])?).then_some(recomputed)
}

pub(crate) fn verify_json(raw: &[u8]) -> Option<(Value, String)> {
    if raw.len() > 2 * MAX_BUNDLE_BYTES {
        return None;
    }
    let package = trust::strict_json(raw)?;
    let reconciliation = reverify(&package)?;
    Some((reconciliation, hex(&sha256(&jcs::canonical_checked(&package)?))))
}
