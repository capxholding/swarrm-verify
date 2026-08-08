// Apache-2.0 (public verifier repo)
//! Independent, offline B28 v1 verifier.
//!
//! The host supplies pinned roots and typed local context separately; exchange
//! bytes contain signed CWTs only and cannot nominate verifier state.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::Value as C;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use p256::ecdsa::{signature::Verifier, Signature as P256Signature, VerifyingKey as P256Key};
use serde_json::{Map as JsonMap, Value as J};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

const PROFILE: &str = "https://swarrm.ai/spec/eat/b28/cwt/v1";
const MEDIA: &str = "application/eat+cwt";
const LOCAL_CONTEXT: &str = "swarrm-b28/local-verifier-context/v1";
const LOCAL_REFUSAL_CONTEXT: &str = "swarrm-b28/local-refusal-context/v1";
const TRUST_PACK: &str = "swarrm-b28/trust-pack/v1";
const ACTION: &str = "swarrm-b28/action-core/v1";
const AGENT_REF: &str = "swarrm-b28/agent-ref/v1";
const RESOURCE_REF: &str = "swarrm-b28/resource-ref/v1";
const PARTY_REF: &str = "swarrm-b28/party-ref/v1";
const CHALLENGE: &str = "swarrm-b28/challenge-core/v1";
const ASA: &str = "swarrm-b28/asa-core/v1";
const PRESENTATION: &str = "swarrm-b28/presentation-core/v1";
const REFUSAL: &str = "swarrm-b28/refusal-core/v1";
const ROOT_DELEGATION: &str = "swarrm-b28/root-delegation/v1";
const TEMPLATE: &str = "swarrm-b28/registration-template/v1";
const ADMIN_BINDING: &str = "swarrm-b28/admin-binding/v1";
const ADMIN_SELECTION: &str = "swarrm-b28/admin-selection/v1";
const ADMIN_CHALLENGE: &str = "swarrm-b28/admin-challenge/v1";
const ADMIN_CONSUMPTION: &str = "swarrm-b28/admin-consumption/v1";
const AGENT_POP: &str = "swarrm-b28/agent-pop/v1";
const CREDENTIAL: &str = "swarrm-b28/agent-credential/v1";
const AGENT_SUCCESSOR: &str = "swarrm-b28/agent-successor/v1";
const GRANT: &str = "swarrm-b28/limit-grant/v1";
const CHECKPOINT: &str = "swarrm-b28/authority-checkpoint/v1";
const SNAPSHOT: &str = "swarrm-b28/status-snapshot/v1";
const MEMBERSHIP: &str = "swarrm-b28/authority-membership-proof/v1";
const NON_ASSERTION: &str = "This proves identity, current proof-bearing authority and durable replay at a bounded checkpoint. It does not evaluate Node, source, coverage, history or post-action evidence readiness in v1, predict behaviour, certify an outcome, establish later evidence, or express a Swarrm opinion.";
const MAX_CWT: usize = 65_536;
const MAX_INPUT: usize = 2 * 1024 * 1024;
const MAX_LOCAL_CONTEXT: usize = 65_536;
const MAX_LOCAL_ITEMS: usize = 64;
const MAX_CBOR_DEPTH: usize = 64;
const MAX_CBOR_ITEMS: usize = 100_000;
const CWT_PROFILE_CLAIM: i64 = 265;
const B28_CORE_CLAIM: i64 = -65_537;

type Doc = BTreeMap<String, C>;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    match arg {
        0..=23 => out.push((major << 5) | arg as u8),
        24..=0xff => out.extend_from_slice(&[(major << 5) | 24, arg as u8]),
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}
fn encode(value: &C, out: &mut Vec<u8>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    match value {
        C::Null => out.push(0xf6),
        C::Bool(value) => out.push(if *value { 0xf5 } else { 0xf4 }),
        C::Integer(value) => {
            let number = i128::from(*value);
            if !(i128::from(i64::MIN)..=i128::from(i64::MAX)).contains(&number) {
                return false;
            }
            if number >= 0 {
                let Ok(argument) = u64::try_from(number) else { return false };
                head(out, 0, argument);
            } else {
                let Ok(argument) = u64::try_from(-1 - number) else { return false };
                head(out, 1, argument);
            }
        }
        C::Bytes(value) => {
            head(out, 2, value.len() as u64);
            out.extend_from_slice(value);
        }
        C::Text(value) => {
            head(out, 3, value.len() as u64);
            out.extend_from_slice(value.as_bytes());
        }
        C::Array(values) => {
            head(out, 4, values.len() as u64);
            for value in values {
                if !encode(value, out, depth - 1) {
                    return false;
                }
            }
        }
        C::Map(entries) => return encode_map(entries, out, depth - 1),
        _ => return false,
    }
    true
}
fn encode_map(entries: &[(C, C)], out: &mut Vec<u8>, depth: usize) -> bool {
    let mut pairs = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        if !matches!(key, C::Integer(_) | C::Text(_)) {
            return false;
        }
        let (mut left, mut right) = (Vec::new(), Vec::new());
        if !encode(key, &mut left, depth) || !encode(value, &mut right, depth) {
            return false;
        }
        pairs.push((left, right));
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    if pairs.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return false;
    }
    head(out, 5, pairs.len() as u64);
    for (key, value) in pairs {
        out.extend_from_slice(&key);
        out.extend_from_slice(&value);
    }
    true
}
fn canonical(value: &C) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    encode(value, &mut out, 65).then_some(out)
}
/// Scan one restricted-CBOR item without materializing it. This runs before
/// ciborium, bounding hostile nesting and aggregate allocation pressure.
fn scan_head(data: &[u8], at: usize) -> Option<(u8, u64, usize)> {
    let byte = *data.get(at)?;
    let (major, info) = (byte >> 5, byte & 0x1f);
    let at = at.checked_add(1)?;
    match info {
        0..=23 if major != 6 && (major != 7 || matches!(info, 20..=22)) => Some((major, u64::from(info), at)),
        24..=27 if major < 6 => {
            let width = 1usize << (info - 24);
            let end = at.checked_add(width)?;
            let value = data.get(at..end)?.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            Some((major, value, end))
        }
        _ => None,
    }
}
fn scan_item(data: &[u8], at: &mut usize, major: u8, argument: u64, stack: &mut Vec<u64>) -> Option<()> {
    match major {
        2 | 3 => {
            *at = at.checked_add(usize::try_from(argument).ok()?)?;
            data.get(*at..)?;
        }
        4 | 5 => {
            let members = argument.checked_mul(if major == 5 { 2 } else { 1 })?;
            (members <= data.len().checked_sub(*at)? as u64).then_some(())?;
            if members > 0 {
                (stack.len() < MAX_CBOR_DEPTH).then_some(())?;
                stack.push(members);
            }
        }
        _ => {}
    }
    Some(())
}
fn structural_scan(data: &[u8]) -> Option<usize> {
    let (mut stack, mut at, mut items) = (Vec::new(), 0usize, 0usize);
    loop {
        items = items.checked_add(1)?;
        (items <= MAX_CBOR_ITEMS).then_some(())?;
        if let Some(remaining) = stack.last_mut() {
            *remaining -= 1;
        }
        let (major, argument, next) = scan_head(data, at)?;
        at = next;
        scan_item(data, &mut at, major, argument, &mut stack)?;
        while stack.last() == Some(&0) {
            stack.pop();
        }
        if stack.is_empty() {
            return Some(at);
        }
    }
}
fn decode(data: &[u8], cap: usize) -> Option<C> {
    if data.len() > cap || structural_scan(data)? != data.len() {
        return None;
    }
    let mut reader = Cursor::new(data);
    let value: C = ciborium::de::from_reader_with_recursion_limit(&mut reader, 64).ok()?;
    (reader.position() == data.len() as u64 && canonical(&value)? == data).then_some(value)
}
fn array(value: &C, cap: usize) -> Option<&[C]> {
    let C::Array(values) = value else { return None };
    (values.len() <= cap).then_some(values)
}
fn map_doc(value: &C) -> Option<Doc> {
    let C::Map(entries) = value else { return None };
    entries.iter().try_fold(Doc::new(), |mut out, (key, value)| {
        let C::Text(key) = key else { return None };
        out.insert(key.clone(), value.clone()).is_none().then_some(out)
    })
}
fn document(value: &C, schema: Option<&str>, fields: &str) -> Option<Doc> {
    let out = map_doc(value)?;
    let names = fields.split_whitespace().collect::<Vec<_>>();
    let expected = names.len() + usize::from(schema.is_some());
    (out.len() == expected && names.iter().all(|field| out.contains_key(*field)) && schema.is_none_or(|schema| out.get("schema").and_then(text) == Some(schema))).then_some(out)
}
fn plain(value: &C) -> Option<Doc> {
    map_doc(value)
}
fn text(value: &C) -> Option<&str> {
    if let C::Text(value) = value {
        Some(value)
    } else {
        None
    }
}
fn bounded(value: &C, maximum: usize) -> Option<&str> {
    let value = text(value)?;
    (!value.is_empty() && value.len() <= maximum && !value.contains('\0')).then_some(value)
}
fn bytes(value: &C) -> Option<&[u8]> {
    if let C::Bytes(value) = value {
        Some(value)
    } else {
        None
    }
}
fn fixed(value: &C, size: usize) -> Option<&[u8]> {
    let value = bytes(value)?;
    (value.len() == size).then_some(value)
}
fn opaque(value: &C) -> Option<&[u8]> {
    let value = fixed(value, 32)?;
    value.iter().any(|byte| *byte != 0).then_some(value)
}
fn uint(value: &C) -> Option<u64> {
    let C::Integer(value) = value else { return None };
    let value = i128::from(*value);
    (0..=i128::from(i64::MAX)).contains(&value).then_some(value as u64)
}
fn positive(value: &C) -> Option<u64> {
    let value = uint(value)?;
    (value > 0).then_some(value)
}
fn decimal(value: &C) -> Option<&str> {
    let value = text(value)?;
    let bytes = value.as_bytes();
    let canonical = value == "0" || (!bytes.is_empty() && bytes.len() <= 78 && matches!(bytes[0], b'1'..=b'9') && bytes[1..].iter().all(u8::is_ascii_digit));
    canonical.then_some(value)
}
fn window(doc: &Doc, start: &str, end: &str) -> bool {
    matches!((uint(&doc[start]), uint(&doc[end])), (Some(left), Some(right)) if left < right)
}
fn key_id(public: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(sha(&[public])).chars().take(16).collect()
}
fn agent(value: &C) -> Option<Doc> {
    let doc = document(value, Some(AGENT_REF), "organisation_root birthtag revision agent_kid")?;
    (opaque(&doc["organisation_root"]).is_some() && opaque(&doc["birthtag"]).is_some() && positive(&doc["revision"]).is_some() && bounded(&doc["agent_kid"], 128).is_some()).then_some(doc)
}
fn resource(value: &C) -> Option<Doc> {
    let doc = document(value, Some(RESOURCE_REF), "namespace identifier_digest")?;
    (bounded(&doc["namespace"], 128).is_some() && opaque(&doc["identifier_digest"]).is_some()).then_some(doc)
}
fn party(value: &C) -> Option<Doc> {
    let doc = document(value, Some(PARTY_REF), "party_id organisation_root")?;
    (bounded(&doc["party_id"], 256).is_some() && opaque(&doc["organisation_root"]).is_some()).then_some(doc)
}
fn action(value: &C) -> Option<Doc> {
    let doc = document(value, Some(ACTION), "action_id asa_id actor operation parameter_schema parameter_digest value unit source destination counterparty recipient grant_id grant_version policy_version policy_digest nonce expires_at")?;
    let (counterparty, recipient) = (party(&doc["counterparty"])?, agent(&doc["recipient"])?);
    #[rustfmt::skip]
    let valid = ["action_id", "asa_id", "parameter_digest", "grant_id", "policy_digest", "nonce"].iter().all(|name| opaque(&doc[*name]).is_some()) && agent(&doc["actor"]).is_some()
        && resource(&doc["source"]).is_some() && resource(&doc["destination"]).is_some()
        && bounded(&doc["operation"], 256).is_some() && bounded(&doc["parameter_schema"], 512).is_some() && decimal(&doc["value"]).is_some() && bounded(&doc["unit"], 64).is_some_and(|unit| { let iso = unit.strip_prefix("iso4217:").is_some_and(|tail| { let bytes = tail.as_bytes(); bytes.len() == 11 && bytes[..3].iter().all(u8::is_ascii_uppercase) && &bytes[3..10] == b":minor-" && bytes[10].is_ascii_digit() }); let named = unit.strip_prefix("ucum:").or_else(|| unit.strip_prefix("count:")).is_some_and(|name| !name.is_empty() && name.len() <= 48 && name.bytes().all(|byte| byte.is_ascii_graphic())); iso || named })
        && positive(&doc["grant_version"]).is_some() && bounded(&doc["policy_version"], 128).is_some() && positive(&doc["expires_at"]).is_some() && counterparty["organisation_root"] == recipient["organisation_root"];
    valid.then_some(doc)
}
fn known_dimension(name: &str) -> bool {
    matches!(name, "passport_identity" | "live_key_control" | "root_chain" | "template_admin_pop" | "fresh_status" | "binding" | "grant" | "delegation" | "exact_action" | "asa_reservation" | "challenge" | "transcript" | "replay" | "node_basis" | "source_basis" | "coverage_basis" | "history" | "post_action_evidence_readiness")
}
fn validate_challenge(value: &C) -> bool {
    let Some(doc) = document(value, Some(CHALLENGE), "profile challenger action accepted_encodings required_dimensions max_checkpoint_age issued_at") else { return false };
    let (Some(encodings), Some(required)) = (array(&doc["accepted_encodings"], 1), array(&doc["required_dimensions"], MAX_LOCAL_ITEMS)) else { return false };
    let names: Option<Vec<&str>> = required.iter().map(|value| bounded(value, 64)).collect();
    let Some(names) = names else { return false };
    let ordered = names.windows(2).all(|pair| pair[0] < pair[1]);
    let action = action(&doc["action"]);
    text(&doc["profile"]) == Some(PROFILE) && agent(&doc["challenger"]).is_some() && matches!(action.as_ref(), Some(action) if doc["challenger"] == action["recipient"] && matches!((positive(&doc["issued_at"]), positive(&action["expires_at"])), (Some(a), Some(b)) if a < b)) && matches!(encodings, [C::Text(value)] if value == MEDIA) && ordered && names.iter().all(|name| known_dimension(name)) && positive(&doc["max_checkpoint_age"]).is_some()
}
fn validate_asa(value: &C) -> bool {
    let Some(doc) = document(value, Some(ASA), "tenant organisation_root authority_delegation_id asa_id action_digest challenge_digest grant_id grant_version reservation_state issued_at expires_at") else { return false };
    bounded(&doc["tenant"], 128).is_some() && ["organisation_root", "authority_delegation_id", "asa_id", "action_digest", "challenge_digest", "grant_id"].iter().all(|name| opaque(&doc[*name]).is_some()) && positive(&doc["grant_version"]).is_some() && text(&doc["reservation_state"]) == Some("ISSUED_HELD") && window(&doc, "issued_at", "expires_at")
}
fn validate_presentation(value: &C) -> bool {
    let Some(doc) = document(value, Some(PRESENTATION), "profile challenge_envelope_hash challenge_digest action_digest root_delegation registration_template admin_binding admin_selection admin_challenge admin_consumption agent_pop agent_successor passport passport_holder_proof limit_grant authority_checkpoint issuance_consistency_proof status_snapshot state_proofs asa transcript_digest non_assertion created_at") else { return false };
    let inline = ["root_delegation", "registration_template", "admin_binding", "admin_challenge", "admin_consumption", "agent_pop", "passport", "passport_holder_proof", "limit_grant", "authority_checkpoint", "status_snapshot", "asa"];
    let Some(proofs) = document(&doc["state_proofs"], None, "root_delegation registration_template mandate agent_config admin_binding admin_selection admin_challenge admin_consumption admin_counter agent_pop passport agent_head agent_successor predecessor_head limit_grant grant_head") else {
        return false;
    };
    text(&doc["profile"]) == Some(PROFILE)
        && text(&doc["non_assertion"]) == Some(NON_ASSERTION)
        && ["challenge_envelope_hash", "challenge_digest", "action_digest", "transcript_digest"].iter().all(|name| fixed(&doc[*name], 32).is_some())
        && inline.iter().all(|name| matches!(bytes(&doc[*name]), Some(raw) if !raw.is_empty() && raw.len() <= MAX_CWT))
        && (doc["agent_successor"] == C::Null || matches!(bytes(&doc["agent_successor"]), Some(raw) if !raw.is_empty() && raw.len() <= MAX_CWT))
        && matches!(bytes(&doc["admin_selection"]), Some(raw) if raw.len() <= 16_384)
        && matches!(array(&doc["issuance_consistency_proof"], 64), Some(path) if path.iter().all(|item| fixed(item, 32).is_some()))
        && proofs.iter().all(|(name, proof)| matches!(proof, C::Map(_)) || matches!(name.as_str(), "agent_successor" | "predecessor_head") && proof == &C::Null)
        && uint(&doc["created_at"]).is_some()
}
fn validate_refusal(value: &C) -> bool {
    let Some(doc) = document(value, Some(REFUSAL), "profile challenge_envelope_hash challenge_digest reason_code created_at") else { return false };
    text(&doc["profile"]) == Some(PROFILE) && fixed(&doc["challenge_envelope_hash"], 32).is_some() && fixed(&doc["challenge_digest"], 32).is_some() && bounded(&doc["reason_code"], 128).is_some() && uint(&doc["created_at"]).is_some()
}
fn tenant_root(doc: &Doc) -> bool {
    bounded(&doc["tenant"], 128).is_some() && opaque(&doc["organisation_root"]).is_some()
}
fn validate_delegation(value: &C) -> bool {
    let Some(doc) = document(value, Some(ROOT_DELEGATION), "tenant organisation_root delegation_id passport_authority_kid passport_authority_key action_authority_kid action_authority_key valid_from valid_to") else { return false };
    let (Some(root), Some(psa), Some(action)) = (fixed(&doc["organisation_root"], 32), fixed(&doc["passport_authority_key"], 32), fixed(&doc["action_authority_key"], 32)) else {
        return false;
    };
    tenant_root(&doc) && opaque(&doc["delegation_id"]).is_some() && psa != action && sha(&[psa]) != root && sha(&[action]) != root && key_id(psa) != key_id(action) && bounded(&doc["passport_authority_kid"], 128) == Some(key_id(psa).as_str()) && bounded(&doc["action_authority_kid"], 128) == Some(key_id(action).as_str()) && window(&doc, "valid_from", "valid_to")
}
fn validate_template(value: &C) -> bool {
    let Some(doc) = document(value, Some(TEMPLATE), "tenant organisation_root template_id template_version owner purpose mandate_digest config_digest valid_from valid_to") else { return false };
    tenant_root(&doc) && opaque(&doc["template_id"]).is_some() && positive(&doc["template_version"]).is_some() && bounded(&doc["owner"], 1024).is_some() && bounded(&doc["purpose"], 1024).is_some() && fixed(&doc["mandate_digest"], 32).is_some() && fixed(&doc["config_digest"], 32).is_some() && window(&doc, "valid_from", "valid_to")
}
fn validate_admin_binding(value: &C) -> bool {
    let Some(doc) = document(value, Some(ADMIN_BINDING), "tenant organisation_root binding_id credential_id cose_public_key rp_id role valid_from valid_to initial_state") else { return false };
    tenant_root(&doc) && opaque(&doc["binding_id"]).is_some() && matches!(bytes(&doc["credential_id"]), Some(raw) if (16..=1024).contains(&raw.len())) && matches!(bytes(&doc["cose_public_key"]), Some(raw) if (16..=256).contains(&raw.len())) && bounded(&doc["rp_id"], 253).is_some() && matches!(text(&doc["role"]), Some("agent-registrar" | "security-admin" | "governance-admin")) && text(&doc["initial_state"]) == Some("ACTIVE") && window(&doc, "valid_from", "valid_to")
}
fn validate_selection(value: &C) -> bool {
    let Some(doc) = document(value, Some(ADMIN_SELECTION), "tenant binding_id template_id template_version proposed_agent_digest credential_id challenge_id challenge client_data_json authenticator_data signature selected_at") else { return false };
    #[rustfmt::skip]
    let valid = bounded(&doc["tenant"], 128).is_some() && opaque(&doc["binding_id"]).is_some() && opaque(&doc["template_id"]).is_some() && positive(&doc["template_version"]).is_some()
        && opaque(&doc["proposed_agent_digest"]).is_some() && matches!(bytes(&doc["credential_id"]), Some(raw) if raw.len() <= 1024) && opaque(&doc["challenge_id"]).is_some() && opaque(&doc["challenge"]).is_some()
        && matches!(bytes(&doc["client_data_json"]), Some(raw) if raw.len() <= 4096) && matches!(bytes(&doc["authenticator_data"]), Some(raw) if (37..=1024).contains(&raw.len()))
        && matches!(bytes(&doc["signature"]), Some(raw) if (64..=80).contains(&raw.len())) && uint(&doc["selected_at"]).is_some();
    valid
}
fn validate_admin_challenge(value: &C) -> bool {
    let Some(doc) = document(value, Some(ADMIN_CHALLENGE), "tenant organisation_root challenge_id binding_id template_id template_version proposed_agent_digest challenge issued_at expires_at") else { return false };
    tenant_root(&doc) && ["challenge_id", "binding_id", "template_id", "proposed_agent_digest", "challenge"].iter().all(|name| opaque(&doc[*name]).is_some()) && positive(&doc["template_version"]).is_some() && window(&doc, "issued_at", "expires_at")
}
fn validate_admin_consumption(value: &C) -> bool {
    let Some(doc) = document(value, Some(ADMIN_CONSUMPTION), "tenant organisation_root binding_id challenge_id challenge_digest selection_digest credential_digest counter_version sign_count_before sign_count_after backup_eligible backup_state consumed_at") else { return false };
    #[rustfmt::skip]
    let valid = matches!((uint(&doc["sign_count_before"]), uint(&doc["sign_count_after"]), &doc["backup_eligible"], &doc["backup_state"]), (Some(before), Some(after), C::Bool(eligible), C::Bool(state)) if (before == 0 && after == 0 || after > before) && (!state || *eligible))
        && tenant_root(&doc) && ["binding_id", "challenge_id", "challenge_digest", "selection_digest", "credential_digest"].iter().all(|name| opaque(&doc[*name]).is_some()) && positive(&doc["counter_version"]).is_some() && uint(&doc["consumed_at"]).is_some();
    valid
}
fn validate_pop(value: &C) -> bool {
    let Some(doc) = document(value, Some(AGENT_POP), "tenant birthtag revision agent_kid proposed_agent_digest challenge") else { return false };
    bounded(&doc["tenant"], 128).is_some() && opaque(&doc["birthtag"]).is_some() && positive(&doc["revision"]).is_some() && bounded(&doc["agent_kid"], 128).is_some() && opaque(&doc["proposed_agent_digest"]).is_some() && opaque(&doc["challenge"]).is_some()
}
fn validate_credential(value: &C) -> bool {
    let Some(doc) = document(value, Some(CREDENTIAL), "tenant organisation_root authority_delegation_id birthtag revision agent_kid agent_key owner purpose mandate_digest config_digest template_id template_version principal_binding_id admin_selection_digest agent_pop_digest agent_successor_digest issuance_checkpoint valid_from valid_to") else { return false };
    let (Some(root), Some(agent_key)) = (fixed(&doc["organisation_root"], 32), fixed(&doc["agent_key"], 32)) else { return false };
    #[rustfmt::skip]
    let valid = tenant_root(&doc) && ["authority_delegation_id", "birthtag", "agent_key", "mandate_digest", "config_digest", "template_id", "principal_binding_id", "admin_selection_digest", "agent_pop_digest", "issuance_checkpoint"].iter().all(|name| opaque(&doc[*name]).is_some())
        && sha(&[agent_key]) != root && positive(&doc["revision"]).is_some() && positive(&doc["template_version"]).is_some() && bounded(&doc["agent_kid"], 128) == Some(key_id(agent_key).as_str())
        && (doc["agent_successor_digest"] == C::Null || opaque(&doc["agent_successor_digest"]).is_some())
        && bounded(&doc["owner"], 1024).is_some() && bounded(&doc["purpose"], 1024).is_some() && window(&doc, "valid_from", "valid_to");
    valid
}
fn validate_successor(value: &C) -> bool {
    let Some(doc) = document(value, Some(AGENT_SUCCESSOR), "tenant organisation_root predecessor_birthtag predecessor_revision predecessor_credential_digest successor_birthtag successor_revision successor_proposal_digest effective_at") else { return false };
    tenant_root(&doc) && ["predecessor_birthtag", "predecessor_credential_digest", "successor_birthtag", "successor_proposal_digest"].iter().all(|name| opaque(&doc[*name]).is_some()) && positive(&doc["predecessor_revision"]).is_some() && positive(&doc["successor_revision"]) == Some(1) && doc["predecessor_birthtag"] != doc["successor_birthtag"] && uint(&doc["effective_at"]).is_some()
}
fn validate_grant(value: &C) -> bool {
    let Some(doc) = document(value, Some(GRANT), "tenant organisation_root grant_id grant_version authority_delegation_id actor_birthtag recipient_organisation_root operation unit action_scope_digest kind ceiling window_start window_end valid_from valid_to max_unresolved_exposure") else { return false };
    #[rustfmt::skip]
    let valid = tenant_root(&doc) && ["grant_id", "authority_delegation_id", "actor_birthtag", "recipient_organisation_root"].iter().all(|name| opaque(&doc[*name]).is_some())
        && positive(&doc["grant_version"]).is_some() && bounded(&doc["operation"], 1024).is_some() && bounded(&doc["unit"], 64).is_some() && opaque(&doc["action_scope_digest"]).is_some()
        && matches!(text(&doc["kind"]), Some("ONE_SHOT" | "FLOW" | "STOCK")) && decimal(&doc["ceiling"]).is_some() && decimal(&doc["max_unresolved_exposure"]).is_some() && decimal_at_most(&doc["max_unresolved_exposure"], &doc["ceiling"])
        && window(&doc, "window_start", "window_end") && window(&doc, "valid_from", "valid_to");
    valid
}
fn validate_checkpoint(value: &C) -> bool {
    let Some(doc) = document(value, Some(CHECKPOINT), "tenant organisation_root sequence authority_root log_root log_size issued_at") else { return false };
    tenant_root(&doc) && fixed(&doc["authority_root"], 32).is_some() && fixed(&doc["log_root"], 32).is_some() && uint(&doc["sequence"]).is_some() && uint(&doc["log_size"]).is_some() && uint(&doc["issued_at"]).is_some()
}
fn validate_snapshot(value: &C) -> bool {
    let Some(doc) = document(value, Some(SNAPSHOT), "tenant organisation_root authority_delegation_id checkpoint_digest proofs_digest status_as_of expires_at") else { return false };
    tenant_root(&doc) && opaque(&doc["authority_delegation_id"]).is_some() && fixed(&doc["checkpoint_digest"], 32).is_some() && fixed(&doc["proofs_digest"], 32).is_some() && window(&doc, "status_as_of", "expires_at")
}
fn validate_core(value: &C, schema: &str) -> bool {
    #[rustfmt::skip]
    let valid = match schema {
        ACTION => action(value).is_some(), CHALLENGE => validate_challenge(value), ASA => validate_asa(value), PRESENTATION => validate_presentation(value),
        REFUSAL => validate_refusal(value), ROOT_DELEGATION => validate_delegation(value), TEMPLATE => validate_template(value), ADMIN_BINDING => validate_admin_binding(value),
        ADMIN_SELECTION => validate_selection(value), ADMIN_CHALLENGE => validate_admin_challenge(value), ADMIN_CONSUMPTION => validate_admin_consumption(value), AGENT_POP => validate_pop(value),
        CREDENTIAL => validate_credential(value), AGENT_SUCCESSOR => validate_successor(value), GRANT => validate_grant(value), CHECKPOINT => validate_checkpoint(value), SNAPSHOT => validate_snapshot(value), _ => false,
    };
    valid
}
fn integer(map: &[(C, C)], key: i64) -> Option<&C> {
    map.iter().find_map(|(candidate, value)| matches!(candidate, C::Integer(number) if i128::from(*number) == key as i128).then_some(value))
}
struct Cwt {
    core: C,
    core_bytes: Vec<u8>,
    payload: Vec<u8>,
    protected: Vec<u8>,
    signature: Vec<u8>,
    kid: String,
}
fn inspect_cwt(raw: &[u8], schema: &str) -> Option<Cwt> {
    if raw.len() > MAX_CWT || raw.first() != Some(&0xd2) {
        return None;
    }
    let C::Array(items) = decode(&raw[1..], MAX_CWT)? else { return None };
    let [C::Bytes(protected), C::Map(unprotected), C::Bytes(payload), C::Bytes(signature)] = items.as_slice() else {
        return None;
    };
    if !unprotected.is_empty() || signature.len() != 64 {
        return None;
    }
    let C::Map(header) = decode(protected, 4096)? else { return None };
    if header.len() != 3 || !matches!(integer(&header, 1), Some(C::Integer(number)) if i128::from(*number) == -8) || text(integer(&header, 3)?) != Some(MEDIA) {
        return None;
    }
    let kid_raw = bytes(integer(&header, 4)?)?;
    let kid = std::str::from_utf8(kid_raw).ok()?;
    if kid.is_empty() || kid.len() > 128 || !kid.is_ascii() {
        return None;
    }
    let C::Map(claims) = decode(payload, MAX_CWT)? else { return None };
    if claims.len() != 2 || !claims.iter().all(|(key, _)| matches!(key, C::Integer(number) if matches!(i128::from(*number), 265 | -65_537))) || text(integer(&claims, CWT_PROFILE_CLAIM)?) != Some(PROFILE) {
        return None;
    }
    let core = integer(&claims, B28_CORE_CLAIM)?.clone();
    let core_bytes = canonical(&core)?;
    validate_core(&core, schema).then_some(Cwt { core, core_bytes, payload: payload.clone(), protected: protected.clone(), signature: signature.clone(), kid: kid.to_owned() })
}
fn verify_ed25519(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(key_raw), Ok(signature_raw)) = (<&[u8; 32]>::try_from(key), <&[u8; 64]>::try_from(signature)) else {
        return false;
    };
    let (Ok(key), signature) = (EdKey::from_bytes(key_raw), EdSignature::from_bytes(signature_raw)) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
fn cwt_signature_valid(cwt: &Cwt, key: &[u8]) -> bool {
    let structure = C::Array(vec![C::Text("Signature1".to_owned()), C::Bytes(cwt.protected.clone()), C::Bytes(Vec::new()), C::Bytes(cwt.payload.clone())]);
    canonical(&structure).is_some_and(|message| cwt.kid == key_id(key) && verify_ed25519(key, &message, &cwt.signature))
}
fn signed_cwt(raw: &[u8], schema: &str, keys: &BTreeMap<String, Vec<u8>>) -> Option<Cwt> {
    let cwt = inspect_cwt(raw, schema)?;
    let key = keys.get(&cwt.kid)?;
    cwt_signature_valid(&cwt, key).then_some(cwt)
}
#[derive(Clone)]
struct RootAnchor {
    fingerprint: Vec<u8>,
    key: Vec<u8>,
}
fn parse_pinned_trust_pack(raw: &[u8], pin: &[u8]) -> Option<BTreeMap<String, RootAnchor>> {
    if pin.len() != 32 || pin != sha(&[raw]) || raw.len() > MAX_CWT {
        return None;
    }
    let doc = document(&decode(raw, MAX_CWT)?, Some(TRUST_PACK), "roots")?;
    let entries = array(&doc["roots"], MAX_LOCAL_ITEMS).filter(|entries| !entries.is_empty())?;
    let mut roots = BTreeMap::new();
    let mut order = Vec::new();
    for entry in entries {
        let root = document(entry, None, "kid organisation_root public_key")?;
        let kid = bounded(&root["kid"], 128)?.to_owned();
        let fingerprint = fixed(&root["organisation_root"], 32)?.to_vec();
        let key = fixed(&root["public_key"], 32)?.to_vec();
        let key_raw = <&[u8; 32]>::try_from(key.as_slice()).ok()?;
        if kid != key_id(&key) || fingerprint != sha(&[&key]) || EdKey::from_bytes(key_raw).is_err() {
            return None;
        }
        order.push(kid.clone());
        if roots.insert(kid, RootAnchor { fingerprint, key }).is_some() {
            return None;
        }
    }
    order.windows(2).all(|pair| pair[0] < pair[1]).then_some(roots)
}
fn root_cwt(raw: &[u8], schema: &str, roots: &BTreeMap<String, RootAnchor>) -> Option<Cwt> {
    let cwt = inspect_cwt(raw, schema)?;
    let anchor = roots.get(&cwt.kid)?;
    cwt_signature_valid(&cwt, &anchor.key).then_some(())?;
    let doc = plain(&cwt.core)?;
    (bytes(&doc["organisation_root"])? == anchor.fingerprint).then_some(cwt)
}
#[derive(Clone)]
struct InputContext {
    challenge: Vec<u8>,
    presentation: Vec<u8>,
    roots: BTreeMap<String, RootAnchor>,
    challenger_keys: BTreeMap<String, Vec<u8>>,
    checkpoints: Checkpoints,
    heads: Heads,
    origin: String,
    max_action_lifetime_s: u64,
    now: u64,
}
#[derive(Clone, PartialEq, Eq)]
struct CounterState {
    before: u64,
    after: u64,
    backup_eligible: bool,
    backup_state: bool,
}
type Head = (u64, Vec<u8>, Vec<u8>, u64);
type Heads = BTreeMap<(String, Vec<u8>), Head>;
type Checkpoints = BTreeMap<Vec<u8>, (String, Vec<u8>, u64, Vec<u8>, Vec<u8>, u64)>;
type PresentationLocal = (BTreeMap<String, Vec<u8>>, Checkpoints, Heads, String, u64, u64);
type RefusalLocal = (BTreeMap<String, Vec<u8>>, BTreeMap<String, Vec<u8>>, u64);
enum LocalContext {
    Presentation(PresentationLocal),
    Refusal(RefusalLocal),
}
fn local_keys(value: &C) -> Option<BTreeMap<String, Vec<u8>>> {
    let entries = array(value, MAX_LOCAL_ITEMS)?;
    let (mut keys, mut order) = (BTreeMap::new(), Vec::new());
    for entry in entries {
        let entry = document(entry, None, "kid public_key")?;
        let kid = bounded(&entry["kid"], 128)?.to_owned();
        let key = fixed(&entry["public_key"], 32)?.to_vec();
        let key_raw = <&[u8; 32]>::try_from(key.as_slice()).ok()?;
        if kid != key_id(&key) || EdKey::from_bytes(key_raw).is_err() {
            return None;
        }
        order.push(kid.clone());
        keys.insert(kid, key);
    }
    (order.windows(2).all(|pair| pair[0] < pair[1]) && order.len() == keys.len()).then_some(keys)
}
fn checkpoints(value: &C) -> Option<Checkpoints> {
    let entries = array(value, MAX_LOCAL_ITEMS)?;
    let (mut values, mut order) = (BTreeMap::new(), Vec::new());
    for entry in entries {
        let entry = document(entry, None, "digest tenant organisation_root sequence authority_root log_root log_size")?;
        let digest = fixed(&entry["digest"], 32)?.to_vec();
        let value = (bounded(&entry["tenant"], 128)?.to_owned(), fixed(&entry["organisation_root"], 32)?.to_vec(), uint(&entry["sequence"])?, fixed(&entry["authority_root"], 32)?.to_vec(), fixed(&entry["log_root"], 32)?.to_vec(), uint(&entry["log_size"])?);
        order.push(digest.clone());
        if values.insert(digest, value).is_some() {
            return None;
        }
    }
    order.windows(2).all(|pair| pair[0] < pair[1]).then_some(values)
}
fn heads(value: &C) -> Option<Heads> {
    let entries = array(value, MAX_LOCAL_ITEMS)?;
    let (mut heads, mut order) = (BTreeMap::new(), Vec::new());
    for entry in entries {
        let entry = document(entry, None, "tenant organisation_root sequence authority_root log_root log_size")?;
        let key = (bounded(&entry["tenant"], 128)?.to_owned(), opaque(&entry["organisation_root"])?.to_vec());
        let value = (uint(&entry["sequence"])?, fixed(&entry["authority_root"], 32)?.to_vec(), fixed(&entry["log_root"], 32)?.to_vec(), uint(&entry["log_size"])?);
        order.push(key.clone());
        if heads.insert(key, value).is_some() {
            return None;
        }
    }
    order.windows(2).all(|pair| pair[0] < pair[1]).then_some(heads)
}
fn presentation_context(local: Doc) -> Option<PresentationLocal> {
    let lifetime = positive(&local["max_action_lifetime_s"]).filter(|value| *value <= 300)?;
    Some((local_keys(&local["challenger_keys"])?, checkpoints(&local["registered_checkpoints"])?, heads(&local["authority_heads"])?, bounded(&local["expected_admin_origin"], 2048)?.to_owned(), lifetime, uint(&local["now"])?))
}
fn refusal_context(local: Doc) -> Option<RefusalLocal> {
    Some((local_keys(&local["challenger_keys"])?, local_keys(&local["responder_keys"])?, uint(&local["now"])?))
}
fn parse_local_context(raw: &[u8]) -> Result<LocalContext, &'static str> {
    let value = decode(raw, MAX_LOCAL_CONTEXT).ok_or("VERIFIER_CONTEXT_INVALID")?;
    if let Some(local) = document(&value, Some(LOCAL_CONTEXT), "challenger_keys registered_checkpoints authority_heads expected_admin_origin max_action_lifetime_s now") {
        if uint(&local["now"]).is_none() {
            return Err("LOCAL_CLOCK_INVALID");
        }
        return presentation_context(local).map(LocalContext::Presentation).ok_or("VERIFIER_CONTEXT_INVALID");
    }
    if let Some(local) = document(&value, Some(LOCAL_REFUSAL_CONTEXT), "challenger_keys responder_keys now") {
        if uint(&local["now"]).is_none() {
            return Err("LOCAL_CLOCK_INVALID");
        }
        return refusal_context(local).map(LocalContext::Refusal).ok_or("VERIFIER_CONTEXT_INVALID");
    }
    Err("VERIFIER_CONTEXT_INVALID")
}
fn parse_input(exchange: &[u8], local: PresentationLocal, roots: &BTreeMap<String, RootAnchor>) -> Option<InputContext> {
    let exchange = document(&decode(exchange, MAX_INPUT)?, None, "challenge presentation")?;
    let (challenger_keys, checkpoints, heads, origin, max_action_lifetime_s, now) = local;
    Some(InputContext { challenge: bytes(&exchange["challenge"])?.to_vec(), presentation: bytes(&exchange["presentation"])?.to_vec(), roots: roots.clone(), challenger_keys, checkpoints, heads, origin, max_action_lifetime_s, now })
}
struct RefusalContext {
    challenge: Vec<u8>,
    refusal: Vec<u8>,
    challenger_keys: BTreeMap<String, Vec<u8>>,
    responder_keys: BTreeMap<String, Vec<u8>>,
    now: u64,
}
fn parse_refusal(exchange: &[u8], local: RefusalLocal) -> Option<RefusalContext> {
    let exchange = document(&decode(exchange, MAX_INPUT)?, None, "challenge refusal")?;
    let (challenger_keys, responder_keys, now) = local;
    Some(RefusalContext { challenge: bytes(&exchange["challenge"])?.to_vec(), refusal: bytes(&exchange["refusal"])?.to_vec(), challenger_keys, responder_keys, now })
}
const VERIFIED: [&str; 13] = ["passport_identity", "live_key_control", "root_chain", "template_admin_pop", "fresh_status", "binding", "grant", "delegation", "exact_action", "asa_reservation", "challenge", "transcript", "replay"];
const UNEVALUATED: [&str; 5] = ["node_basis", "source_basis", "coverage_basis", "history", "post_action_evidence_readiness"];
#[derive(Clone)]
struct ResultValue {
    verdict: String,
    reason: String,
    vector: BTreeMap<String, String>,
}
impl ResultValue {
    fn new(verdict: &str, reason: impl Into<String>, vector: BTreeMap<String, String>) -> Self {
        Self { verdict: verdict.to_owned(), reason: reason.into(), vector }
    }

    fn json(&self) -> J {
        let vector = self.vector.iter().map(|(key, value)| (key.clone(), J::String(value.clone()))).collect::<JsonMap<_, _>>();
        let mut out = JsonMap::new();
        out.insert("verdict".to_owned(), J::String(self.verdict.clone()));
        out.insert("reasons".to_owned(), J::Array(vec![J::String(self.reason.clone())]));
        out.insert("vector".to_owned(), J::Object(vector));
        out.insert("should_execute".to_owned(), J::Bool(false));
        J::Object(out)
    }
}
fn initial_vector() -> BTreeMap<String, String> {
    let mut out = VERIFIED.into_iter().map(|name| (name.to_owned(), "INDETERMINATE".to_owned())).collect::<BTreeMap<_, _>>();
    out.extend(UNEVALUATED.into_iter().map(|name| (name.to_owned(), "NOT_EVALUATED_V1".to_owned())));
    out
}
fn mark(vector: &mut BTreeMap<String, String>, names: &[&str], state: &str) {
    for name in names {
        vector.insert((*name).to_owned(), state.to_owned());
    }
}
fn core_digest(canonical_core: &[u8]) -> [u8; 32] {
    sha(&[b"swarrm-b28/core/v1\0", canonical_core])
}

fn json_string_end(raw: &[u8], mut at: usize) -> Option<usize> {
    at += 1;
    while at < raw.len() && raw[at] != b'"' {
        at += if raw[at] == b'\\' { 2 } else { 1 };
    }
    (at < raw.len()).then_some(at + 1)
}
fn top_level_json_keys(raw: &[u8]) -> Option<BTreeSet<String>> {
    let (mut at, mut depth, mut keys) = (0usize, 0i32, BTreeSet::new());
    while at < raw.len() {
        match raw[at] {
            b'{' | b'[' => {
                depth += 1;
                at += 1;
            }
            b'}' | b']' => {
                depth -= 1;
                at += 1;
            }
            b'"' => {
                let start = at;
                at = json_string_end(raw, at)?;
                let mut look = at;
                while raw.get(look).is_some_and(u8::is_ascii_whitespace) {
                    look += 1;
                }
                if depth == 1 && raw.get(look) == Some(&b':') {
                    let key: String = serde_json::from_slice(raw.get(start..at)?).ok()?;
                    if !keys.insert(key) {
                        return None;
                    }
                }
            }
            _ => at += 1,
        }
    }
    Some(keys)
}
fn strict_client_json(raw: &[u8]) -> Option<JsonMap<String, J>> {
    let J::Object(object) = serde_json::from_slice(raw).ok()? else { return None };
    let exact = [object.len() == 4, ["type", "challenge", "origin", "crossOrigin"].iter().all(|name| object.contains_key(*name))];
    (exact.into_iter().all(|held| held) && top_level_json_keys(raw)?.len() == 4).then_some(object)
}

fn canonical_origin(origin: &str, rp_id: &str) -> bool {
    let label = |part: &str| !part.is_empty() && part.len() <= 63 && !part.starts_with('-') && !part.ends_with('-') && part.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    !rp_id.is_empty() && rp_id.is_ascii() && rp_id.split('.').all(label) && origin.strip_prefix("https://").is_some_and(|host| host == rp_id || host.strip_suffix('/').is_some_and(|host| host == rp_id))
}

fn admin_context(admin: &Doc, picked: &Doc, now: u64) -> bool {
    let checks = [text(&admin["role"]) == Some("agent-registrar"), matches!((uint(&admin["valid_from"]), uint(&admin["valid_to"])), (Some(a), Some(b)) if a <= now && now < b), picked["tenant"] == admin["tenant"], picked["binding_id"] == admin["binding_id"], picked["credential_id"] == admin["credential_id"], matches!(uint(&picked["selected_at"]), Some(at) if uint(&admin["valid_from"]) <= Some(at) && at <= now)];
    checks.into_iter().all(|held| held)
}
fn client_binding(client: &JsonMap<String, J>, auth: &[u8], admin: &Doc, picked: &Doc, origin: &str) -> bool {
    if auth.len() != 37 {
        return false;
    }
    let (Some(challenge), Some(rp_id)) = (bytes(&picked["challenge"]), text(&admin["rp_id"])) else { return false };
    let expected_challenge = URL_SAFE_NO_PAD.encode(challenge);
    let checks = [client.get("type") == Some(&J::String("webauthn.get".to_owned())), client.get("challenge") == Some(&J::String(expected_challenge)), client.get("origin") == Some(&J::String(origin.to_owned())), client.get("crossOrigin") == Some(&J::Bool(false)), auth[..32] == sha(&[rp_id.as_bytes()])];
    checks.into_iter().all(|held| held)
}
fn counter_progresses(previous: u64, current: u64) -> bool {
    (previous == 0 && current == 0) || current > previous
}
fn admin_flags(auth: &[u8], previous: u64) -> Option<(bool, bool, u64)> {
    let flags = *auth.get(32)?;
    let (backup_eligible, backup_state) = (flags & 0x08 != 0, flags & 0x10 != 0);
    let checks = [flags & !0x1d == 0, flags & 0x05 == 0x05, matches!((backup_eligible, backup_state), (false, false) | (true, false) | (true, true))];
    if !checks.into_iter().all(|held| held) {
        return None;
    }
    let counter = u32::from_be_bytes(auth.get(33..37)?.try_into().ok()?) as u64;
    counter_progresses(previous, counter).then_some((backup_eligible, backup_state, counter))
}
fn admin_p256_key(admin: &Doc) -> Option<P256Key> {
    let C::Map(cose) = decode(bytes(&admin["cose_public_key"])?, 256)? else { return None };
    let profile = [cose.len() == 5, matches!(integer(&cose, 1), Some(C::Integer(n)) if i128::from(*n) == 2), matches!(integer(&cose, 3), Some(C::Integer(n)) if i128::from(*n) == -7), matches!(integer(&cose, -1), Some(C::Integer(n)) if i128::from(*n) == 1)];
    let (Some(x), Some(y)) = (integer(&cose, -2).and_then(bytes), integer(&cose, -3).and_then(bytes)) else { return None };
    if !profile.into_iter().all(|held| held) || x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut encoded = vec![4];
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    P256Key::from_sec1_bytes(&encoded).ok()
}
fn verify_admin(admin: &Doc, selection: &C, origin: &str, previous: u64, now: u64) -> Option<CounterState> {
    let picked = plain(selection)?;
    let context = [admin_context(admin, &picked, now), canonical_origin(origin, text(&admin["rp_id"]).unwrap_or(""))];
    if !context.into_iter().all(|held| held) {
        return None;
    }
    let (client_raw, auth, signature) = (bytes(&picked["client_data_json"])?, bytes(&picked["authenticator_data"])?, bytes(&picked["signature"])?);
    let client = strict_client_json(client_raw)?;
    if !client_binding(&client, auth, admin, &picked, origin) {
        return None;
    }
    let (backup_eligible, backup_state, counter) = admin_flags(auth, previous)?;
    let signature = P256Signature::from_der(signature).ok()?;
    if signature.normalize_s().is_some() {
        return None;
    }
    let mut signed = auth.to_vec();
    signed.extend_from_slice(&sha(&[client_raw]));
    admin_p256_key(admin)?.verify(&signed, &signature).ok().map(|_| CounterState { before: previous, after: counter, backup_eligible, backup_state })
}

fn state_key(kind: &str, object_id: &[u8]) -> [u8; 32] {
    sha(&[b"swarrm-authority-state/v1\0", kind.as_bytes(), b"\0", object_id])
}

fn state_meta(proof: &C, expected_key: &[u8], digest: &[u8], expected_state: &str, expected_version: Option<u64>) -> Option<(Vec<C>, u64, u64, [u8; 32])> {
    let proof = document(proof, Some(MEMBERSHIP), "key value index tree_size path")?;
    let value = document(&proof["value"], None, "key state version object_digest")?;
    let (Some(index), Some(size), C::Array(path)) = (uint(&proof["index"]), positive(&proof["tree_size"]), &proof["path"]) else {
        return None;
    };
    let checks = [index < size, path.len() <= 64, bytes(&proof["key"]) == Some(expected_key), value["key"] == proof["key"], text(&value["state"]) == Some(expected_state), positive(&value["version"]).is_some(), expected_version.is_none_or(|version| uint(&value["version"]) == Some(version)), bytes(&value["object_digest"]) == Some(digest)];
    if !checks.into_iter().all(|held| held) {
        return None;
    }
    let leaf = canonical(&proof["value"])?;
    Some((path.clone(), index, size, sha(&[b"\0", &leaf])))
}
fn state_root(path: &[C], mut position: u64, mut last: u64, mut hash: [u8; 32], root: &[u8]) -> bool {
    for sibling in path {
        let Some(sibling) = fixed(sibling, 32) else { return false };
        if last == 0 {
            return false;
        }
        let left = [position & 1 == 1, position == last].into_iter().any(|held| held);
        if left {
            hash = sha(&[b"\x01", sibling, &hash]);
            if position & 1 == 0 {
                while position != 0 {
                    if position & 1 != 0 {
                        break;
                    }
                    position >>= 1;
                    last >>= 1;
                }
            }
        } else {
            hash = sha(&[b"\x01", &hash, sibling]);
        }
        position >>= 1;
        last >>= 1;
    }
    last == 0 && hash == root
}
fn verify_state(proof: &C, root: &[u8], expected_key: &[u8], digest: &[u8], expected_state: &str, expected_version: Option<u64>) -> bool {
    state_meta(proof, expected_key, digest, expected_state, expected_version).is_some_and(|(path, index, size, hash)| state_root(&path, index, size - 1, hash, root))
}
fn verify_counter_head(proof: &C, root: &[u8], binding_id: &[u8], minimum_version: u64) -> bool {
    let Some(doc) = document(proof, Some(MEMBERSHIP), "key value index tree_size path") else { return false };
    let Some(value) = document(&doc["value"], None, "key state version object_digest") else { return false };
    let (Some(version), Some(digest)) = (positive(&value["version"]), fixed(&value["object_digest"], 32)) else { return false };
    version >= minimum_version && verify_state(proof, root, &state_key("admin_counter", binding_id), digest, "ACTIVE", Some(version))
}
fn consistency_seed<'a>(old: u64, first_root: &[u8], items: &mut impl Iterator<Item = &'a [u8; 32]>) -> Option<[u8; 32]> {
    let mut seed = [0u8; 32];
    if old == 0 {
        if first_root.len() != 32 {
            return None;
        }
        seed.copy_from_slice(first_root);
    } else if let Some(item) = items.next() {
        seed = *item;
    } else {
        return None;
    }
    Some(seed)
}
fn consistency_hashes<'a>(mut old: u64, mut new: u64, seed: [u8; 32], items: impl Iterator<Item = &'a [u8; 32]>) -> Option<([u8; 32], [u8; 32], u64)> {
    let (mut first_hash, mut second_hash) = (seed, seed);
    for item in items {
        if new == 0 {
            return None;
        }
        if old & 1 == 1 || old == new {
            first_hash = sha(&[b"\x01", item, &first_hash]);
            second_hash = sha(&[b"\x01", item, &second_hash]);
            while old != 0 && old & 1 == 0 {
                old >>= 1;
                new >>= 1;
            }
        } else {
            second_hash = sha(&[b"\x01", &second_hash, item]);
        }
        old >>= 1;
        new >>= 1;
    }
    Some((first_hash, second_hash, new))
}
fn verify_consistency(value: &C, first: u64, second: u64, first_root: &[u8], second_root: &[u8]) -> bool {
    let Some(path) = array(value, 64).and_then(|path| path.iter().map(|item| fixed(item, 32).and_then(|raw| raw.try_into().ok())).collect::<Option<Vec<[u8; 32]>>>()) else { return false };
    if first > second || first == 0 {
        return false;
    }
    if first == second {
        return path.is_empty() && first_root == second_root;
    }
    let (mut old, mut new) = (first - 1, second - 1);
    while old & 1 == 1 {
        old >>= 1;
        new >>= 1;
    }
    let mut items = path.iter();
    let Some(seed) = consistency_seed(old, first_root, &mut items) else { return false };
    matches!(consistency_hashes(old, new, seed, items), Some((a, b, 0)) if a == first_root && b == second_root)
}

fn map_value(items: Vec<(&str, C)>) -> C {
    C::Map(items.into_iter().map(|(key, value)| (C::Text(key.to_owned()), value)).collect())
}

fn named_digest(doc: &Doc, names: &[&str], domain: &[u8]) -> Option<[u8; 32]> {
    let value = map_value(names.iter().map(|name| (*name, doc[*name].clone())).collect());
    Some(sha(&[domain, &canonical(&value)?]))
}
const PROPOSAL_FIELDS: [&str; 12] = ["tenant", "birthtag", "revision", "agent_kid", "agent_key", "owner", "purpose", "mandate_digest", "config_digest", "template_id", "template_version", "principal_binding_id"];
const ACTION_SCOPE_FIELDS: [&str; 11] = ["actor", "operation", "parameter_schema", "parameter_digest", "unit", "source", "destination", "counterparty", "recipient", "policy_version", "policy_digest"];
fn selected_digest(credential: &Doc) -> Option<[u8; 32]> {
    named_digest(credential, &PROPOSAL_FIELDS, b"swarrm-b28/agent-proposal/v1\0")
}
fn action_scope_digest(action: &Doc) -> Option<[u8; 32]> {
    named_digest(action, &ACTION_SCOPE_FIELDS, b"swarrm-b28/action-scope/v1\0")
}
fn successor_matches(credential: &Doc, envelope: Option<&Cwt>, now: u64) -> bool {
    match (&credential["agent_successor_digest"], envelope) {
        (C::Null, None) => true,
        (C::Bytes(digest), Some(envelope)) => {
            let link = plain(&envelope.core).unwrap();
            digest.as_slice() == core_digest(&envelope.core_bytes) && link["successor_birthtag"] == credential["birthtag"] && link["successor_revision"] == credential["revision"] && bytes(&link["successor_proposal_digest"]) == selected_digest(credential).as_ref().map(<[u8; 32]>::as_slice) && uint(&link["effective_at"]).is_some_and(|at| at <= now)
        }
        _ => false,
    }
}
fn checkpoint_head_error(checkpoint: &Doc, sequence: u64, head: &Head) -> Option<(&'static str, &'static str)> {
    if sequence < head.0 {
        return Some(("FAIL", "AUTHORITY_CHECKPOINT_ROLLBACK"));
    }
    if sequence > head.0 {
        return Some(("INDETERMINATE", "AUTHORITY_CHECKPOINT_AHEAD_OF_LOCAL_HEAD"));
    }
    (bytes(&checkpoint["authority_root"]) != Some(&head.1) || bytes(&checkpoint["log_root"]) != Some(&head.2) || uint(&checkpoint["log_size"]) != Some(head.3)).then_some(("FAIL", "AUTHORITY_CHECKPOINT_FORK"))
}

fn decimal_at_most(left: &C, right: &C) -> bool {
    matches!((decimal(left), decimal(right)), (Some(a), Some(b)) if a.len() < b.len() || (a.len() == b.len() && a <= b))
}
fn registration_digests_match(credential: &Doc, selection: &[u8], pop: &[u8]) -> bool {
    bytes(&credential["admin_selection_digest"]) == Some(&core_digest(selection)) && bytes(&credential["agent_pop_digest"]) == Some(&core_digest(pop))
}

#[derive(Clone)]
#[allow(dead_code)] // Fields are consumed by the native durable-store adapter; WASM is read-only.
struct ConsumeContext {
    key: (String, Vec<u8>, Vec<u8>, Vec<u8>),
    action_key: (String, Vec<u8>, Vec<u8>),
    action_digest: Vec<u8>,
    presentation_digest: Vec<u8>,
    vector: BTreeMap<String, String>,
}

struct Evaluation<'a> {
    input: &'a InputContext,
    vector: BTreeMap<String, String>,
    challenge: Cwt,
    challenge_doc: Doc,
    action: Doc,
    action_bytes: Vec<u8>,
    pres: Doc,
    rooted: BTreeMap<&'static str, Cwt>,
    signed: BTreeMap<&'static str, Cwt>,
    credential: Option<Cwt>,
    selection: Option<C>,
    selection_raw: Vec<u8>,
    head_root: Vec<u8>,
}

impl<'a> Evaluation<'a> {
    fn reject(&self, verdict: &str, reason: impl Into<String>) -> ResultValue {
        ResultValue::new(verdict, reason, self.vector.clone())
    }

    fn start(input: &'a InputContext) -> Result<Self, ResultValue> {
        let mut vector = initial_vector();
        if input.challenger_keys.is_empty() {
            return Err(ResultValue::new("INDETERMINATE", "NO_LOCAL_CHALLENGER_KEY", vector));
        }
        let challenge = signed_cwt(&input.challenge, CHALLENGE, &input.challenger_keys).ok_or_else(|| ResultValue::new("FAIL", "CHALLENGE_SIGNATURE_OR_PROFILE_INVALID", vector.clone()))?;
        let challenge_doc = plain(&challenge.core).unwrap();
        let challenger = plain(&challenge_doc["challenger"]).unwrap();
        if text(&challenger["agent_kid"]) != Some(&challenge.kid) {
            return Err(ResultValue::new("FAIL", "CHALLENGE_SIGNER_MISMATCH", vector));
        }
        let action = plain(&challenge_doc["action"]).unwrap();
        if uint(&challenge_doc["issued_at"]).unwrap() > input.now {
            return Err(ResultValue::new("INDETERMINATE", "CHALLENGE_NOT_CURRENT", vector));
        }
        if input.now >= uint(&action["expires_at"]).unwrap() {
            return Err(ResultValue::new("FAIL", "CHALLENGE_EXPIRED", vector));
        }
        if uint(&action["expires_at"]).unwrap() - uint(&challenge_doc["issued_at"]).unwrap() > input.max_action_lifetime_s {
            return Err(ResultValue::new("INDETERMINATE", "ACTION_LIFETIME_EXCEEDS_LOCAL_POLICY", vector));
        }
        mark(&mut vector, &["challenge"], "VERIFIED");
        let presentation = inspect_cwt(&input.presentation, PRESENTATION).ok_or_else(|| ResultValue::new("FAIL", "PRESENTATION_NOT_STRICT_CWT", vector.clone()))?;
        let pres = plain(&presentation.core).unwrap();
        let action_bytes = canonical(&challenge_doc["action"]).unwrap();
        let bindings = [bytes(&pres["challenge_envelope_hash"]) == Some(&sha(&[&input.challenge])), bytes(&pres["challenge_digest"]) == Some(&core_digest(&challenge.core_bytes)), bytes(&pres["action_digest"]) == Some(&core_digest(&action_bytes))];
        if !bindings.into_iter().all(|held| held) {
            return Err(ResultValue::new("FAIL", "PRESENTATION_CHALLENGE_OR_ACTION_MISMATCH", vector));
        }
        Ok(Self { input, vector, challenge, challenge_doc, action, action_bytes, pres, rooted: BTreeMap::new(), signed: BTreeMap::new(), credential: None, selection: None, selection_raw: Vec::new(), head_root: Vec::new() })
    }

    fn roots(&mut self) -> Result<(), ResultValue> {
        let items = [("root_delegation", ROOT_DELEGATION), ("registration_template", TEMPLATE), ("admin_binding", ADMIN_BINDING), ("admin_challenge", ADMIN_CHALLENGE), ("admin_consumption", ADMIN_CONSUMPTION), ("limit_grant", GRANT), ("authority_checkpoint", CHECKPOINT)];
        for (name, schema) in items {
            let Some(cwt) = bytes(&self.pres[name]).and_then(|raw| root_cwt(raw, schema, &self.input.roots)) else {
                return Err(self.reject("FAIL", "ROOT_AUTHORITY_CHAIN_INVALID"));
            };
            self.rooted.insert(name, cwt);
        }
        if let Some(raw) = bytes(&self.pres["agent_successor"]) {
            let Some(successor) = root_cwt(raw, AGENT_SUCCESSOR, &self.input.roots) else {
                return Err(self.reject("FAIL", "ROOT_AUTHORITY_CHAIN_INVALID"));
            };
            self.rooted.insert("agent_successor", successor);
        }
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        if self.rooted.values().any(|cwt| plain(&cwt.core).is_none_or(|doc| doc["organisation_root"] != delegation["organisation_root"] || doc["tenant"] != delegation["tenant"])) {
            return Err(self.reject("FAIL", "ROOT_OR_TENANT_SUBSTITUTION"));
        }
        let actor = plain(&self.action["actor"]).unwrap();
        if actor["organisation_root"] != delegation["organisation_root"] {
            return Err(self.reject("FAIL", "ACTOR_ORGANISATION_MISMATCH"));
        }
        if !matches!((uint(&delegation["valid_from"]), uint(&delegation["valid_to"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b) {
            return Err(self.reject("FAIL", "AUTHORITY_DELEGATION_INACTIVE"));
        }
        mark(&mut self.vector, &["root_chain", "delegation"], "VERIFIED");
        Ok(())
    }

    fn signatures(&mut self) -> Result<(), ResultValue> {
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let psa = BTreeMap::from([(text(&delegation["passport_authority_kid"]).unwrap().to_owned(), bytes(&delegation["passport_authority_key"]).unwrap().to_vec())]);
        let action = BTreeMap::from([(text(&delegation["action_authority_kid"]).unwrap().to_owned(), bytes(&delegation["action_authority_key"]).unwrap().to_vec())]);
        let Some(credential) = bytes(&self.pres["passport"]).and_then(|raw| signed_cwt(raw, CREDENTIAL, &psa)) else {
            return Err(self.reject("FAIL", "DELEGATED_OR_AGENT_SIGNATURE_INVALID"));
        };
        let Some(holder) = bytes(&self.pres["passport_holder_proof"]).and_then(|raw| inspect_cwt(raw, CREDENTIAL)) else {
            return Err(self.reject("FAIL", "DELEGATED_OR_AGENT_SIGNATURE_INVALID"));
        };
        if holder.core != credential.core {
            return Err(self.reject("FAIL", "PASSPORT_HOLDER_CORE_MISMATCH"));
        }
        let doc = plain(&credential.core).unwrap();
        let agent = BTreeMap::from([(text(&doc["agent_kid"]).unwrap().to_owned(), bytes(&doc["agent_key"]).unwrap().to_vec())]);
        let items = [("passport_holder_proof", CREDENTIAL, &agent), ("agent_pop", AGENT_POP, &agent), ("status_snapshot", SNAPSHOT, &psa), ("asa", ASA, &action)];
        for (name, schema, keys) in items {
            let Some(cwt) = bytes(&self.pres[name]).and_then(|raw| signed_cwt(raw, schema, keys)) else {
                return Err(self.reject("FAIL", "DELEGATED_OR_AGENT_SIGNATURE_INVALID"));
            };
            self.signed.insert(name, cwt);
        }
        if signed_cwt(&self.input.presentation, PRESENTATION, &agent).is_none() {
            return Err(self.reject("FAIL", "DELEGATED_OR_AGENT_SIGNATURE_INVALID"));
        }
        self.credential = Some(credential);
        mark(&mut self.vector, &["live_key_control", "passport_identity"], "VERIFIED");
        Ok(())
    }

    fn passport(&mut self) -> Result<(), ResultValue> {
        let credential = plain(&self.credential.as_ref().unwrap().core).unwrap();
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let template = plain(&self.rooted["registration_template"].core).unwrap();
        let actor = plain(&self.action["actor"]).unwrap();
        let pairs = [(&credential["organisation_root"], &delegation["organisation_root"]), (&credential["tenant"], &delegation["tenant"]), (&credential["authority_delegation_id"], &delegation["delegation_id"]), (&credential["birthtag"], &actor["birthtag"]), (&credential["revision"], &actor["revision"]), (&credential["agent_kid"], &actor["agent_kid"])];
        let role_collision = credential["agent_key"] == delegation["passport_authority_key"] || credential["agent_key"] == delegation["action_authority_key"];
        let live = matches!((uint(&credential["valid_from"]), uint(&credential["valid_to"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b);
        if role_collision {
            return Err(self.reject("FAIL", "AUTHORITY_KEY_ROLE_COLLISION"));
        }
        if pairs.iter().any(|(left, right)| left != right) || !live {
            return Err(self.reject("FAIL", "PASSPORT_BINDING_OR_VALIDITY_INVALID"));
        }
        if !successor_matches(&credential, self.rooted.get("agent_successor"), self.input.now) {
            return Err(self.reject("FAIL", "AGENT_SUCCESSOR_INVALID"));
        }
        let names = ["template_id", "template_version", "owner", "purpose", "mandate_digest", "config_digest"];
        let template_live = matches!((uint(&template["valid_from"]), uint(&template["valid_to"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b);
        if names.iter().any(|name| credential[*name] != template[*name]) || !template_live {
            return Err(self.reject("FAIL", "PASSPORT_TEMPLATE_MISMATCH"));
        }
        mark(&mut self.vector, &["binding"], "VERIFIED");
        Ok(())
    }

    fn registration(&mut self) -> Result<(), ResultValue> {
        let credential = plain(&self.credential.as_ref().unwrap().core).unwrap();
        let template = plain(&self.rooted["registration_template"].core).unwrap();
        let admin = plain(&self.rooted["admin_binding"].core).unwrap();
        let challenge = plain(&self.rooted["admin_challenge"].core).unwrap();
        let consumption = plain(&self.rooted["admin_consumption"].core).unwrap();
        let pop = plain(&self.signed["agent_pop"].core).unwrap();
        self.selection_raw = bytes(&self.pres["admin_selection"]).unwrap().to_vec();
        let Some(selection_value) = decode(&self.selection_raw, 16_384).filter(validate_selection) else {
            return Err(self.reject("FAIL", "TEMPLATE_ADMIN_POP_ISSUANCE_INVALID"));
        };
        let selection = plain(&selection_value).unwrap();
        let proposal = selected_digest(&credential).unwrap();
        #[rustfmt::skip]
        let checks = [
            bytes(&selection["proposed_agent_digest"]) == Some(&proposal), selection["template_id"] == template["template_id"], selection["template_version"] == template["template_version"],
            selection["binding_id"] == admin["binding_id"], credential["principal_binding_id"] == admin["binding_id"], selection["challenge_id"] == challenge["challenge_id"], selection["challenge"] == challenge["challenge"],
            selection["binding_id"] == challenge["binding_id"], selection["template_id"] == challenge["template_id"], selection["template_version"] == challenge["template_version"],
            selection["proposed_agent_digest"] == challenge["proposed_agent_digest"], bytes(&pop["proposed_agent_digest"]) == Some(&proposal), pop["challenge"] == selection["challenge"],
            pop["birthtag"] == credential["birthtag"], pop["revision"] == credential["revision"], pop["agent_kid"] == credential["agent_kid"],
            challenge["tenant"] == credential["tenant"], challenge["organisation_root"] == credential["organisation_root"],
            matches!((uint(&admin["valid_from"]), uint(&challenge["issued_at"]), uint(&admin["valid_to"])), (Some(a), Some(b), Some(c)) if a <= b && b < c),
            matches!((uint(&challenge["issued_at"]), uint(&selection["selected_at"]), uint(&challenge["expires_at"])), (Some(a), Some(b), Some(c)) if a <= b && b < c),
        ];
        let checks = checks.into_iter().all(|held| held);
        if !checks {
            return Err(self.reject("FAIL", "TEMPLATE_ADMIN_POP_ISSUANCE_INVALID"));
        }
        let (C::Bool(backup_eligible), C::Bool(backup_state)) = (&consumption["backup_eligible"], &consumption["backup_state"]) else { unreachable!() };
        let signed_state = CounterState { before: uint(&consumption["sign_count_before"]).unwrap(), after: uint(&consumption["sign_count_after"]).unwrap(), backup_eligible: *backup_eligible, backup_state: *backup_state };
        if verify_admin(&admin, &selection_value, &self.input.origin, signed_state.before, self.input.now).as_ref() != Some(&signed_state) {
            return Err(self.reject("FAIL", "TEMPLATE_ADMIN_POP_CONSUMPTION_INVALID"));
        }
        if !registration_digests_match(&credential, &self.selection_raw, &self.signed["agent_pop"].core_bytes) {
            return Err(self.reject("FAIL", "TEMPLATE_ADMIN_POP_ISSUANCE_INVALID"));
        }
        #[rustfmt::skip]
        let consumption_checks = [
            consumption["tenant"] == challenge["tenant"], consumption["organisation_root"] == challenge["organisation_root"], consumption["binding_id"] == admin["binding_id"], consumption["challenge_id"] == challenge["challenge_id"],
            bytes(&consumption["challenge_digest"]) == Some(&core_digest(&self.rooted["admin_challenge"].core_bytes)), bytes(&consumption["selection_digest"]) == Some(&core_digest(&self.selection_raw)),
            bytes(&consumption["credential_digest"]) == Some(&core_digest(&self.credential.as_ref().unwrap().core_bytes)),
            matches!((uint(&selection["selected_at"]), uint(&consumption["consumed_at"]), uint(&challenge["expires_at"])), (Some(a), Some(b), Some(c)) if a <= b && b <= self.input.now && b < c),
        ];
        if !consumption_checks.into_iter().all(|held| held) {
            return Err(self.reject("FAIL", "TEMPLATE_ADMIN_POP_CONSUMPTION_INVALID"));
        }
        self.selection = Some(selection_value);
        mark(&mut self.vector, &["template_admin_pop"], "VERIFIED");
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<(), ResultValue> {
        let checkpoint = plain(&self.rooted["authority_checkpoint"].core).unwrap();
        let credential = plain(&self.credential.as_ref().unwrap().core).unwrap();
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let digest = core_digest(&self.rooted["authority_checkpoint"].core_bytes);
        let key = (text(&checkpoint["tenant"]).unwrap().to_owned(), bytes(&checkpoint["organisation_root"]).unwrap().to_vec());
        let sequence = uint(&checkpoint["sequence"]).unwrap();
        let pin = (key.0.clone(), key.1.clone(), sequence, bytes(&checkpoint["authority_root"]).unwrap().to_vec(), bytes(&checkpoint["log_root"]).unwrap().to_vec(), uint(&checkpoint["log_size"]).unwrap());
        if self.input.checkpoints.get(digest.as_slice()) != Some(&pin) {
            return Err(self.reject("INDETERMINATE", "AUTHORITY_CHECKPOINT_UNREGISTERED"));
        }
        let Some(head) = self.input.heads.get(&key) else {
            return Err(self.reject("INDETERMINATE", "LOCAL_AUTHORITY_HEAD_UNAVAILABLE"));
        };
        if let Some((verdict, reason)) = checkpoint_head_error(&checkpoint, sequence, head) {
            return Err(self.reject(verdict, reason));
        }
        let Some(issued) = self.input.checkpoints.get(bytes(&credential["issuance_checkpoint"]).unwrap()).filter(|entry| entry.0 == key.0 && entry.1 == key.1 && entry.2 <= sequence) else {
            return Err(self.reject("INDETERMINATE", "PASSPORT_ISSUANCE_CHECKPOINT_UNREGISTERED"));
        };
        if !verify_consistency(&self.pres["issuance_consistency_proof"], issued.5, pin.5, &issued.4, &pin.4) {
            return Err(self.reject("FAIL", "PASSPORT_ISSUANCE_LOG_NOT_ANCESTOR"));
        }
        let snapshot = plain(&self.signed["status_snapshot"].core).unwrap();
        let proof_bytes = canonical(&self.pres["state_proofs"]).unwrap();
        let checks = [snapshot["organisation_root"] == checkpoint["organisation_root"], snapshot["tenant"] == checkpoint["tenant"], snapshot["authority_delegation_id"] == delegation["delegation_id"], bytes(&snapshot["checkpoint_digest"]) == Some(&digest), bytes(&snapshot["proofs_digest"]) == Some(&sha(&[b"swarrm-b28/proofs/v1\0", &proof_bytes]))];
        if !checks.into_iter().all(|held| held) {
            return Err(self.reject("FAIL", "STATUS_CHECKPOINT_BINDING_INVALID"));
        }
        if self.input.now.checked_sub(uint(&checkpoint["issued_at"]).unwrap()).is_none_or(|age| age > uint(&self.challenge_doc["max_checkpoint_age"]).unwrap()) {
            return Err(self.reject("INDETERMINATE", "STATUS_CHECKPOINT_STALE"));
        }
        if checkpoint["issued_at"] != snapshot["status_as_of"] {
            return Err(self.reject("FAIL", "STATUS_CHECKPOINT_BINDING_INVALID"));
        }
        if self.input.now >= uint(&snapshot["expires_at"]).unwrap() {
            return Err(self.reject("INDETERMINATE", "STATUS_CHECKPOINT_STALE"));
        }
        self.head_root = head.1.clone();
        Ok(())
    }

    fn authority_proofs(&mut self) -> Result<(), ResultValue> {
        let credential = plain(&self.credential.as_ref().unwrap().core).unwrap();
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let template = plain(&self.rooted["registration_template"].core).unwrap();
        let admin = plain(&self.rooted["admin_binding"].core).unwrap();
        let grant = plain(&self.rooted["limit_grant"].core).unwrap();
        let selection = plain(self.selection.as_ref().unwrap()).unwrap();
        let admin_challenge = plain(&self.rooted["admin_challenge"].core).unwrap();
        let admin_consumption = plain(&self.rooted["admin_consumption"].core).unwrap();
        let mut revision = bytes(&credential["birthtag"]).unwrap().to_vec();
        revision.extend_from_slice(&uint(&credential["revision"]).unwrap().to_be_bytes());
        let selection_id = bytes(&selection["challenge_id"]).unwrap().to_vec();
        let mut grant_id = bytes(&grant["grant_id"]).unwrap().to_vec();
        grant_id.extend_from_slice(&uint(&grant["grant_version"]).unwrap().to_be_bytes());
        #[rustfmt::skip]
        let objects = [
            ("root_delegation", "root_delegation", bytes(&delegation["delegation_id"]).unwrap().to_vec(), core_digest(&self.rooted["root_delegation"].core_bytes), "ACTIVE", None), ("registration_template", "registration_template", bytes(&template["template_id"]).unwrap().to_vec(), core_digest(&self.rooted["registration_template"].core_bytes), "ACTIVE", None),
            ("mandate", "mandate", bytes(&template["mandate_digest"]).unwrap().to_vec(), bytes(&template["mandate_digest"]).unwrap().try_into().unwrap(), "ACTIVE", None), ("agent_config", "agent_config", bytes(&template["config_digest"]).unwrap().to_vec(), bytes(&template["config_digest"]).unwrap().try_into().unwrap(), "ACTIVE", None),
            ("admin_binding", "admin_binding", bytes(&admin["binding_id"]).unwrap().to_vec(), core_digest(&self.rooted["admin_binding"].core_bytes), "ACTIVE", None), ("admin_selection", "admin_selection", selection_id, core_digest(&self.selection_raw), "ACTIVE", None),
            ("admin_challenge", "admin_challenge", bytes(&admin_challenge["challenge_id"]).unwrap().to_vec(), core_digest(&self.rooted["admin_challenge"].core_bytes), "SUPERSEDED", None), ("admin_consumption", "admin_consumption", bytes(&admin_consumption["challenge_id"]).unwrap().to_vec(), core_digest(&self.rooted["admin_consumption"].core_bytes), "ACTIVE", None),
            ("agent_pop", "agent_pop", revision.clone(), core_digest(&self.signed["agent_pop"].core_bytes), "ACTIVE", None), ("passport", "agent_credential", revision, core_digest(&self.credential.as_ref().unwrap().core_bytes), "ACTIVE", None),
            ("agent_head", "agent_head", bytes(&credential["birthtag"]).unwrap().to_vec(), core_digest(&self.credential.as_ref().unwrap().core_bytes), "ACTIVE", uint(&credential["revision"])),
            ("limit_grant", "limit_grant", grant_id, core_digest(&self.rooted["limit_grant"].core_bytes), "ACTIVE", None), ("grant_head", "grant_head", bytes(&grant["grant_id"]).unwrap().to_vec(), core_digest(&self.rooted["limit_grant"].core_bytes), "ACTIVE", None),
        ];
        let proofs = plain(&self.pres["state_proofs"]).unwrap();
        for (name, kind, id, digest, state, version) in objects {
            if !verify_state(&proofs[name], &self.head_root, &state_key(kind, &id), &digest, state, version) {
                return Err(self.reject("FAIL", format!("AUTHORITY_STATE_PROOF_INVALID:{name}")));
            }
        }
        if let Some(envelope) = self.rooted.get("agent_successor") {
            let link = plain(&envelope.core).unwrap();
            let successor = verify_state(&proofs["agent_successor"], &self.head_root, &state_key("agent_successor", bytes(&credential["birthtag"]).unwrap()), &core_digest(&envelope.core_bytes), "ACTIVE", Some(1));
            let predecessor = verify_state(&proofs["predecessor_head"], &self.head_root, &state_key("agent_head", bytes(&link["predecessor_birthtag"]).unwrap()), bytes(&link["predecessor_credential_digest"]).unwrap(), "SUPERSEDED", uint(&link["predecessor_revision"]).and_then(|version| version.checked_add(1)));
            if !successor || !predecessor {
                return Err(self.reject("FAIL", if !successor { "AUTHORITY_STATE_PROOF_INVALID:agent_successor" } else { "AUTHORITY_STATE_PROOF_INVALID:predecessor_head" }));
            }
        } else if proofs["agent_successor"] != C::Null || proofs["predecessor_head"] != C::Null {
            return Err(self.reject("FAIL", "AGENT_SUCCESSOR_INVALID"));
        }
        if !verify_counter_head(&proofs["admin_counter"], &self.head_root, bytes(&admin_consumption["binding_id"]).unwrap(), uint(&admin_consumption["counter_version"]).unwrap()) {
            return Err(self.reject("FAIL", "AUTHORITY_STATE_PROOF_INVALID:admin_counter"));
        }
        mark(&mut self.vector, &["fresh_status"], "VERIFIED");
        Ok(())
    }

    fn exact_action(&mut self) -> Result<(), ResultValue> {
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let grant = plain(&self.rooted["limit_grant"].core).unwrap();
        let actor = plain(&self.action["actor"]).unwrap();
        let recipient = plain(&self.action["recipient"]).unwrap();
        let action_scope = action_scope_digest(&self.action).unwrap();
        #[rustfmt::skip]
        let grant_checks = [
            grant["tenant"] == delegation["tenant"], grant["organisation_root"] == delegation["organisation_root"], grant["authority_delegation_id"] == delegation["delegation_id"],
            grant["actor_birthtag"] == actor["birthtag"], grant["recipient_organisation_root"] == recipient["organisation_root"], grant["operation"] == self.action["operation"],
            grant["unit"] == self.action["unit"], bytes(&grant["action_scope_digest"]) == Some(&action_scope), grant["grant_id"] == self.action["grant_id"], grant["grant_version"] == self.action["grant_version"],
            matches!((uint(&grant["valid_from"]), uint(&grant["valid_to"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b),
            matches!((uint(&grant["window_start"]), uint(&grant["window_end"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b), decimal_at_most(&self.action["value"], &grant["ceiling"]),
        ];
        if !grant_checks.into_iter().all(|held| held) {
            return Err(self.reject("FAIL", "ACTION_OUTSIDE_ROOT_LIMIT_GRANT"));
        }
        mark(&mut self.vector, &["grant"], "VERIFIED");
        let asa = plain(&self.signed["asa"].core).unwrap();
        #[rustfmt::skip]
        let asa_checks = [
            asa["organisation_root"] == delegation["organisation_root"], asa["tenant"] == delegation["tenant"], asa["authority_delegation_id"] == delegation["delegation_id"], asa["asa_id"] == self.action["asa_id"],
            bytes(&asa["action_digest"]) == Some(&core_digest(&self.action_bytes)), bytes(&asa["challenge_digest"]) == Some(&core_digest(&self.challenge.core_bytes)), asa["grant_id"] == self.action["grant_id"],
            asa["grant_version"] == self.action["grant_version"], asa["expires_at"] == self.action["expires_at"],
            matches!((uint(&asa["issued_at"]), uint(&asa["expires_at"])), (Some(a), Some(b)) if a <= self.input.now && self.input.now < b),
        ];
        if !asa_checks.into_iter().all(|held| held) {
            return Err(self.reject("FAIL", "ASA_EXACT_BINDING_OR_VALIDITY_INVALID"));
        }
        mark(&mut self.vector, &["asa_reservation", "exact_action"], "VERIFIED");
        Ok(())
    }

    fn finish(mut self) -> Result<ConsumeContext, ResultValue> {
        let delegation = plain(&self.rooted["root_delegation"].core).unwrap();
        let asa_raw = bytes(&self.pres["asa"]).unwrap();
        let transcript = map_value(vec![("schema", C::Text("swarrm-b28/transcript/v1".to_owned())), ("challenge_envelope_hash", C::Bytes(sha(&[&self.input.challenge]).to_vec())), ("challenge_digest", C::Bytes(core_digest(&self.challenge.core_bytes).to_vec())), ("action_digest", C::Bytes(core_digest(&self.action_bytes).to_vec())), ("asa_envelope_hash", C::Bytes(sha(&[asa_raw]).to_vec())), ("asa_digest", C::Bytes(core_digest(&self.signed["asa"].core_bytes).to_vec()))]);
        let digest = sha(&[b"swarrm-b28/transcript/v1\0", &canonical(&transcript).unwrap()]);
        if bytes(&self.pres["transcript_digest"]) != Some(&digest) {
            return Err(self.reject("FAIL", "TRANSCRIPT_BINDING_INVALID"));
        }
        if !matches!((uint(&self.challenge_doc["issued_at"]), uint(&self.action["expires_at"]), uint(&self.pres["created_at"])), (Some(a), Some(b), Some(c)) if a <= c && c < b) {
            return Err(self.reject("FAIL", "PRESENTATION_TIME_OUTSIDE_CHALLENGE"));
        }
        let (asa, checkpoint, snapshot) = (plain(&self.signed["asa"].core).unwrap(), plain(&self.rooted["authority_checkpoint"].core).unwrap(), plain(&self.signed["status_snapshot"].core).unwrap());
        let created_at = uint(&self.pres["created_at"]).unwrap();
        if !matches!((uint(&asa["issued_at"]), uint(&checkpoint["issued_at"]), uint(&snapshot["status_as_of"])), (Some(a), Some(b), Some(c)) if a <= created_at && b <= created_at && c <= created_at) {
            return Err(self.reject("FAIL", "PRESENTATION_TIME_OUTSIDE_ASSURANCE"));
        }
        if created_at > self.input.now {
            return Err(self.reject("FAIL", "PRESENTATION_TIME_OUTSIDE_LOCAL_CLOCK"));
        }
        mark(&mut self.vector, &["transcript"], "VERIFIED");
        let C::Array(required) = &self.challenge_doc["required_dimensions"] else { unreachable!() };
        let unavailable = required.iter().filter_map(text).filter(|name| UNEVALUATED.contains(name)).collect::<Vec<_>>();
        if !unavailable.is_empty() {
            return Err(self.reject("INDETERMINATE", format!("REQUIRED_DIMENSION_NOT_EVALUATED_V1:{}", unavailable.join(","))));
        }
        let actor = plain(&self.action["actor"]).unwrap();
        let tenant = text(&delegation["tenant"]).unwrap().to_owned();
        Ok(ConsumeContext { key: (tenant.clone(), bytes(&delegation["organisation_root"]).unwrap().to_vec(), bytes(&delegation["delegation_id"]).unwrap().to_vec(), bytes(&self.action["asa_id"]).unwrap().to_vec()), action_key: (tenant, bytes(&actor["organisation_root"]).unwrap().to_vec(), bytes(&self.action["action_id"]).unwrap().to_vec()), action_digest: core_digest(&self.action_bytes).to_vec(), presentation_digest: sha(&[&self.input.presentation]).to_vec(), vector: self.vector })
    }
}

fn evaluate(input: &InputContext) -> (ResultValue, Option<ConsumeContext>) {
    let mut evaluation = match Evaluation::start(input) {
        Ok(value) => value,
        Err(result) => return (result, None),
    };
    macro_rules! step {
        ($method:ident) => {
            if let Err(result) = evaluation.$method() {
                return (result, None);
            }
        };
    }
    step!(roots);
    step!(signatures);
    step!(passport);
    step!(registration);
    step!(checkpoint);
    step!(authority_proofs);
    step!(exact_action);
    match evaluation.finish() {
        Ok(context) => (ResultValue::new("INDETERMINATE", "DURABLE_REPLAY_REQUIRED", context.vector.clone()), Some(context)),
        Err(result) => (result, None),
    }
}

fn refusal_time_reason(challenge: &Doc, refusal: &Doc, action: &Doc, now: u64) -> Option<&'static str> {
    let Some(created) = uint(&refusal["created_at"]) else { return Some("REFUSAL_TIME_OUTSIDE_LOCAL_CLOCK") };
    if created > now {
        return Some("REFUSAL_TIME_OUTSIDE_LOCAL_CLOCK");
    }
    (!matches!((uint(&challenge["issued_at"]), uint(&action["expires_at"])), (Some(start), Some(end)) if start <= created && created < end)).then_some("REFUSAL_TIME_OUTSIDE_CHALLENGE")
}

fn evaluate_refusal(input: &RefusalContext) -> ResultValue {
    let mut vector = initial_vector();
    if input.challenger_keys.is_empty() {
        return ResultValue::new("INDETERMINATE", "NO_LOCAL_CHALLENGER_KEY", vector);
    }
    if input.responder_keys.is_empty() {
        return ResultValue::new("INDETERMINATE", "NO_LOCAL_RESPONDER_KEY", vector);
    }
    let Some(challenge) = signed_cwt(&input.challenge, CHALLENGE, &input.challenger_keys) else {
        return ResultValue::new("FAIL", "SIGNED_REFUSAL_INVALID", vector);
    };
    let challenge_doc = plain(&challenge.core).unwrap();
    let challenger = plain(&challenge_doc["challenger"]).unwrap();
    if text(&challenger["agent_kid"]) != Some(&challenge.kid) {
        return ResultValue::new("FAIL", "CHALLENGE_SIGNER_MISMATCH", vector);
    }
    let action = plain(&challenge_doc["action"]).unwrap();
    if !matches!((uint(&challenge_doc["issued_at"]), uint(&action["expires_at"])), (Some(a), Some(b)) if a <= input.now && input.now < b) {
        return ResultValue::new("FAIL", "CHALLENGE_EXPIRED", vector);
    }
    let Some(refusal) = signed_cwt(&input.refusal, REFUSAL, &input.responder_keys) else {
        return ResultValue::new("FAIL", "SIGNED_REFUSAL_INVALID", vector);
    };
    let refusal_doc = plain(&refusal.core).unwrap();
    let actor = plain(&action["actor"]).unwrap();
    if text(&actor["agent_kid"]) != Some(&refusal.kid) {
        return ResultValue::new("FAIL", "REFUSAL_SIGNER_MISMATCH", vector);
    }
    let bindings = [bytes(&refusal_doc["challenge_envelope_hash"]) == Some(&sha(&[&input.challenge])), bytes(&refusal_doc["challenge_digest"]) == Some(&core_digest(&challenge.core_bytes))];
    if !bindings.into_iter().all(|held| held) {
        return ResultValue::new("FAIL", "REFUSAL_CHALLENGE_MISMATCH", vector);
    }
    if let Some(reason) = refusal_time_reason(&challenge_doc, &refusal_doc, &action, input.now) {
        return ResultValue::new("FAIL", reason, vector);
    }
    mark(&mut vector, &["challenge", "binding"], "VERIFIED");
    ResultValue::new("FAIL", "SIGNED_REFUSAL", vector)
}

/// Verify a two-field exchange after locally validating context and root pin.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_b28_cwt(exchange: &[u8], local_context: &[u8], trust_pack: &[u8], expected_trust_pack_digest: &[u8]) -> String {
    let Some(roots) = parse_pinned_trust_pack(trust_pack, expected_trust_pack_digest) else {
        let result = ResultValue::new("INDETERMINATE", "NO_PINNED_TRUST_PACK", initial_vector());
        return serde_json::to_string(&result.json()).expect("result is a fixed JSON-compatible value");
    };
    let local = match parse_local_context(local_context) {
        Ok(local) => local,
        Err(reason) => {
            let result = ResultValue::new("INDETERMINATE", reason, initial_vector());
            return serde_json::to_string(&result.json()).expect("result is a fixed JSON-compatible value");
        }
    };
    let result = match local {
        LocalContext::Presentation(local) => parse_input(exchange, local, &roots).map(|input| evaluate(&input).0),
        LocalContext::Refusal(local) => parse_refusal(exchange, local).map(|input| evaluate_refusal(&input)),
    }
    .unwrap_or_else(|| ResultValue::new("INDETERMINATE", "VERIFIER_CONTEXT_INVALID", initial_vector()));
    serde_json::to_string(&result.json()).expect("result is a fixed JSON-compatible value")
}

#[cfg(test)]
#[path = "b28_tests.rs"]
mod tests;
