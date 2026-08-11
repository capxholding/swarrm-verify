// Apache-2.0 (public verifier repo)
use super::*;

type ReplayKey = (String, Vec<u8>, Vec<u8>, Vec<u8>);
type ActionKey = (String, Vec<u8>, Vec<u8>);
type ReplayRecord = (Vec<u8>, Vec<u8>, ResultValue);

fn fixture_trust() -> BTreeMap<String, RootAnchor> {
    let pack = include_bytes!("../../../tests/golden/b28/trust-pack.cbor");
    parse_pinned_trust_pack(pack, &sha(&[pack])).unwrap()
}

fn presentation_context() -> PresentationLocal {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/golden/b28/verify-context.cbor");
    let Ok(LocalContext::Presentation(context)) = parse_local_context(&std::fs::read(path).unwrap()) else { unreachable!() };
    context
}

fn presentation_context_bytes() -> Vec<u8> {
    std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/golden/b28/verify-context.cbor")).unwrap()
}

fn parse_fixture(raw: &[u8]) -> InputContext {
    parse_input(raw, presentation_context(), &fixture_trust()).unwrap()
}

#[derive(Default)]
struct MemoryStore {
    asa: BTreeMap<ReplayKey, ReplayRecord>,
    action: BTreeMap<ActionKey, ReplayRecord>,
}

enum ReplayOutcome {
    Stored(ResultValue),
    AsaConflict,
    ActionConflict,
    Corrupt,
    Unavailable,
}

trait ReplayStore {
    fn consume(&mut self, context: &ConsumeContext, acceptance: &ResultValue) -> ReplayOutcome;
}

fn evaluate_and_consume(input: &InputContext, store: &mut dyn ReplayStore) -> ResultValue {
    let (result, context) = evaluate(input);
    let Some(context) = context else { return result };
    let mut vector = context.vector.clone();
    mark(&mut vector, &["replay"], "VERIFIED");
    let acceptance = ResultValue::new("INDETERMINATE", "PASS_NOT_ENABLED", vector.clone());
    match store.consume(&context, &acceptance) {
        ReplayOutcome::Stored(stored) => stored,
        ReplayOutcome::AsaConflict => {
            mark(&mut vector, &["replay"], "FAIL");
            ResultValue::new("FAIL", "ASA_REPLAY_CONFLICT", vector)
        }
        ReplayOutcome::ActionConflict => {
            mark(&mut vector, &["replay"], "FAIL");
            ResultValue::new("FAIL", "ACTION_ID_REPLAY_CONFLICT", vector)
        }
        ReplayOutcome::Corrupt => ResultValue::new("INDETERMINATE", "DURABLE_REPLAY_STORE_CORRUPT", vector),
        ReplayOutcome::Unavailable => ResultValue::new("INDETERMINATE", "DURABLE_REPLAY_STORE_UNAVAILABLE", vector),
    }
}

impl ReplayStore for MemoryStore {
    fn consume(&mut self, context: &ConsumeContext, acceptance: &ResultValue) -> ReplayOutcome {
        let (asa, action) = (self.asa.get(&context.key), self.action.get(&context.action_key));
        if asa.is_some() || action.is_some() {
            let Some(asa) = asa else { return ReplayOutcome::ActionConflict };
            let Some(action) = action else { return ReplayOutcome::Corrupt };
            if asa.0 != context.action_digest || asa.1 != context.presentation_digest {
                return ReplayOutcome::AsaConflict;
            }
            if action.0 != context.action_digest || action.1 != context.presentation_digest {
                return ReplayOutcome::ActionConflict;
            }
            return if asa.2.json() == action.2.json() { ReplayOutcome::Stored(asa.2.clone()) } else { ReplayOutcome::Corrupt };
        }
        let record = (context.action_digest.clone(), context.presentation_digest.clone(), acceptance.clone());
        self.asa.insert(context.key.clone(), record.clone());
        self.action.insert(context.action_key.clone(), record);
        ReplayOutcome::Stored(acceptance.clone())
    }
}

#[test]
fn durable_consume_is_idempotent_and_conflicts_fail() {
    let valid = parse_fixture(include_bytes!("../../../tests/golden/b28/verify-input.cbor"));
    let changed = parse_fixture(include_bytes!("../../../tests/golden/b28/replay-conflict-input.cbor"));
    let expected: J = serde_json::from_str(include_str!("../../../tests/golden/b28/manifest.json")).unwrap();
    let mut store = MemoryStore::default();
    assert_eq!(evaluate_and_consume(&valid, &mut store).json(), expected["expected_consume_first"]);
    assert_eq!(evaluate_and_consume(&valid, &mut store).json(), expected["expected_consume_retry"]);
    assert_eq!(evaluate_and_consume(&changed, &mut store).json(), expected["expected_consume_conflict"]);
}

#[test]
fn unavailable_store_cannot_authorize() {
    struct Unavailable;
    impl ReplayStore for Unavailable {
        fn consume(&mut self, _: &ConsumeContext, _: &ResultValue) -> ReplayOutcome {
            ReplayOutcome::Unavailable
        }
    }
    let input = parse_fixture(include_bytes!("../../../tests/golden/b28/verify-input.cbor"));
    let result = evaluate_and_consume(&input, &mut Unavailable);
    assert_eq!(result.reason, "DURABLE_REPLAY_STORE_UNAVAILABLE");
    assert_eq!(result.verdict, "INDETERMINATE");
}

#[test]
fn action_id_claim_rejects_a_fresh_asa_or_changed_action() {
    let input = parse_fixture(include_bytes!("../../../tests/golden/b28/verify-input.cbor"));
    let (_, Some(context)) = evaluate(&input) else { unreachable!() };
    let acceptance = ResultValue::new("INDETERMINATE", "PASS_NOT_ENABLED", context.vector.clone());
    let mut store = MemoryStore::default();
    assert!(matches!(store.consume(&context, &acceptance), ReplayOutcome::Stored(_)));

    let mut fresh_asa = context.clone();
    fresh_asa.key.3 = vec![0x11; 32];
    assert!(matches!(store.consume(&fresh_asa, &acceptance), ReplayOutcome::ActionConflict));

    let mut changed_action = fresh_asa;
    changed_action.key.3 = vec![0x22; 32];
    changed_action.action_digest = vec![0x33; 32];
    assert!(matches!(store.consume(&changed_action, &acceptance), ReplayOutcome::ActionConflict));
}

#[test]
fn semantic_digests_match_the_cross_language_manifest() {
    let expected: J = serde_json::from_str(include_str!("../../../tests/golden/b28/manifest.json")).unwrap();
    let challenge = inspect_cwt(include_bytes!("../../../tests/golden/b28/challenge.cwt"), CHALLENGE).unwrap();
    let presentation = inspect_cwt(include_bytes!("../../../tests/golden/b28/presentation.cwt"), PRESENTATION).unwrap();
    let challenge_doc = plain(&challenge.core).unwrap();
    let presentation_doc = plain(&presentation.core).unwrap();
    let hex = |raw: &[u8]| raw.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    let digests = &expected["semantic_digests"];
    assert_eq!(hex(&core_digest(&challenge.core_bytes)), digests["challenge_core_digest"]);
    assert_eq!(hex(&core_digest(&canonical(&challenge_doc["action"]).unwrap())), digests["action_core_digest"]);
    assert_eq!(hex(&sha(&[include_bytes!("../../../tests/golden/b28/presentation.cwt")])), digests["presentation_envelope_hash"]);
    assert_eq!(hex(bytes(&presentation_doc["transcript_digest"]).unwrap()), digests["transcript_digest"]);
}

fn fixture_challenge_core() -> C {
    let raw = include_bytes!("../../../tests/golden/b28/challenge.cwt");
    let C::Array(items) = decode(&raw[1..], MAX_CWT).unwrap() else { unreachable!() };
    let C::Bytes(payload) = &items[2] else { unreachable!() };
    let payload = decode(payload, MAX_CWT).unwrap();
    if validate_core(&payload, CHALLENGE) {
        return payload;
    }
    let C::Map(claims) = payload else { unreachable!() };
    integer(&claims, B28_CORE_CLAIM).unwrap().clone()
}

fn fixture_presentation_core() -> C {
    let raw = include_bytes!("../../../tests/golden/b28/presentation.cwt");
    let C::Array(items) = decode(&raw[1..], MAX_CWT).unwrap() else { unreachable!() };
    let C::Bytes(payload) = &items[2] else { unreachable!() };
    let C::Map(claims) = decode(payload, MAX_CWT).unwrap() else { unreachable!() };
    integer(&claims, B28_CORE_CLAIM).unwrap().clone()
}

fn presented_core(field: &str, schema: &str) -> C {
    let presentation = fixture_presentation_core();
    let document = plain(&presentation).unwrap();
    inspect_cwt(bytes(&document[field]).unwrap(), schema).unwrap().core
}

fn set_member(value: &mut C, name: &str, replacement: C) {
    let C::Map(entries) = value else { unreachable!() };
    if let Some((_, value)) = entries.iter_mut().find(|(key, _)| text(key) == Some(name)) {
        *value = replacement;
    } else {
        entries.push((C::Text(name.to_owned()), replacement));
    }
}

fn exact_b28_cwt(protected: C, claims: C) -> Vec<u8> {
    let outer = C::Array(vec![C::Bytes(canonical(&protected).unwrap()), C::Map(vec![]), C::Bytes(canonical(&claims).unwrap()), C::Bytes(vec![0; 64])]);
    let mut raw = vec![0xd2];
    raw.extend(canonical(&outer).unwrap());
    raw
}

fn b28_header(extra: bool) -> C {
    let mut header = vec![(C::Integer(1.into()), C::Integer((-8).into())), (C::Integer(3.into()), C::Text(MEDIA.to_owned())), (C::Integer(4.into()), C::Bytes(b"test-kid".to_vec()))];
    if extra {
        header.push((C::Integer(15.into()), C::Null));
    }
    C::Map(header)
}

fn b28_claims(core: C) -> C {
    C::Map(vec![(C::Integer(CWT_PROFILE_CLAIM.into()), C::Text(PROFILE.to_owned())), (C::Integer(B28_CORE_CLAIM.into()), core)])
}

#[test]
fn cwt_payload_claims_are_exact_numeric_wrapper_and_keep_inner_digest() {
    let core = fixture_challenge_core();
    let parsed = inspect_cwt(&exact_b28_cwt(b28_header(false), b28_claims(core.clone())), CHALLENGE).unwrap();
    assert_eq!(parsed.core, core);
    assert_eq!(parsed.core_bytes, canonical(&parsed.core).unwrap());
    assert!(inspect_cwt(&exact_b28_cwt(b28_header(true), b28_claims(parsed.core.clone())), CHALLENGE).is_none());
    let malformed = vec![
        C::Map(vec![(C::Text("265".to_owned()), C::Text(PROFILE.to_owned())), (C::Integer(B28_CORE_CLAIM.into()), parsed.core.clone())]),
        C::Map(vec![(C::Integer(CWT_PROFILE_CLAIM.into()), C::Text("wrong".to_owned())), (C::Integer(B28_CORE_CLAIM.into()), parsed.core.clone())]),
        C::Map(vec![(C::Integer(CWT_PROFILE_CLAIM.into()), C::Text(PROFILE.to_owned()))]),
        C::Map(vec![(C::Integer(CWT_PROFILE_CLAIM.into()), C::Text(PROFILE.to_owned())), (C::Integer(B28_CORE_CLAIM.into()), C::Text("not-a-core".to_owned()))]),
        C::Map(vec![(C::Integer(CWT_PROFILE_CLAIM.into()), C::Text(PROFILE.to_owned())), (C::Integer(B28_CORE_CLAIM.into()), parsed.core.clone()), (C::Integer(1.into()), C::Null)]),
    ];
    for claims in malformed {
        assert!(inspect_cwt(&exact_b28_cwt(b28_header(false), claims), CHALLENGE).is_none());
    }
}

#[test]
fn b28_integers_are_capped_at_signed_i64() {
    assert_eq!(uint(&C::Integer(i64::MAX.into())), Some(i64::MAX as u64));
    assert!(uint(&C::Integer((i64::MAX as u64 + 1).into())).is_none());
    assert!(canonical(&C::Integer(i64::MAX.into())).is_some());
    assert!(canonical(&C::Integer((i64::MAX as u64 + 1).into())).is_none());
}

#[test]
fn governance_root_cannot_be_reused_by_delegated_or_agent_roles() {
    let delegation = presented_core("root_delegation", ROOT_DELEGATION);
    for field in ["passport_authority_key", "action_authority_key"] {
        let mut changed = delegation.clone();
        let key = bytes(&plain(&changed).unwrap()[field]).unwrap().to_vec();
        set_member(&mut changed, "organisation_root", C::Bytes(sha(&[&key]).to_vec()));
        assert!(!validate_delegation(&changed));
    }

    let mut credential = presented_core("passport", CREDENTIAL);
    let key = bytes(&plain(&credential).unwrap()["agent_key"]).unwrap().to_vec();
    set_member(&mut credential, "organisation_root", C::Bytes(sha(&[&key]).to_vec()));
    assert!(!validate_credential(&credential));
}

#[test]
fn b28_cbor_item_cap_precedes_codec_materialization() {
    let mut payload = vec![0x9a];
    payload.extend_from_slice(&(MAX_CBOR_ITEMS as u32).to_be_bytes());
    payload.extend(std::iter::repeat_n(0xf4, MAX_CBOR_ITEMS));
    assert!(decode(&payload, MAX_INPUT).is_none());
}

#[test]
fn b28_cbor_preflight_rejects_depth_truncation_and_unsupported_items() {
    let mut deep = vec![0x81; MAX_CBOR_DEPTH + 1];
    deep.push(0xf4);
    assert!(decode(&deep, MAX_INPUT).is_none());
    for raw in [vec![0x43, 1, 2], vec![0xc0, 0xf6], vec![0xf9, 0, 0], vec![0x9f, 0xff]] {
        assert!(decode(&raw, MAX_INPUT).is_none(), "{raw:02x?}");
    }
}

#[test]
fn presentation_non_assertion_is_closed() {
    let mut presentation = fixture_presentation_core();
    set_member(&mut presentation, "non_assertion", C::Text(NON_ASSERTION.to_owned()));
    assert!(validate_presentation(&presentation));
    set_member(&mut presentation, "non_assertion", C::Text("omits a frozen limitation".to_owned()));
    assert!(!validate_presentation(&presentation));
    set_member(&mut presentation, "non_assertion", C::Text(format!("{NON_ASSERTION} ")));
    assert!(!validate_presentation(&presentation));
}

#[test]
fn local_action_lifetime_is_closed_and_enforced_before_presentation_use() {
    let mut context = decode(&presentation_context_bytes(), MAX_LOCAL_CONTEXT).unwrap();
    set_member(&mut context, "max_action_lifetime_s", C::Integer(1.into()));
    let bytes = canonical(&context).unwrap();
    let Ok(LocalContext::Presentation(local)) = parse_local_context(&bytes) else { unreachable!() };
    let input = parse_input(include_bytes!("../../../tests/golden/b28/verify-input.cbor"), local, &fixture_trust()).unwrap();
    let (result, _) = evaluate(&input);
    assert_eq!(result.reason, "ACTION_LIFETIME_EXCEEDS_LOCAL_POLICY");
    for value in [C::Integer(0.into()), C::Integer(301.into()), C::Text("60".to_owned())] {
        let mut context = decode(&presentation_context_bytes(), MAX_LOCAL_CONTEXT).unwrap();
        set_member(&mut context, "max_action_lifetime_s", value);
        assert!(parse_local_context(&canonical(&context).unwrap()).is_err());
    }
}

#[test]
fn challenge_must_be_current_before_expiry_or_lifetime() {
    let challenge = fixture_challenge_core();
    let issued_at = uint(&plain(&challenge).unwrap()["issued_at"]).unwrap();
    let mut context = decode(&presentation_context_bytes(), MAX_LOCAL_CONTEXT).unwrap();
    set_member(&mut context, "max_action_lifetime_s", C::Integer(300.into()));
    set_member(&mut context, "now", C::Integer((issued_at - 1).into()));
    let Ok(LocalContext::Presentation(local)) = parse_local_context(&canonical(&context).unwrap()) else { unreachable!() };
    let input = parse_input(include_bytes!("../../../tests/golden/b28/verify-input.cbor"), local, &fixture_trust()).unwrap();
    let (result, _) = evaluate(&input);
    assert_eq!(result.verdict, "INDETERMINATE");
    assert_eq!(result.reason, "CHALLENGE_NOT_CURRENT");
}

#[test]
fn grant_exposure_is_bounded_by_the_grant_ceiling() {
    assert!(decimal_at_most(&C::Text("100".to_owned()), &C::Text("100".to_owned())));
    assert!(!decimal_at_most(&C::Text("101".to_owned()), &C::Text("100".to_owned())));
}

#[test]
fn counter_head_can_advance_but_never_roll_back() {
    let binding = vec![0x42; 32];
    let key = state_key("admin_counter", &binding);
    let value = map_value(vec![("key", C::Bytes(key.to_vec())), ("state", C::Text("ACTIVE".to_owned())), ("version", C::Integer(2.into())), ("object_digest", C::Bytes(vec![0x24; 32]))]);
    let root = sha(&[b"\0", &canonical(&value).unwrap()]);
    let proof = map_value(vec![("schema", C::Text(MEMBERSHIP.to_owned())), ("key", C::Bytes(key.to_vec())), ("value", value), ("index", C::Integer(0.into())), ("tree_size", C::Integer(1.into())), ("path", C::Array(vec![]))]);
    assert!(verify_counter_head(&proof, &root, &binding, 1));
    assert!(!verify_counter_head(&proof, &root, &binding, 3));
}

#[test]
fn webauthn_origin_is_exact_canonical_https_host() {
    assert!(canonical_origin("https://console.example", "console.example"));
    assert!(canonical_origin("https://console.example/", "console.example"));
    for (origin, rp_id) in [
        ("https://CONSOLE.example", "CONSOLE.example"),
        ("https://console.example:443", "console.example:443"),
        ("https://console.example:0443", "console.example:0443"),
        ("https://console.example/path", "console.example/path"),
        ("https://admin@console.example", "admin@console.example"),
        ("https://console.example?next=x", "console.example?next=x"),
        ("https://console.example#fragment", "console.example#fragment"),
        ("https://console.example\\evil", "console.example\\evil"),
        ("https://console..example", "console..example"),
        ("https://-console.example", "-console.example"),
        ("https://console-.example", "console-.example"),
        ("https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"),
        ("https://cönsole.example", "cönsole.example"),
    ] {
        assert!(!canonical_origin(origin, rp_id), "{origin}");
    }
}

#[test]
fn exchange_cannot_supply_or_replace_root_trust() {
    let clean = include_bytes!("../../../tests/golden/b28/verify-input.cbor");
    let context = presentation_context_bytes();
    assert!(parse_input(clean, presentation_context(), &fixture_trust()).is_some());

    let C::Map(mut entries) = decode(clean, MAX_INPUT).unwrap() else { unreachable!() };
    entries.push((C::Text("trust_pack".to_owned()), C::Bytes(vec![0; 1])));
    entries.push((C::Text("trust_pack_digest".to_owned()), C::Bytes(vec![0; 32])));
    let supplied = canonical(&C::Map(entries)).unwrap();
    assert!(parse_input(&supplied, presentation_context(), &fixture_trust()).is_none());

    let pack = include_bytes!("../../../tests/golden/b28/trust-pack.cbor");
    let rejected: J = serde_json::from_str(&verify_b28_cwt(&supplied, &context, pack, &sha(&[pack]))).unwrap();
    assert_eq!(rejected["verdict"], "INDETERMINATE");
    assert_eq!(rejected["reasons"], serde_json::json!(["VERIFIER_CONTEXT_INVALID"]));

    let C::Map(mut entries) = decode(&context, MAX_LOCAL_CONTEXT).unwrap() else { unreachable!() };
    entries.push((C::Text("admin_counter_states".to_owned()), C::Array(vec![])));
    let supplied_context = canonical(&C::Map(entries)).unwrap();
    let rejected: J = serde_json::from_str(&verify_b28_cwt(clean, &supplied_context, pack, &sha(&[pack]))).unwrap();
    assert_eq!(rejected["verdict"], "INDETERMINATE");
    assert_eq!(rejected["reasons"], serde_json::json!(["VERIFIER_CONTEXT_INVALID"]));

    let result: J = serde_json::from_str(&verify_b28_cwt(clean, &context, pack, &[0; 32])).unwrap();
    assert_eq!(result["verdict"], "INDETERMINATE");
    assert_eq!(result["reasons"], serde_json::json!(["NO_PINNED_TRUST_PACK"]));
}
