use super::*;
use std::{fs, path::PathBuf};

fn golden(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden").join(path)
}

fn core_json(bytes: &[u8]) -> J {
    cbor_to_json(&decode_cbor(bytes, MAX_DEPTH as usize, MAX_CORE_BYTES).unwrap(), MAX_DEPTH).unwrap()
}

fn read_pack(name: &str) -> J {
    serde_json::from_str(&fs::read_to_string(golden("scitt").join(format!("{name}.pack.json"))).unwrap()).unwrap()
}

/// Only an unrevoked `scitt-issuer` key of the certificate's own log may sign
/// the Signed Statement — every pack here is genuinely registered under its
/// signer (scripts/gen_scitt_golden.py), so the role alone decides.
#[test]
fn scitt_override_requires_an_unrevoked_scitt_issuer() {
    let expected: J = serde_json::from_str(&fs::read_to_string(golden("scitt/expected.json")).unwrap()).unwrap();
    let roles = &expected["issuer_roles"];
    let core_bytes = fs::read(golden("certificates/issuer_roles.core.cbor")).unwrap();
    let (bundle, id) = (core_json(&core_bytes)["bundle"].clone(), hex(&sha256(&core_bytes)));
    // The TS root is supplied out of band, never copied from the pack.
    let trust = json!({"scitt_ts_keys": {"ts-1": roles["ts_root"]}});
    for (name, want) in roles["families"].as_object().unwrap() {
        let mut vi = json!({"registration": {"scope_registration": {"transparency_service": "ts-1"}, "scitt_pack": read_pack(&format!("issuer_role_{name}"))}});
        apply_scitt_override(&mut vi, &id, &bundle, Some(&trust));
        assert_eq!(&vi["registration"]["scitt_receipt_valid"], want, "issuer role {name}");
        apply_scitt_override(&mut vi, &id, &bundle, None);
        assert_eq!(vi["registration"]["scitt_receipt_valid"], json!(false), "issuer role {name}: no local root");
    }
    // `registered_valid` is signed by its log's genesis key, never a SCITT issuer.
    let core_bytes = fs::read(golden("scitt/registered_valid.core.cbor")).unwrap();
    let core = core_json(&core_bytes);
    let mut vi = core["verdict_input"].clone();
    vi["registration"]["scitt_pack"] = read_pack("registered_valid");
    apply_scitt_override(&mut vi, &hex(&sha256(&core_bytes)), &core["bundle"], Some(&trust));
    assert_eq!(vi["registration"]["scitt_receipt_valid"], json!(false));
}

#[test]
fn hostile_hex_fails_certificate_pack_fields() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/scitt");
    let mut pack: J = serde_json::from_str(&fs::read_to_string(dir.join("registered_valid.pack.json")).unwrap()).unwrap();
    let statement = pack["signed_statement"].as_str().unwrap().to_string();
    assert!(hex_to_bytes(&statement).is_some());
    pack["signed_statement"] = J::String(format!("+{}", &statement[1..]));
    assert!(hex_to_bytes(pack["signed_statement"].as_str().unwrap()).is_none());
    pack["receipt"] = J::String("+f".repeat(32));
    assert!(hex_to_bytes(pack["receipt"].as_str().unwrap()).is_none());
}
