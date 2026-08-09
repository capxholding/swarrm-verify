use super::*;
use std::{fs, path::PathBuf};

#[test]
fn scitt_override_resolves_the_named_local_root() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/scitt");
    let core_bytes = fs::read(dir.join("registered_valid.core.cbor")).unwrap();
    let core = cbor_to_json(&decode_cbor(&core_bytes, MAX_DEPTH as usize, MAX_CORE_BYTES).unwrap(), MAX_DEPTH).unwrap();
    let bundle = core["bundle"].clone();
    let mut vi = core["verdict_input"].clone();
    vi["registration"]["scitt_pack"] = serde_json::from_str(&fs::read_to_string(dir.join("registered_valid.pack.json")).unwrap()).unwrap();
    let id = hex(&sha256(&core_bytes));
    // Fixed generator key supplied out of band, not copied from the pack.
    let trust = json!({"scitt_ts_keys": {"ts-1": "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"}});

    apply_scitt_override(&mut vi, &id, &bundle, Some(&trust));
    assert_eq!(vi["registration"]["scitt_receipt_valid"], json!(true));
    apply_scitt_override(&mut vi, &id, &bundle, None);
    assert_eq!(vi["registration"]["scitt_receipt_valid"], json!(false));
}
