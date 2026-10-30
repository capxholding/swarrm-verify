// Apache-2.0 (public verifier repo)
//! The Rust verifier runs the SAME shared golden fixtures as the Python
//! verifier (tests/golden/) and must agree with expected.json. Two
//! independent implementations agreeing is the spec-hardening guarantee.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

#[test]
fn golden_suite_agrees_with_expected() {
    let dir = golden_dir();
    let expected: Value = serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let bundle: Value = serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap()).unwrap();
        // Both parent and child consume the same public report without repeating verification.
        let facts = swarrm_verify::verify_bundle(&bundle, None);
        let verified = facts["ok"].as_bool().expect("bundle report verdict");
        let got = if verified { "VERIFIED" } else { "NOT_VERIFIED" };
        assert_eq!(got, want.as_str().unwrap(), "fixture {name}: Rust got {got}, expected {}", want);
        if std::env::var_os("SWARRM_GOLDEN_REPORT").is_some() {
            println!("GOLDEN_REPORT {}", serde_json::json!({"name": name, "facts": facts}));
        }
        checked += 1;
    }
    assert!(checked >= 6, "expected at least 6 golden fixtures, ran {checked}");
}

#[test]
fn golden_results_are_environment_independent() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!("golden failure streams retained at {}", self.0.display());
            } else {
                fs::remove_dir_all(&self.0).expect("remove owned golden scratch");
            }
        }
    }
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = std::env::temp_dir().join(format!("swarrm-rust-golden-{}-{nonce}", std::process::id()));
    fs::create_dir(&scratch).unwrap();
    let scratch = Scratch(scratch);
    let expected: Value = serde_json::from_slice(&fs::read(golden_dir().join("expected.json")).unwrap()).unwrap();
    let mut baseline = None;
    for (index, zone) in ["UTC0", "EST5EDT", "JST-9"].iter().enumerate() {
        let cwd = scratch.0.join(format!("foreign {index} é"));
        fs::create_dir(&cwd).unwrap();
        let stdout = cwd.join("stdout");
        let stderr = cwd.join("stderr");
        let mut child = Command::new(std::env::current_exe().unwrap()).args(["--exact", "golden_suite_agrees_with_expected", "--nocapture"]).env_clear().env("TZ", zone).env("LANG", "C").env("LC_ALL", "C").env("SWARRM_GOLDEN_REPORT", "1").current_dir(&cwd).stdin(Stdio::null()).stdout(fs::File::create(&stdout).unwrap()).stderr(fs::File::create(&stderr).unwrap()).spawn().unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > Duration::from_secs(60) || fs::metadata(&stdout).unwrap().len() >= 8 * 1024 * 1024 || fs::metadata(&stderr).unwrap().len() >= 8 * 1024 * 1024 {
                child.kill().unwrap();
                let status = child.wait().unwrap();
                panic!("golden environment child exceeded deadline or output bound; original status={status}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "golden environment {zone}: {status}");
        assert_eq!(fs::metadata(&stderr).unwrap().len(), 0);
        assert!(fs::metadata(&stdout).unwrap().len() < 8 * 1024 * 1024);
        let output = fs::read_to_string(&stdout).unwrap();
        let mut records = std::collections::BTreeMap::new();
        for line in output.lines().filter_map(|line| line.strip_prefix("GOLDEN_REPORT ")) {
            let record: Value = serde_json::from_str(line).unwrap();
            let name = record["name"].as_str().unwrap().to_string();
            assert!(records.insert(name, record["facts"].clone()).is_none(), "duplicate golden result");
        }
        assert_eq!(records.keys().collect::<Vec<_>>(), expected.as_object().unwrap().keys().collect::<Vec<_>>());
        let bytes = serde_json::to_vec(&records).unwrap();
        if let Some(ref baseline) = baseline {
            assert_eq!(&bytes, baseline, "environment drift: {zone}");
        } else {
            baseline = Some(bytes);
        }
    }
}
