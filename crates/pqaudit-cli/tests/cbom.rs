//! Tests of the `cbom` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use predicates::prelude::*;
use serde_json::Value;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../pqaudit-scan-files/tests/fixtures")
}

fn pqaudit(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("pqaudit").unwrap();
    cmd.env("PQAUDIT_DATA_DIR", dir.join("data"))
        .arg("--engagement")
        .arg(dir.join("eng"));
    cmd
}

/// Make an engagement. Scan the files of `target`, then merge the result.
fn setup(target: &Path) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "eng", "--dir"])
        .arg(dir.path())
        .assert()
        .code(0);
    let scan = dir.path().join("a.pqr");
    pqaudit(dir.path())
        .args(["scan", "files", "--output"])
        .arg(&scan)
        .arg(target)
        .assert()
        .success();
    pqaudit(dir.path()).arg("merge").arg(&scan).assert().code(0);
    dir
}

fn read(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn cbom_writes_the_default_path() {
    let target = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("rsa2048-leaf.pem"),
        target.path().join("x.pem"),
    )
    .unwrap();
    fs::copy(fixtures().join("mldsa65.pem"), target.path().join("pq.pem")).unwrap();
    let dir = setup(target.path());
    pqaudit(dir.path())
        .arg("cbom")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("cbom.cdx.json"));
    let bom = read(&dir.path().join("eng/reports/cbom.cdx.json"));
    assert_eq!(bom["bomFormat"], "CycloneDX");
    let algorithms: Vec<&str> = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["cryptoProperties"]["assetType"] == "algorithm")
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(algorithms.contains(&"RSA"), "{algorithms:?}");
}

#[test]
fn cbom_accepts_results_and_output_flags() {
    let target = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("rsa2048-leaf.pem"),
        target.path().join("x.pem"),
    )
    .unwrap();
    let dir = setup(target.path());
    let copy = dir.path().join("copy.pqr");
    fs::copy(dir.path().join("eng/results/merged.pqr"), &copy).unwrap();
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    let out = dir.path().join("sub/out.json");
    pqaudit(dir.path())
        .args(["cbom", "--results"])
        .arg(&copy)
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    assert_eq!(read(&out)["specVersion"], "1.6");
}

#[test]
fn cbom_fails_when_results_are_missing() {
    let target = tempfile::tempdir().unwrap();
    fs::copy(
        fixtures().join("rsa2048-leaf.pem"),
        target.path().join("x.pem"),
    )
    .unwrap();
    let dir = setup(target.path());
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    pqaudit(dir.path())
        .arg("cbom")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot read the results file"));
}

/// Decode the first PEM block of a file.
fn decode_block(path: &Path) -> Vec<u8> {
    let text = fs::read_to_string(path).unwrap();
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
        } else if line.starts_with("-----END") {
            break;
        } else if inside && !line.contains(':') {
            body.push_str(line.trim());
        }
    }
    STANDARD.decode(body).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn no_key_bytes_in_cbom() {
    let names = [
        "pkcs8-rsa.pem",
        "pkcs8-rsa1024.pem",
        "pkcs8-ec.pem",
        "pkcs8-ed25519.pem",
        "pkcs8-x25519.pem",
        "pkcs8-rsa-enc.pem",
        "pkcs8-mldsa65.pem",
        "pkcs8-mlkem768.pem",
        "pkcs1-rsa.pem",
        "sec1-ec.pem",
        "id_rsa",
        "id_ecdsa",
        "id_ed25519",
        "id_ed25519_enc",
    ];
    let target = tempfile::tempdir().unwrap();
    let mut secrets = Vec::new();
    for name in names {
        let source = fixtures().join("keys").join(name);
        fs::copy(&source, target.path().join(name)).unwrap();
        secrets.push((name, decode_block(&source)));
    }
    let dir = setup(target.path());
    pqaudit(dir.path()).arg("cbom").assert().code(0);
    let text = fs::read_to_string(dir.path().join("eng/reports/cbom.cdx.json")).unwrap();
    // The CBOM must show the keys, or the test proves nothing.
    assert!(text.contains("related-crypto-material"));
    for (name, secret) in &secrets {
        assert!(secret.len() > 32, "{name}");
        for window in secret.windows(16) {
            assert!(!text.contains(&hex(window)), "{name}: hex window");
        }
        // A window has at least 21 full base64 characters in one of 3 alignments.
        for shift in 0..3 {
            let encoded = STANDARD.encode(&secret[shift..]);
            for window in encoded.as_bytes().windows(21) {
                let window = std::str::from_utf8(window).unwrap();
                assert!(!text.contains(window), "{name}: base64 window");
            }
        }
    }
}
