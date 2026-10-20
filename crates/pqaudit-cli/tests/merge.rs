//! Tests of the `merge` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use pqaudit_core::{ResultsFile, ScannerKind};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pqaudit-scan-files/tests/fixtures")
        .join(name)
}

fn pqaudit(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("pqaudit").unwrap();
    cmd.env("PQAUDIT_DATA_DIR", dir.join("data"))
        .arg("--engagement")
        .arg(dir.join("eng"));
    cmd
}

/// Make an engagement and two results files from two scans.
fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "eng", "--dir"])
        .arg(dir.path())
        .assert()
        .code(0);
    let mut outputs = Vec::new();
    for (name, fixture_name) in [("a", "rsa2048-leaf.pem"), ("b", "rsa2048-sha1.pem")] {
        let target = dir.path().join(format!("target-{name}"));
        fs::create_dir(&target).unwrap();
        fs::copy(fixture(fixture_name), target.join("x.pem")).unwrap();
        let output = dir.path().join(format!("{name}.pqr"));
        pqaudit(dir.path())
            .args(["scan", "files", "--output"])
            .arg(&output)
            .arg(&target)
            .assert()
            .code(0);
        outputs.push(output);
    }
    let b = outputs.pop().unwrap();
    let a = outputs.pop().unwrap();
    (dir, a, b)
}

#[test]
fn merge_writes_default_output() {
    let (dir, a, b) = setup();
    pqaudit(dir.path())
        .arg("merge")
        .arg(&a)
        .arg(&b)
        .assert()
        .code(0);
    let path = dir.path().join("eng/results/merged.pqr");
    let merged = ResultsFile::read(&path).unwrap();
    assert_eq!(merged.header.scanner, ScannerKind::Merged);
    assert_eq!(merged.header.runs.len(), 2);
    assert!(!merged.header.redacted);
    let a = ResultsFile::read(&a).unwrap();
    let b = ResultsFile::read(&b).unwrap();
    assert!(merged.findings.len() >= a.findings.len().max(b.findings.len()));
}

#[test]
fn merge_redact_flag_removes_paths() {
    let (dir, a, b) = setup();
    let out = dir.path().join("red.pqr");
    pqaudit(dir.path())
        .arg("merge")
        .arg(&a)
        .arg(&b)
        .arg("--redact")
        .arg("--output")
        .arg(&out)
        .assert()
        .code(0)
        .stdout(predicates::str::contains("fingerprints stay"));
    let key_path = dir.path().join("eng/redact.key");
    assert_eq!(fs::read_to_string(&key_path).unwrap().trim().len(), 64);
    let merged = ResultsFile::read(&out).unwrap();
    assert!(merged.header.redacted);
    let json = serde_json::to_string(&merged).unwrap();
    assert!(!json.contains("target-a") && !json.contains("target-b"));
    assert!(json.contains("redacted:"));
}

#[test]
fn merge_bad_input_exits_1() {
    let (dir, a, _) = setup();
    pqaudit(dir.path())
        .arg("merge")
        .arg(&a)
        .arg(dir.path().join("missing.pqr"))
        .assert()
        .code(1);
    assert!(!dir.path().join("eng/results/merged.pqr").exists());
}

#[test]
fn redact_default_output_and_key_file() {
    let (dir, a, b) = setup();
    pqaudit(dir.path())
        .arg("merge")
        .arg(&a)
        .arg("--redact")
        .assert()
        .code(0);
    let red = dir.path().join("eng/results/merged.redacted.pqr");
    assert!(ResultsFile::read(&red).unwrap().header.redacted);
    // A redacted file and a plain file merge with the same key.
    let out = dir.path().join("mixed.pqr");
    pqaudit(dir.path())
        .arg("merge")
        .arg(&red)
        .arg(&b)
        .arg("--output")
        .arg(&out)
        .assert()
        .code(0);
    // Another folder has no key. A key file that does not exist is an error.
    let other = tempfile::tempdir().unwrap();
    pqaudit(other.path())
        .arg("merge")
        .arg(&red)
        .arg("--redact-key-file")
        .arg(other.path().join("none.key"))
        .assert()
        .code(1);
    // The same key from a file gives the same redacted values.
    let copy = other.path().join("copy.key");
    fs::copy(dir.path().join("eng/redact.key"), &copy).unwrap();
    let out2 = other.path().join("out.pqr");
    pqaudit(other.path())
        .arg("merge")
        .arg(&a)
        .arg("--redact")
        .arg("--redact-key-file")
        .arg(&copy)
        .arg("--output")
        .arg(&out2)
        .assert()
        .code(0);
    let first = ResultsFile::read(&red).unwrap();
    let second = ResultsFile::read(&out2).unwrap();
    assert_eq!(first.header.engagement, second.header.engagement);
    assert_eq!(first, second);
}
