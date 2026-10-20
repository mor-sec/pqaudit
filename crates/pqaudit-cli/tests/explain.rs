//! Tests of the `explain` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use pqaudit_core::ResultsFile;
use predicates::prelude::*;

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

/// Make an engagement with a merged results file. Return the directory and the first finding ID.
fn setup() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "eng", "--dir"])
        .arg(dir.path())
        .assert()
        .code(0);
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), target.join("x.pem")).unwrap();
    let scan = dir.path().join("a.pqr");
    pqaudit(dir.path())
        .args(["scan", "files", "--output"])
        .arg(&scan)
        .arg(&target)
        .assert()
        .code(0);
    pqaudit(dir.path()).arg("merge").arg(&scan).assert().code(0);
    let merged = ResultsFile::read(&dir.path().join("eng/results/merged.pqr")).unwrap();
    let id = merged.findings[0].id.clone();
    assert!(id.starts_with("F-"));
    (dir, id)
}

#[test]
fn explain_shows_factor_breakdown() {
    let (dir, id) = setup();
    let assert = pqaudit(dir.path()).args(["explain", &id]).assert().code(0);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for name in [
        "threat",
        "exposure",
        "sensitivity",
        "mosca",
        "deadline",
        "scale",
        "Total",
        "Complexity",
        "Remediation",
        "unassessed",
        &id,
    ] {
        assert!(out.contains(name), "output has no {name}:\n{out}");
    }
}

#[test]
fn explain_accepts_a_results_flag() {
    let (dir, id) = setup();
    let other = dir.path().join("copy.pqr");
    fs::copy(dir.path().join("eng/results/merged.pqr"), &other).unwrap();
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    pqaudit(dir.path())
        .args(["explain", &id, "--results"])
        .arg(&other)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Total"));
}

#[test]
fn explain_unknown_id_exits_1() {
    let (dir, _) = setup();
    pqaudit(dir.path())
        .args(["explain", "F-00000000"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("F-00000000"));
}

#[test]
fn explain_pack_mismatch_exits_1_with_message() {
    let (dir, id) = setup();
    let path = dir.path().join("eng/results/merged.pqr");
    let mut results = ResultsFile::read(&path).unwrap();
    results.header.rules_pack.content_hash = "0000".into();
    results.write(&path, true).unwrap();
    pqaudit(dir.path())
        .args(["explain", &id])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("rules pack"));
}

#[test]
fn explain_missing_results_exits_1() {
    let (dir, id) = setup();
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    pqaudit(dir.path()).args(["explain", &id]).assert().code(1);
}
