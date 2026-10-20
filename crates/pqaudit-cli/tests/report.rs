//! Tests of the `report` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
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

/// Make an engagement with a merged results file.
fn setup() -> tempfile::TempDir {
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
    dir
}

#[test]
fn report_board_exits_1_later_release() {
    let dir = setup();
    pqaudit(dir.path())
        .args(["report", "--audience", "board"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("later release"));
    let reports = dir.path().join("eng/reports");
    assert!(!reports.exists() || fs::read_dir(reports).unwrap().next().is_none());
}

#[test]
fn report_pdf_exits_1_later_release() {
    let dir = setup();
    pqaudit(dir.path())
        .args(["report", "--audience", "technical", "--format", "pdf"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("later release"));
}

#[test]
fn report_writes_default_path() {
    let dir = setup();
    for (format, ext, marker) in [
        ("html", "html", "<h1>Technical report</h1>"),
        ("md", "md", "# Technical report"),
        ("json", "json", "\"findings\""),
    ] {
        pqaudit(dir.path())
            .args(["report", "--audience", "technical", "--format", format])
            .assert()
            .code(0);
        let path = dir.path().join(format!("eng/reports/technical.{ext}"));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(marker), "{format}: no {marker}");
    }
}

#[test]
fn report_defaults_to_technical_html() {
    let dir = setup();
    pqaudit(dir.path()).arg("report").assert().code(0);
    assert!(dir.path().join("eng/reports/technical.html").is_file());
}

#[test]
fn report_accepts_results_and_output_flags() {
    let dir = setup();
    let other = dir.path().join("copy.pqr");
    fs::copy(dir.path().join("eng/results/merged.pqr"), &other).unwrap();
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    let out = dir.path().join("out.md");
    pqaudit(dir.path())
        .args(["report", "--format", "md", "--results"])
        .arg(&other)
        .arg("--output")
        .arg(&out)
        .assert()
        .code(0);
    assert!(fs::read_to_string(out)
        .unwrap()
        .contains("Technical report"));
}

#[test]
fn report_fails_when_results_are_missing() {
    let dir = setup();
    fs::remove_file(dir.path().join("eng/results/merged.pqr")).unwrap();
    pqaudit(dir.path())
        .arg("report")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot read the results file"));
}
