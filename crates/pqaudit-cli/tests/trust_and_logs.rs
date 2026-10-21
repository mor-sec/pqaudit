//! Tests of the rules pack warnings, the engagement check, and the log flags.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::install_unsigned_pack;

const UNSIGNED: &str = "this pack has no valid signature";
const SKIPPED: &str = "did not use the installed rules pack 99.0.0";
const CLIENT: &str = "Secret Client Name";

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

fn stderr_of(assert: &assert_cmd::assert::Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stderr).into_owned()
}

/// Make an engagement and a target directory with one certificate.
fn engagement() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "eng", "--dir"])
        .arg(dir.path())
        .assert()
        .code(0);
    let config = dir.path().join("eng/engagement.toml");
    let text = fs::read_to_string(&config)
        .unwrap()
        .replace("client = \"\"", &format!("client = \"{CLIENT}\""));
    fs::write(&config, text).unwrap();
    let target = dir.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), target.join("x.pem")).unwrap();
    dir
}

/// Scan the target and merge. Extra flags go before the command.
fn scan_and_merge(dir: &Path, flags: &[&str]) {
    let scan = dir.join("a.pqr");
    pqaudit(dir)
        .args(flags)
        .args(["scan", "files", "--output"])
        .arg(&scan)
        .arg(dir.join("target"))
        .assert()
        .code(0);
    pqaudit(dir)
        .args(flags)
        .arg("merge")
        .arg(&scan)
        .assert()
        .code(0);
}

fn first_finding_id(results: &Path) -> String {
    let file = pqaudit_core::ResultsFile::read(results).unwrap();
    file.findings[0].id.clone()
}

#[test]
fn unsigned_pack_warns_in_every_command() {
    let dir = engagement();
    install_unsigned_pack(&dir.path().join("data"));
    let flag = ["--allow-unsigned-rules"];
    let scan = pqaudit(dir.path())
        .args(flag)
        .args(["scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0);
    assert_eq!(stderr_of(&scan).matches(UNSIGNED).count(), 1);
    scan_and_merge(dir.path(), &flag);

    pqaudit(dir.path())
        .args(flag)
        .arg("report")
        .assert()
        .code(0)
        .stderr(predicate::str::contains(UNSIGNED));
    let html = fs::read_to_string(dir.path().join("eng/reports/technical.html")).unwrap();
    assert!(html.contains("Origin: installed, no valid signature"));
    assert!(html.contains("The rules pack of these results has no valid signature."));

    pqaudit(dir.path())
        .args(flag)
        .arg("cbom")
        .assert()
        .code(0)
        .stderr(predicate::str::contains(UNSIGNED));
    let cbom = fs::read_to_string(dir.path().join("eng/reports/cbom.cdx.json")).unwrap();
    assert!(cbom.contains("\"pqaudit:rules-pack-origin\""));
    assert!(cbom.contains("\"unsigned\""));

    let id = first_finding_id(&dir.path().join("eng/results/merged.pqr"));
    pqaudit(dir.path())
        .args(flag)
        .arg("explain")
        .arg(&id)
        .assert()
        .code(0)
        .stderr(predicate::str::contains(UNSIGNED));
}

#[test]
fn skipped_pack_gives_one_warning_line_in_each_command() {
    let dir = engagement();
    install_unsigned_pack(&dir.path().join("data"));
    let scan = pqaudit(dir.path())
        .args(["scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0);
    assert_eq!(stderr_of(&scan).matches(SKIPPED).count(), 1);
    scan_and_merge(dir.path(), &[]);
    let id = first_finding_id(&dir.path().join("eng/results/merged.pqr"));
    for args in [vec!["report"], vec!["cbom"], vec!["explain", id.as_str()]] {
        let run = pqaudit(dir.path()).args(&args).assert().code(0);
        assert_eq!(stderr_of(&run).matches(SKIPPED).count(), 1, "{args:?}");
    }
}

#[test]
fn engagement_mismatch_stops_report_cbom_and_explain() {
    let dir = engagement();
    scan_and_merge(dir.path(), &[]);
    let merged = dir.path().join("eng/results/merged.pqr");
    let id = first_finding_id(&merged);
    let mut file = pqaudit_core::ResultsFile::read(&merged).unwrap();
    file.header.engagement = String::from("other-client");
    file.write(&merged, false).unwrap();
    for args in [vec!["report"], vec!["cbom"], vec!["explain", id.as_str()]] {
        pqaudit(dir.path())
            .args(&args)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("other-client"))
            .stderr(predicate::str::contains("eng"));
    }
}

#[test]
fn redacted_results_check_the_engagement_with_the_key() {
    let dir = engagement();
    scan_and_merge(dir.path(), &[]);
    pqaudit(dir.path())
        .args(["merge", "--redact"])
        .arg(dir.path().join("eng/results/merged.pqr"))
        .assert()
        .code(0);
    let redacted = dir.path().join("eng/results/merged.redacted.pqr");

    // The key gives the redacted form of the engagement name. The names match.
    pqaudit(dir.path())
        .args(["report", "--results"])
        .arg(&redacted)
        .assert()
        .code(0);
    let html = fs::read_to_string(dir.path().join("eng/reports/technical.html")).unwrap();
    assert!(!html.contains(CLIENT), "the client name is in clear");
    pqaudit(dir.path())
        .args(["cbom", "--results"])
        .arg(&redacted)
        .assert()
        .code(0);
    let cbom = fs::read_to_string(dir.path().join("eng/reports/cbom.cdx.json")).unwrap();
    assert!(!cbom.contains(CLIENT), "the client name is in clear");

    let json_path = dir.path().join("eng/reports/technical.json");
    pqaudit(dir.path())
        .args(["report", "--format", "json", "--results"])
        .arg(&redacted)
        .assert()
        .code(0);
    let json = fs::read_to_string(&json_path).unwrap();
    assert!(!json.contains(CLIENT), "the client name is in the JSON");
    let md_path = dir.path().join("eng/reports/technical.md");
    pqaudit(dir.path())
        .args(["report", "--format", "md", "--results"])
        .arg(&redacted)
        .assert()
        .code(0);
    let md = fs::read_to_string(&md_path).unwrap();
    assert!(!md.contains(CLIENT), "the client name is in the Markdown");

    // A redacted name from a different key does not match.
    let mut file = pqaudit_core::ResultsFile::read(&redacted).unwrap();
    let good = file.header.engagement.clone();
    file.header.engagement = String::from("redacted:000000000000");
    file.write(&redacted, false).unwrap();
    pqaudit(dir.path())
        .args(["report", "--results"])
        .arg(&redacted)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("redacted:000000000000"))
        .stderr(predicate::str::contains("different redaction key"));

    // Without the key, the tool cannot check. It gives a warning and continues.
    file.header.engagement = good;
    file.write(&redacted, false).unwrap();
    fs::remove_file(dir.path().join("eng/redact.key")).unwrap();
    pqaudit(dir.path())
        .args(["report", "--results"])
        .arg(&redacted)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("cannot check the engagement name"));
}

#[test]
fn overrides_apply_to_redacted_results_with_the_key() {
    let dir = engagement();
    scan_and_merge(dir.path(), &[]);
    let plain =
        pqaudit_core::ResultsFile::read(&dir.path().join("eng/results/merged.pqr")).unwrap();
    let fingerprint = plain.findings[0].fingerprint.0.clone();
    fs::write(
        dir.path().join("eng/overrides.toml"),
        format!("[[override]]\nfingerprint = \"{fingerprint}\"\npriority = \"low\"\nreason = \"Accepted risk.\"\nby = \"Jo\"\ndate = 2026-10-01\n"),
    )
    .unwrap();
    pqaudit(dir.path())
        .args(["merge", "--redact"])
        .arg(dir.path().join("eng/results/merged.pqr"))
        .assert()
        .code(0);
    let redacted = dir.path().join("eng/results/merged.redacted.pqr");
    let redacted_file = pqaudit_core::ResultsFile::read(&redacted).unwrap();
    let redacted_text = serde_json::to_string(&redacted_file).unwrap();
    assert!(
        !redacted_text.contains(&fingerprint),
        "the plain fingerprint is in the file"
    );
    let id = redacted_file.findings[0].id.clone();

    // With the key, the plain override matches the keyed fingerprint.
    pqaudit(dir.path())
        .args(["report", "--format", "json", "--results"])
        .arg(&redacted)
        .assert()
        .code(0);
    let json = fs::read_to_string(dir.path().join("eng/reports/technical.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["findings"][0]["override_"]["reason"],
        "Accepted risk."
    );
    assert_eq!(value["orphaned_overrides"].as_array().unwrap().len(), 0);
    assert!(
        !json.contains(&fingerprint),
        "the plain fingerprint is in the report"
    );
    pqaudit(dir.path())
        .args(["explain", id.as_str(), "--results"])
        .arg(&redacted)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Accepted risk."));

    // Without the key, no override matches. The report says why.
    fs::remove_file(dir.path().join("eng/redact.key")).unwrap();
    pqaudit(dir.path())
        .args(["report", "--results"])
        .arg(&redacted)
        .assert()
        .code(0)
        .stderr(predicate::str::contains(
            "No override with a plain fingerprint matches",
        ));
    let html = fs::read_to_string(dir.path().join("eng/reports/technical.html")).unwrap();
    assert!(html.contains(
        "The results file has keyed hashes, but the engagement directory has no file redact.key."
    ));
}

#[test]
fn quiet_stops_the_summary_lines() {
    let dir = engagement();
    for args in [vec!["scan", "files"], vec!["scan", "files", "--output"]] {
        let mut cmd = pqaudit(dir.path());
        cmd.arg("--quiet").args(&args);
        if args.len() == 3 {
            cmd.arg(dir.path().join("a.pqr"));
        }
        cmd.arg(dir.path().join("target"))
            .assert()
            .code(0)
            .stdout(predicate::str::is_empty());
    }
    pqaudit(dir.path())
        .args(["--quiet", "merge"])
        .arg(dir.path().join("a.pqr"))
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty());
    for command in ["report", "cbom"] {
        pqaudit(dir.path())
            .args(["--quiet", command])
            .assert()
            .code(0)
            .stdout(predicate::str::is_empty());
    }
}

#[test]
fn quiet_still_shows_warnings() {
    let dir = engagement();
    install_unsigned_pack(&dir.path().join("data"));
    pqaudit(dir.path())
        .args(["--quiet", "scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(SKIPPED));
}

#[test]
fn verbose_shows_the_pack_origin() {
    let dir = engagement();
    let plain = pqaudit(dir.path())
        .args(["scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0);
    assert!(!stderr_of(&plain).contains("The active rules pack is"));
    pqaudit(dir.path())
        .args(["--verbose", "scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0)
        .stderr(predicate::str::contains("The active rules pack is"));
}

#[test]
fn json_log_format_gives_json_lines_on_stderr() {
    let dir = engagement();
    install_unsigned_pack(&dir.path().join("data"));
    let run = pqaudit(dir.path())
        .args(["--log-format", "json", "--verbose", "scan", "files"])
        .arg(dir.path().join("target"))
        .assert()
        .code(0);
    let text = stderr_of(&run);
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines.len() >= 2, "{text}");
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).expect(line);
        assert!(value["level"].is_string(), "{line}");
    }
    assert!(text.contains(SKIPPED));
    assert!(text.contains("\"WARN\""));
}
