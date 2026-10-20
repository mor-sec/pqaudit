//! Tests of the `profiles` command.

use assert_cmd::Command;
use predicates::prelude::*;

fn pqaudit() -> Command {
    Command::cargo_bin("pqaudit").expect("the pqaudit binary exists")
}

#[test]
fn profiles_list_shows_three() {
    let assert = pqaudit().args(["profiles", "list"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert_eq!(out.lines().count(), 3, "{out}");
    for id in ["us", "uk", "au"] {
        assert!(out.lines().any(|l| l.starts_with(id)), "no line for {id}");
    }
    let uk = out.lines().find(|l| l.starts_with("uk")).unwrap();
    assert!(uk.trim_end().ends_with('3'), "{uk}");
}

#[test]
fn profiles_show_uk() {
    pqaudit()
        .args(["profiles", "show", "uk"])
        .assert()
        .success()
        .stdout(predicate::str::contains("2028-12-31"))
        .stdout(predicate::str::contains("2031-12-31"))
        .stdout(predicate::str::contains("2035-12-31"))
        .stdout(predicate::str::contains("planning"))
        .stdout(predicate::str::contains("migration"))
        .stdout(predicate::str::contains(
            "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines",
        ))
        .stdout(predicate::str::contains(
            "Timelines for migration to post-quantum cryptography",
        ))
        .stdout(predicate::str::contains("as of 2026-10-20"));
}

#[test]
fn profiles_show_unknown_exits_1() {
    pqaudit()
        .args(["profiles", "show", "xx"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("xx"));
}
