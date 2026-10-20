//! Basic tests of the pqaudit binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn pqaudit() -> Command {
    Command::cargo_bin("pqaudit").expect("the pqaudit binary exists")
}

#[test]
fn version_prints_name() {
    pqaudit()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("pqaudit "));
}

#[test]
fn help_lists_stage1_commands() {
    let assert = pqaudit().arg("--help").assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    for name in [
        "init", "scan", "merge", "report", "cbom", "explain", "rules", "profiles",
    ] {
        assert!(out.contains(name), "help does not list {name}");
    }
}

#[test]
fn unknown_command_exits_1() {
    pqaudit().arg("frobnicate").assert().code(1);
}

#[test]
fn stub_command_exits_1_with_message() {
    pqaudit()
        .arg("cbom")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not implemented"));
}

#[test]
fn scan_subcommands_are_stubs() {
    for sub in ["files", "net"] {
        pqaudit().args(["scan", sub]).assert().code(1);
    }
}
