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
fn no_command_is_a_stub() {
    // Without an engagement, each command fails for its own reason.
    let dir = tempfile::tempdir().unwrap();
    let commands: [&[&str]; 6] = [
        &["cbom"],
        &["report"],
        &["explain", "F-00000000"],
        &["merge", "missing.pqr"],
        &["scan", "files", "."],
        &["scan", "net"],
    ];
    for args in commands {
        pqaudit()
            .current_dir(dir.path())
            .args(args)
            .assert()
            .stderr(predicate::str::contains("not implemented").not());
    }
}
