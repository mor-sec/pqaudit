//! Tests of `scan net --dry-run`.

use assert_cmd::Command;
use predicates::prelude::*;

/// Make an engagement directory with the given `scope.toml`.
fn engagement(scope: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("scope.toml"), scope).unwrap();
    dir
}

fn dry_run(dir: &tempfile::TempDir) -> assert_cmd::assert::Assert {
    Command::cargo_bin("pqaudit")
        .unwrap()
        .arg("--engagement")
        .arg(dir.path())
        .args(["scan", "net", "--dry-run"])
        .assert()
}

#[test]
fn dry_run_lists_targets_exit_0() {
    let dir = engagement(
        r#"
        allowed_cidrs = ["127.0.0.0/8", "::1/128"]
        [[target]]
        host = "localhost."
        ports = [443]
        protocol = "tls"
        [[target]]
        host = "127.0.0.1"
        ports = [22]
        protocol = "ssh"
        [[target]]
        host = "::1"
        ports = [22]
        protocol = "ssh"
        "#,
    );
    dry_run(&dir)
        .code(0)
        .stdout(predicate::str::contains("host localhost"))
        .stdout(predicate::str::contains(
            "port 443, protocol tls, connections 2",
        ))
        .stdout(predicate::str::contains(
            "address 127.0.0.1, port 22, protocol ssh, connections 1",
        ));
}

#[test]
fn dry_run_with_refusal_exit_2() {
    // The name localhost resolves to a loopback address. The allowed range is another range.
    let dir = engagement(
        r#"
        allowed_cidrs = ["10.0.0.0/16"]
        [[target]]
        host = "localhost."
        ports = [443]
        protocol = "tls"
        "#,
    );
    dry_run(&dir)
        .code(2)
        .stdout(predicate::str::contains("Refused: localhost"))
        .stdout(predicate::str::contains("not in an allowed CIDR range"));
}

#[test]
fn dry_run_loopback_name_without_ip_target_exit_2() {
    // The allowed range holds the loopback addresses, but no IP target names them.
    let dir = engagement(
        r#"
        allowed_cidrs = ["127.0.0.0/8", "::1/128"]
        [[target]]
        host = "localhost."
        ports = [443]
        protocol = "tls"
        "#,
    );
    dry_run(&dir)
        .code(2)
        .stdout(predicate::str::contains("Refused: localhost"))
        .stdout(predicate::str::contains("loopback"));
}

#[test]
fn dry_run_host_names_without_allowed_ranges_exit_1() {
    let dir =
        engagement("[[target]]\nhost = \"pay.acme.example\"\nports = [443]\nprotocol = \"tls\"\n");
    dry_run(&dir)
        .code(1)
        .stderr(predicate::str::contains("allowed_cidrs"));
}

#[test]
fn dry_run_unknown_key_exit_1_names_line() {
    let dir = engagement("override_limits = false\nbogus = 1\n");
    dry_run(&dir)
        .code(1)
        .stderr(predicate::str::contains("scope.toml"))
        .stderr(predicate::str::contains("line 2"));
}

#[test]
fn dry_run_limit_above_default_exit_2() {
    let dir = engagement("[limits]\nconcurrency = 50\n");
    dry_run(&dir)
        .code(2)
        .stderr(predicate::str::contains("concurrency"));
}

#[test]
fn dry_run_missing_scope_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    dry_run(&dir).code(1);
}

#[test]
fn dry_run_of_the_init_template_has_no_targets() {
    let parent = tempfile::tempdir().unwrap();
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "eng", "--dir"])
        .arg(parent.path())
        .assert()
        .code(0);
    Command::cargo_bin("pqaudit")
        .unwrap()
        .arg("--engagement")
        .arg(parent.path().join("eng"))
        .args(["scan", "net", "--dry-run"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no targets"));
}

#[test]
fn legacy_check_with_too_few_handshakes_exits_1() {
    let dir = engagement(
        "legacy_tls_check = true\n[limits]\ntls_handshakes = 1\n[[target]]\nhost = \"192.0.2.1\"\nports = [443]\nprotocol = \"tls\"\n",
    );
    dry_run(&dir)
        .code(1)
        .stderr(predicates::str::contains("tls_handshakes"));
}
