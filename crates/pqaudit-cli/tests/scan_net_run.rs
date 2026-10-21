//! Tests of `scan net` without `--dry-run`. These tests open sockets on 127.0.0.1 only.

use std::fmt::Write as _;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use assert_cmd::Command;
use chrono::{Local, Timelike};
use pqaudit_core::{ResultsFile, ScannerKind};
use predicates::prelude::*;
use sha2::{Digest, Sha256};

mod common;
use common::classical_tls_server;

/// A scratch directory with an engagement directory.
struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    fn new(scope: &str) -> Self {
        let setup = Setup {
            dir: tempfile::tempdir().unwrap(),
        };
        Command::cargo_bin("pqaudit")
            .unwrap()
            .args(["init", "eng", "--dir"])
            .arg(setup.dir.path())
            .assert()
            .code(0);
        fs::write(setup.engagement().join("scope.toml"), scope).unwrap();
        setup
    }

    fn engagement(&self) -> PathBuf {
        self.dir.path().join("eng")
    }

    fn audit_log(&self) -> PathBuf {
        self.engagement().join("audit.log")
    }

    fn scan(&self) -> assert_cmd::assert::Assert {
        self.scan_with(&[])
    }

    fn scan_with(&self, extra: &[&str]) -> assert_cmd::assert::Assert {
        Command::cargo_bin("pqaudit")
            .unwrap()
            .env("PQAUDIT_DATA_DIR", self.dir.path().join("data"))
            .arg("--engagement")
            .arg(self.engagement())
            .args(["scan", "net"])
            .args(extra)
            .assert()
    }

    fn results(&self) -> Vec<PathBuf> {
        match fs::read_dir(self.engagement().join("results")) {
            Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn audit_lines(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.audit_log())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|line| line["outcome"] != "started")
            .collect()
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hex = String::new();
    for byte in Sha256::digest(data) {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

/// A port on 127.0.0.1 where nobody listens.
fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn scope_for(port: u16, extra: &str) -> String {
    format!(
        "allowed_cidrs = [\"127.0.0.0/8\"]\n{extra}\n[[target]]\nhost = \"127.0.0.1\"\nports = [{port}]\nprotocol = \"tls\"\n"
    )
}

/// A listener that no one should connect to. The listener is not blocking.
fn watched_listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn assert_no_connection(listener: &TcpListener) {
    thread::sleep(Duration::from_millis(100));
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("the tool made a connection: {other:?}"),
    }
}

#[test]
fn refused_plan_exits_2_before_any_connection() {
    let (listener, port) = watched_listener();
    // The name localhost resolves to a loopback address. The allowed range is another range.
    let setup = Setup::new(&format!(
        "allowed_cidrs = [\"10.0.0.0/16\"]\n[[target]]\nhost = \"localhost\"\nports = [{port}]\nprotocol = \"tls\"\n"
    ));
    setup
        .scan()
        .code(2)
        .stdout(predicate::str::contains("Refused: localhost"));
    assert_no_connection(&listener);
    assert!(!setup.audit_log().exists());
    assert!(setup.results().is_empty());
}

#[test]
fn outside_allowed_hours_exits_2_before_any_connection() {
    let (listener, port) = watched_listener();
    // A window of one hour that starts 2 hours from now. It never holds the current time.
    let minutes = Local::now().time().hour() * 60 + Local::now().time().minute();
    let start = (minutes + 120) % (24 * 60);
    let end = (minutes + 180) % (24 * 60);
    let window = format!(
        "{:02}:{:02}-{:02}:{:02}",
        start / 60,
        start % 60,
        end / 60,
        end % 60
    );
    let setup = Setup::new(&scope_for(port, &format!("allowed_hours = \"{window}\"")));
    setup
        .scan()
        .code(2)
        .stderr(predicate::str::contains("allowed_hours"));
    assert_no_connection(&listener);
    assert!(!setup.audit_log().exists());
    assert!(setup.results().is_empty());
}

#[test]
fn failed_connection_is_audited_and_exit_3() {
    let port = closed_port();
    let scope = scope_for(port, "");
    let setup = Setup::new(&scope);
    let output = setup.engagement().join("custom.pqr");
    setup
        .scan_with(&["--output", output.to_str().unwrap()])
        .code(3)
        .stderr(predicate::str::contains("Scan error at"));
    let lines = setup.audit_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["port"], port);
    assert_eq!(lines[0]["dst_ip"], "127.0.0.1");
    assert!(lines[0]["outcome"]
        .as_str()
        .unwrap()
        .starts_with("connect-failed"));
    assert!(lines[0]["run_id"].is_string());

    let results = ResultsFile::read(&output).unwrap();
    assert_eq!(results.header.scanner, ScannerKind::Net);
    assert_eq!(results.errors.len(), 1);
    assert_eq!(
        results.header.scope_hash.as_deref(),
        Some(sha256_hex(scope.as_bytes()).as_str())
    );
    let log = fs::read(setup.audit_log()).unwrap();
    assert_eq!(
        results.header.audit_log_hash.as_deref(),
        Some(sha256_hex(&log).as_str())
    );
    assert_eq!(results.header.runs.len(), 1);
    assert_eq!(results.header.runs[0].scope_hash, results.header.scope_hash);
    assert_eq!(
        results.header.runs[0].audit_log_hash,
        results.header.audit_log_hash
    );
    assert!(setup.results().is_empty(), "the output flag sets the path");
}

#[test]
fn silent_server_gives_timeout_error_exit_3() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    let setup = Setup::new(&scope_for(port, "[limits]\nread_timeout_ms = 1000\n"));
    let started = std::time::Instant::now();
    setup.scan().code(3);
    assert!(started.elapsed() < Duration::from_secs(5));
    let lines = setup.audit_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["outcome"], "timeout");
}

#[test]
fn full_scan_writes_findings_audit_log_and_results() {
    let address = classical_tls_server();
    let scope = scope_for(address.port(), "[limits]\nmin_interval_ms = 1000\n");
    let setup = Setup::new(&scope);
    setup
        .scan()
        .code(0)
        .stdout(predicate::str::contains("Wrote the audit log to:"));
    let files = setup.results();
    assert_eq!(files.len(), 1);
    let results = ResultsFile::read(&files[0]).unwrap();
    assert!(results.errors.is_empty(), "{:?}", results.errors);
    assert!(results
        .findings
        .iter()
        .any(|finding| finding.rule_id == "tls.no-pq-kex"));
    assert!(results
        .findings
        .iter()
        .any(|finding| finding.rule_id == "cert.classical-key"));
    for finding in &results.findings {
        assert_eq!(
            finding.id,
            pqaudit_core::fingerprint::finding_id(&finding.fingerprint),
            "the ID comes from the fingerprint"
        );
    }
    // Two connections for a TLS port: hybrid and classical.
    let lines = setup.audit_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["probe"], "tls-hybrid");
    assert_eq!(lines[1]["probe"], "tls-classical");
    let log = fs::read(setup.audit_log()).unwrap();
    assert_eq!(
        results.header.audit_log_hash.as_deref(),
        Some(sha256_hex(&log).as_str())
    );
    // A second run adds lines to the same log. It does not replace it.
    setup.scan().code(0);
    assert_eq!(setup.audit_lines().len(), 4);
}

#[cfg(unix)]
#[test]
fn ctrl_c_keeps_finished_results_and_audits_open_connections() {
    use std::process::{Command as Std, Stdio};
    use std::sync::mpsc;
    // A fast target and a held target, both on 127.0.0.1 with different ports.
    // The scope sets per_host to 2, so the held connection does not block the fast target.
    let fast = classical_tls_server();
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let held_port = held.local_addr().unwrap().port();
    let (ready_tx, ready_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        while let Ok((stream, _)) = held.accept() {
            kept.push(stream);
            let _ = ready_tx.send(());
        }
    });
    let scope = format!(
        "allowed_cidrs = [\"127.0.0.0/8\"]\n\
         override_limits = true\n\
         [limits]\nper_host = 2\n\
         [[target]]\nhost = \"127.0.0.1\"\nports = [{}]\nprotocol = \"tls\"\n\
         [[target]]\nhost = \"127.0.0.1\"\nports = [{held_port}]\nprotocol = \"tls\"\n",
        fast.port()
    );
    let setup = Setup::new(&scope);
    let mut child = Std::new(assert_cmd::cargo::cargo_bin("pqaudit"))
        .env("PQAUDIT_DATA_DIR", setup.dir.path().join("data"))
        .arg("--engagement")
        .arg(setup.engagement())
        .args(["scan", "net"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The held server accepted a connection, so the scan runs and the handler is in place.
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // Wait until the fast target finishes: its classical handshake has a final audit line.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !setup
        .audit_log()
        .exists_and(|text| text.contains("tls-classical") && text.contains("\"ok\""))
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the fast target did not finish"
        );
        thread::sleep(Duration::from_millis(50));
    }
    // Give the scan time to store the result of the finished target.
    thread::sleep(Duration::from_millis(300));
    Std::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(3));

    let lines = setup.audit_lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line["outcome"] == "aborted")
            .count(),
        1
    );
    let files = setup.results();
    assert_eq!(files.len(), 1);
    let results = ResultsFile::read(&files[0]).unwrap();
    // The finished target keeps its finding.
    assert!(results
        .findings
        .iter()
        .any(|finding| finding.rule_id == "tls.no-pq-kex"));
    // The held target gives one error with its own address.
    assert_eq!(results.errors.len(), 1, "{:?}", results.errors);
    assert!(results.errors[0]
        .location
        .contains(&format!("127.0.0.1:{held_port}")));
    let log = fs::read(setup.audit_log()).unwrap();
    assert_eq!(
        results.header.audit_log_hash.as_deref(),
        Some(sha256_hex(&log).as_str())
    );
}

/// A helper for the wait loop: read a file and test its text.
trait ExistsAnd {
    fn exists_and(&self, test: impl Fn(&str) -> bool) -> bool;
}

impl ExistsAnd for PathBuf {
    fn exists_and(&self, test: impl Fn(&str) -> bool) -> bool {
        fs::read_to_string(self).is_ok_and(|text| test(&text))
    }
}

#[test]
fn unsigned_pack_warns_in_scan_net() {
    let setup = Setup::new(&scope_for(closed_port(), ""));
    common::install_unsigned_pack(&setup.dir.path().join("data"));
    setup
        .scan_with(&["--allow-unsigned-rules"])
        .code(3)
        .stderr(predicate::str::contains("this pack has no valid signature"));
    setup.scan().code(3).stderr(predicate::str::contains(
        "did not use the installed rules pack 99.0.0",
    ));
}
