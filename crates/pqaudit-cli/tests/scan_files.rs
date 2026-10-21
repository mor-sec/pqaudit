//! Tests of the `scan files` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use pqaudit_core::{PackOriginRef, ResultsFile, ScannerKind};
use predicates::prelude::*;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../pqaudit-scan-files/tests/fixtures")
        .join(name)
}

/// A scratch directory with an engagement directory and a directory to scan.
struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    fn new() -> Self {
        let setup = Setup {
            dir: tempfile::tempdir().unwrap(),
        };
        Command::cargo_bin("pqaudit")
            .unwrap()
            .args(["init", "eng", "--dir"])
            .arg(setup.dir.path())
            .assert()
            .code(0);
        fs::create_dir(setup.target()).unwrap();
        setup
    }

    fn engagement(&self) -> PathBuf {
        self.dir.path().join("eng")
    }

    fn target(&self) -> PathBuf {
        self.dir.path().join("target")
    }

    fn pqaudit(&self) -> Command {
        let mut cmd = Command::cargo_bin("pqaudit").unwrap();
        cmd.env("PQAUDIT_DATA_DIR", self.dir.path().join("data"))
            .arg("--engagement")
            .arg(self.engagement());
        cmd
    }

    fn results(&self) -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = fs::read_dir(self.engagement().join("results"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        found.sort();
        found
    }
}

#[test]
fn good_scan_writes_default_results_file_and_exits_0() {
    let setup = Setup::new();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join("a.pem")).unwrap();
    setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(0);
    let results = setup.results();
    assert_eq!(results.len(), 1);
    let name = results[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        name.starts_with("files-") && name.ends_with(".pqr"),
        "{name}"
    );
    // The name has the form files-yyyymmddThhmmss.pqr.
    assert_eq!(name.len(), "files-20261020T120000.pqr".len());
    let file = ResultsFile::read(&results[0]).unwrap();
    assert_eq!(file.header.scanner, ScannerKind::Files);
    assert_eq!(file.header.rules_pack.origin, PackOriginRef::Embedded);
    assert_eq!(file.findings.len(), 1);
    assert!(file.errors.is_empty());
}

#[test]
fn output_flag_sets_the_results_path() {
    let setup = Setup::new();
    fs::copy(fixture("mldsa65.pem"), setup.target().join("a.pem")).unwrap();
    let output = setup.dir.path().join("out.pqr");
    setup
        .pqaudit()
        .args(["scan", "files", "--output"])
        .arg(&output)
        .arg(setup.target())
        .assert()
        .code(0);
    let file = ResultsFile::read(&output).unwrap();
    assert!(file.findings.is_empty());
    assert_eq!(file.inventory.len(), 1);
    assert!(file.inventory[0].pq_ready);
}

#[test]
fn no_readable_file_exits_1() {
    let setup = Setup::new();
    setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.dir.path().join("missing"))
        .assert()
        .code(1);
}

#[test]
fn empty_directory_exits_1() {
    let setup = Setup::new();
    setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(1);
}

#[cfg(unix)]
#[test]
fn only_symlinks_exits_1_and_shows_the_hint() {
    let setup = Setup::new();
    let real = setup.dir.path().join("real.pem");
    fs::copy(fixture("rsa2048-leaf.pem"), &real).unwrap();
    std::os::unix::fs::symlink(&real, setup.target().join("link.pem")).unwrap();
    setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(1)
        .stdout(predicate::str::contains("--follow-symlinks"));
}

#[test]
fn too_large_file_gives_partial_exit_3() {
    let setup = Setup::new();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join("a.pem")).unwrap();
    fs::write(setup.target().join("b.pem"), vec![b'x'; 5000]).unwrap();
    setup
        .pqaudit()
        .args(["scan", "files", "--max-file-size", "2000"])
        .arg(setup.target())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("too large"));
}

#[test]
fn password_value_is_never_written() {
    let setup = Setup::new();
    let path = setup.engagement().join("engagement.toml");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("\n[passwords]\nenv = \"PQAUDIT_TEST_PW\"\n");
    fs::write(&path, text).unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join("a.pem")).unwrap();
    let assert = setup
        .pqaudit()
        .env("PQAUDIT_TEST_PW", "hunter2-secret")
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(0);
    let output = assert.get_output();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("hunter2-secret"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("hunter2-secret"));
    let raw = fs::read(&setup.results()[0]).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("hunter2-secret"));
    // A missing variable is an error that does not show a value.
    setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("PQAUDIT_TEST_PW"));
}

#[cfg(unix)]
#[test]
fn unreadable_paths_give_partial_exit_3() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};

    let setup = Setup::new();
    let target = setup.target();

    // One good certificate.
    fs::copy(fixture("rsa2048-leaf.pem"), target.join("good.pem")).unwrap();

    // A file that the tool cannot read.
    let locked = target.join("locked.pem");
    fs::copy(fixture("rsa2048-leaf.pem"), &locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        // The user can read the file anyway, for example the user is root.
        return;
    }

    // A loop of symbolic links. The scan follows links, so it finds the loop.
    let sub = target.join("sub");
    fs::create_dir(&sub).unwrap();
    symlink("..", sub.join("up")).unwrap();

    // A file name that is not valid UTF-8.
    let odd = target.join(OsStr::from_bytes(b"odd-\xff.pem"));
    fs::copy(fixture("rsa2048-leaf.pem"), odd).unwrap();

    let assert = setup
        .pqaudit()
        .args(["scan", "files", "--follow-symlinks"])
        .arg(&target)
        .assert()
        .code(3);
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).into_owned();
    assert!(stderr.contains("locked.pem"), "{stderr}");
    assert!(stderr.contains("odd-"), "{stderr}");

    let file = ResultsFile::read(&setup.results()[0]).unwrap();
    assert_eq!(file.findings.len(), 1);
    assert_eq!(file.errors.len(), 3, "{:?}", file.errors);
    assert!(file
        .errors
        .iter()
        .any(|e| e.location.ends_with("locked.pem")));
    assert!(file.errors.iter().any(|e| e.location.contains("odd-")));
    assert!(file.errors.iter().any(|e| e.location.contains("up")));

    // Make the file readable, so that the cleanup can delete it.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn host_name_comes_from_the_operating_system() {
    let setup = Setup::new();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join("a.pem")).unwrap();
    let output = setup.dir.path().join("a.pqr");
    setup
        .pqaudit()
        .env("HOSTNAME", "env-name-marker")
        .env("COMPUTERNAME", "env-name-marker")
        .args(["scan", "files", "--output"])
        .arg(&output)
        .arg(setup.target())
        .assert()
        .code(0);
    let file = ResultsFile::read(&output).unwrap();
    let host = &file.header.host;
    assert!(!host.is_empty());
    assert_eq!(host, host.trim());
    assert_ne!(host, "env-name-marker", "the variable must not win");
    assert_eq!(&file.header.runs[0].host, host);
}

#[test]
fn finding_ids_come_from_the_fingerprint() {
    let setup = Setup::new();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join("a.pem")).unwrap();
    fs::copy(fixture("rsa1024-leaf.pem"), setup.target().join("b.pem")).unwrap();
    let output = setup.dir.path().join("a.pqr");
    setup
        .pqaudit()
        .args(["scan", "files", "--output"])
        .arg(&output)
        .arg(setup.target())
        .assert()
        .code(0);
    let file = ResultsFile::read(&output).unwrap();
    assert_eq!(file.findings.len(), 2);
    for finding in &file.findings {
        let id = &finding.id;
        assert!(id.starts_with("F-") && id.len() == 10, "{id}");
        assert_eq!(
            id,
            &pqaudit_core::fingerprint::finding_id(&finding.fingerprint)
        );
    }
}

/// True if the text has a control character other than a line end or a tab.
fn has_control(text: &str) -> bool {
    text.chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r')
}

#[cfg(unix)]
#[test]
fn control_characters_in_file_names_do_not_reach_the_terminal() {
    let setup = Setup::new();
    let bad = "bad\u{1b}[31m\u{7}.pem";
    let good = "good\u{1b}]0;title\u{7}.pem";
    fs::write(setup.target().join(bad), "not a certificate").unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), setup.target().join(good)).unwrap();
    let assert = setup
        .pqaudit()
        .args(["scan", "files"])
        .arg(setup.target())
        .assert()
        .code(3);
    let out = assert.get_output();
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stderr.contains("bad?[31m?.pem"), "{stderr}");
    assert!(!has_control(&stderr), "{stderr:?}");
    assert!(!has_control(&stdout), "{stdout:?}");

    // explain shows the location of the finding.
    let results = setup.results();
    let file = ResultsFile::read(&results[0]).unwrap();
    let id = file.findings[0].id.clone();
    let merged = setup
        .pqaudit()
        .arg("merge")
        .arg(&results[0])
        .assert()
        .code(0);
    assert!(!has_control(&String::from_utf8_lossy(
        &merged.get_output().stdout
    )));
    let explained = setup
        .pqaudit()
        .args(["explain", id.as_str()])
        .assert()
        .code(0);
    let stdout = String::from_utf8_lossy(&explained.get_output().stdout);
    assert!(stdout.contains("good?]0;title?.pem"), "{stdout}");
    assert!(!has_control(&stdout), "{stdout:?}");
}
