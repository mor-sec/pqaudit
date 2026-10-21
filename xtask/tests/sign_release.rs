//! Tests for the `sign-release` task of xtask. A fake `cosign` records its arguments.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// Make a release directory with one file and its bundle, and a fake `cosign` that fails.
/// The fake writes each argument on one line to `args.txt`.
fn setup(dir: &Path) {
    let release = dir.join("release");
    fs::create_dir(&release).unwrap();
    fs::write(release.join("pqaudit-v9.9.9-linux"), b"binary").unwrap();
    fs::write(release.join("pqaudit-v9.9.9-linux.sigstore.json"), b"{}").unwrap();
    let bin = dir.join("bin");
    fs::create_dir(&bin).unwrap();
    let fake = bin.join("cosign");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nexit 1\n",
        dir.join("args.txt").display()
    );
    fs::write(&fake, script).unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
}

fn sign_release(dir: &Path, extra: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        dir.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .env("PATH", path)
        .arg("sign-release")
        .arg("--keys")
        .arg(dir.join("keys"))
        .arg("--dir")
        .arg(dir.join("release"))
        .args(["--repo", "mor-sec/pqaudit", "--tag", "v9.9.9"])
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn cosign_gets_the_expected_commit() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let out = sign_release(dir.path(), &["--commit", COMMIT]);
    assert!(!out.status.success(), "the fake cosign fails");
    let args = fs::read_to_string(dir.path().join("args.txt")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    let at = args
        .iter()
        .position(|arg| *arg == "--certificate-github-workflow-sha")
        .expect("cosign must check the commit");
    assert_eq!(args[at + 1], COMMIT);
    let at = args
        .iter()
        .position(|arg| *arg == "--certificate-identity")
        .unwrap();
    assert_eq!(
        args[at + 1],
        "https://github.com/mor-sec/pqaudit/.github/workflows/release.yml@refs/tags/v9.9.9"
    );
}

#[test]
fn the_commit_is_required_and_must_be_a_full_sha() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let out = sign_release(dir.path(), &[]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--commit"));
    for bad in [
        "0123abc",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "main",
    ] {
        let out = sign_release(dir.path(), &["--commit", bad]);
        assert!(!out.status.success(), "{bad}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("40 lower case hex digits"),
            "{bad}: {stderr}"
        );
        assert!(
            !dir.path().join("args.txt").exists(),
            "{bad}: cosign must not run"
        );
    }
}
