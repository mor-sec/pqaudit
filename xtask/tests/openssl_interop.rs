//! Check that OpenSSL accepts the signatures that xtask makes.

use std::fs;
use std::path::Path;
use std::process::Command;

fn xtask(args: &[&str]) {
    let status = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .status()
        .expect("xtask runs");
    assert!(status.success(), "xtask {args:?} failed");
}

/// Return the OpenSSL version as (major, minor), or None when OpenSSL is not there.
fn openssl_version() -> Option<(u32, u32)> {
    let out = Command::new("openssl").arg("version").output().ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let version = text.split_whitespace().nth(1)?;
    let mut parts = version.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn openssl_verify(key: &Path, file: &Path, sig: &Path) -> String {
    let out = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
        .arg(key)
        .arg("-rawin")
        .arg("-in")
        .arg(file)
        .arg("-sigfile")
        .arg(sig)
        .output()
        .expect("openssl runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "openssl failed: {text}");
    text
}

#[test]
fn openssl_verifies_both_signatures() {
    match openssl_version() {
        Some(version) if version >= (3, 5) => {}
        other => {
            eprintln!("NOTE: skipped. The test needs OpenSSL 3.5 or later. Found: {other:?}");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let file = dir.path().join("message.bin");
    fs::write(&file, b"pqaudit interop test\n").unwrap();
    xtask(&["keygen", "--out", keys.to_str().unwrap()]);
    xtask(&[
        "sign",
        "--keys",
        keys.to_str().unwrap(),
        file.to_str().unwrap(),
    ]);

    let ed = openssl_verify(
        &keys.join("ed25519.pub.pem"),
        &file,
        &dir.path().join("message.bin.ed25519.sig"),
    );
    assert!(ed.contains("Signature Verified Successfully"), "{ed}");
    let ml = openssl_verify(
        &keys.join("mldsa65.pub.pem"),
        &file,
        &dir.path().join("message.bin.mldsa65.sig"),
    );
    assert!(ml.contains("Signature Verified Successfully"), "{ml}");
}

#[test]
fn pack_rules_is_deterministic_and_skips_the_trust_list() {
    let out_a = tempfile::tempdir().unwrap();
    let out_b = tempfile::tempdir().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for out in [&out_a, &out_b] {
        xtask(&[
            "pack-rules",
            "--root",
            root.to_str().unwrap(),
            "--out",
            out.path().to_str().unwrap(),
        ]);
    }
    let name = fs::read_dir(out_a.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let a = fs::read(out_a.path().join(&name)).unwrap();
    let b = fs::read(out_b.path().join(&name)).unwrap();
    assert_eq!(a, b);
    let files = pqaudit_rules::archive::read_archive(&a).unwrap();
    assert!(files.iter().any(|(n, _)| n == "pack.toml"));
    assert!(files.iter().all(|(n, _)| !n.starts_with("trust/")));
}
