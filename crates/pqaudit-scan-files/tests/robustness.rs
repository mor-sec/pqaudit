//! Tests with bad files. Each bad file must give a scan error and no panic.

use std::fs;
use std::path::Path;

use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_files::{scan, ScanOptions};
use uuid::Uuid;

fn good_cert() -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rsa2048-leaf.pem")).unwrap()
}

#[test]
fn malformed_inputs_are_errors_not_panics() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // A truncated DER file.
    let der =
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rsa2048-leaf.der"))
            .unwrap();
    fs::write(root.join("truncated.der"), &der[..der.len() / 2]).unwrap();

    // Random bytes with the name x.pem. A simple generator makes the bytes.
    let mut state: u64 = 0x1234_5678_9abc_def1;
    let random: Vec<u8> = (0..4096)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect();
    fs::write(root.join("x.pem"), random).unwrap();

    // A PEM file with 10 000 bad blocks.
    let block = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    fs::write(root.join("many.pem"), block.repeat(10_000)).unwrap();

    // A sparse 2 GB file.
    let big = fs::File::create(root.join("big.pem")).unwrap();
    big.set_len(2 * 1024 * 1024 * 1024).unwrap();
    drop(big);

    // One good file shows that the scan continues.
    fs::write(root.join("good.pem"), good_cert()).unwrap();

    let out = scan(
        &[root.to_path_buf()],
        &ScanOptions::default(),
        default_pack(),
        Uuid::new_v4(),
    );

    assert_eq!(out.findings.len(), 1);
    for name in ["truncated.der", "x.pem", "many.pem", "big.pem"] {
        let errors: Vec<_> = out
            .errors
            .iter()
            .filter(|e| e.location.ends_with(name))
            .collect();
        assert_eq!(errors.len(), 1, "{name}: {:?}", out.errors);
        assert!(!errors[0].reason.is_empty());
    }
    let big_error = out
        .errors
        .iter()
        .find(|e| e.location.ends_with("big.pem"))
        .unwrap();
    assert!(
        big_error.reason.contains("too large"),
        "{}",
        big_error.reason
    );
    assert_eq!(out.errors.len(), 4);
}

#[test]
fn missing_path_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = scan(
        &[dir.path().join("does-not-exist")],
        &ScanOptions::default(),
        default_pack(),
        Uuid::new_v4(),
    );
    assert_eq!(out.errors.len(), 1);
    assert_eq!(out.files_read, 0);
}

#[cfg(unix)]
#[test]
fn skipped_symlinks_are_counted_and_noted() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("real.pem");
    fs::write(&cert, good_cert()).unwrap();
    std::os::unix::fs::symlink(&cert, dir.path().join("link.pem")).unwrap();
    let scan_with = |follow| {
        scan(
            &[dir.path().to_path_buf()],
            &ScanOptions {
                follow_symlinks: follow,
                ..ScanOptions::default()
            },
            default_pack(),
            Uuid::new_v4(),
        )
    };
    let out = scan_with(false);
    assert_eq!(out.skipped_symlinks, 1);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].reason.contains("symbolic link"));
    assert_eq!(out.findings.len(), 1);
    let out = scan_with(true);
    assert_eq!(out.skipped_symlinks, 0);
    assert!(out.errors.is_empty());
    assert_eq!(out.findings[0].occurrences.len(), 2);
}

#[test]
fn local_host_name_is_not_empty() {
    let name = pqaudit_scan_files::local_host_name();
    assert!(!name.is_empty());
    assert_eq!(name, name.trim());
}
