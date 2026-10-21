//! Tests of the PKCS#12 and Java key store scan.

mod support;

use std::fs;

use pqaudit_core::KeyKind;
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_files::jks::{scan_jks, JksEntry};
use pqaudit_scan_files::pkcs12::{scan_p12, StoreError};
use pqaudit_scan_files::{scan, ScanOptions, ScanOutput};
use support::{
    assert_no_window, fixture, hex, pem_to_der, pseudo_random, write_store, Entry, JCEKS_MAGIC,
    JKS_MAGIC,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD: &str = "pqaudit-test";

fn passwords(list: &[&str]) -> Vec<Zeroizing<String>> {
    list.iter()
        .map(|text| Zeroizing::new(text.to_string()))
        .collect()
}

fn scan_with(paths: &[std::path::PathBuf], list: &[&str]) -> ScanOutput {
    let opts = ScanOptions {
        passwords: passwords(list),
        ..ScanOptions::default()
    };
    scan(paths, &opts, default_pack(), Uuid::new_v4())
}

#[test]
fn p12_with_empty_password_reads_certs() {
    let bytes = fs::read(fixture("store-empty.p12")).unwrap();
    let certs = scan_p12(&bytes, &[]).unwrap().found;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subject, "CN=p12-empty.test");

    let out = scan_with(&[fixture("store-empty.p12")], &[]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].rule_id, "cert.classical-key");
    assert_eq!(out.files_read, 1);
}

#[test]
fn p12_with_supplied_password_reads_certs() {
    let bytes = fs::read(fixture("store-pw.p12")).unwrap();
    // The first password is wrong. The tool tries the next one.
    let certs = scan_p12(&bytes, &passwords(&["wrong", PASSWORD]))
        .unwrap()
        .found;
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].subject, "CN=p12-pw.test");

    let out = scan_with(&[fixture("store-pw.p12")], &["wrong", PASSWORD]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn p12_wrong_password_is_not_inspected_note() {
    let bytes = fs::read(fixture("store-pw.p12")).unwrap();
    assert_eq!(
        scan_p12(&bytes, &passwords(&["wrong"])).unwrap_err(),
        StoreError::Encrypted
    );

    let out = scan_with(&[fixture("store-pw.p12")], &["wrong"]);
    assert!(out.findings.is_empty());
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].reason.contains("ncrypted — not inspected"));
    assert!(out.errors[0].location.ends_with("store-pw.p12"));
    assert_eq!(out.inventory.len(), 1);
    let key = out.inventory[0].key.as_ref().unwrap();
    assert_eq!(key.kind, KeyKind::EncryptedPrivate);
    assert!(key.algorithm.is_none());
}

fn two_entry_store(magic: [u8; 4], key: &[u8]) -> Vec<u8> {
    let trusted = pem_to_der("ecdsa-p256-ca.pem").remove(0);
    let chain = pem_to_der("chain3.pem");
    write_store(
        magic,
        &[
            Entry::Trusted {
                alias: "ca",
                cert: trusted,
            },
            Entry::Key {
                alias: "server",
                encrypted_key: key.to_vec(),
                chain,
            },
        ],
    )
}

#[test]
fn jks_trusted_and_chain_certs_read() {
    let bytes = two_entry_store(JKS_MAGIC, &pseudo_random(1, 300));
    let entries = scan_jks(&bytes).unwrap().found;
    assert_eq!(entries.len(), 2);
    match &entries[0] {
        JksEntry::TrustedCert(cert) => assert_eq!(cert.subject, "CN=ecdsa-ca.test"),
        other => panic!("unexpected entry {other:?}"),
    }
    match &entries[1] {
        JksEntry::PrivateKeyChain(chain) => {
            assert_eq!(chain.len(), 3);
            assert_eq!(chain[0].subject, "CN=chain-leaf.test");
            assert_eq!(chain[2].chain_position, Some(2));
        }
        other => panic!("unexpected entry {other:?}"),
    }

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.jks");
    fs::write(&path, &bytes).unwrap();
    let out = scan_with(&[path], &[]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    // 4 different certificates: the CA, and 3 in the chain.
    assert_eq!(out.findings.len() + out.inventory.len(), 4);
    assert_eq!(out.files_read, 1);
}

#[test]
fn jceks_key_entry_stops_the_read_and_names_the_alias() {
    let bytes = two_entry_store(JCEKS_MAGIC, &pseudo_random(2, 64));
    let scan = scan_jks(&bytes).unwrap();
    // The trusted certificate before the key entry stays.
    assert_eq!(scan.found.len(), 1);
    assert!(matches!(scan.found[0], JksEntry::TrustedCert(_)));
    assert_eq!(scan.errors.len(), 1);
    assert!(scan.errors[0].contains("alias server"), "{:?}", scan.errors);
    assert!(!scan.errors[0].contains("ends too soon"));

    // The tool detects a file with an unknown extension by the magic number.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dat");
    fs::write(&path, &bytes).unwrap();
    let out = scan_with(&[path], &[]);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].reason.contains("JCEKS"));
    assert_eq!(out.findings.len() + out.inventory.len(), 1);
    assert_eq!(out.files_read, 1);

    // The tool detects a PKCS#12 file with an unknown extension by its first bytes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dat");
    fs::copy(fixture("store-empty.p12"), &path).unwrap();
    let out = scan_with(&[path], &[]);
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn corrupt_p12_is_an_error_not_an_encrypted_note() {
    let mut bytes = fs::read(fixture("store-pw.p12")).unwrap();
    // The outer length stays correct. Damage the tag of the content info.
    let header = if bytes[1] & 0x80 == 0 {
        2
    } else {
        2 + usize::from(bytes[1] & 0x7f)
    };
    assert_eq!(bytes[header + 3], 0x30);
    bytes[header + 3] = 0x31;
    assert_eq!(
        scan_p12(&bytes, &passwords(&[PASSWORD])).unwrap_err(),
        StoreError::Invalid
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.p12");
    fs::write(&path, &bytes).unwrap();
    let out = scan_with(&[path], &[PASSWORD]);
    assert_eq!(out.errors.len(), 1);
    assert!(!out.errors[0].reason.contains("ncrypted"));
    assert!(out.inventory.is_empty());
    assert!(out.findings.is_empty());
}

#[test]
fn bad_certificate_does_not_drop_the_store() {
    let good = pem_to_der("rsa2048-leaf.pem").remove(0);
    // Change the last byte of the RSA key OID to make an unknown key type.
    let oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let mut bad = good.clone();
    let at = bad.windows(oid.len()).position(|w| w == oid).unwrap();
    bad[at + oid.len() - 1] = 0x7F;
    let bytes = write_store(
        JKS_MAGIC,
        &[
            Entry::Trusted {
                alias: "bad",
                cert: bad,
            },
            Entry::Trusted {
                alias: "good",
                cert: good,
            },
        ],
    );
    let scan = scan_jks(&bytes).unwrap();
    assert_eq!(scan.found.len(), 1);
    assert_eq!(scan.errors.len(), 1);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.jks");
    fs::write(&path, &bytes).unwrap();
    let out = scan_with(&[path], &[]);
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].reason.contains("public key type"));
}

#[test]
fn truncated_jks_is_error() {
    let bytes = two_entry_store(JKS_MAGIC, &pseudo_random(3, 300));
    for cut in [
        6,
        20,
        100,
        bytes.len() / 2,
        bytes.len() - 21,
        bytes.len() - 1,
    ] {
        assert!(scan_jks(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cut.jks");
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let out = scan_with(&[path], &[]);
    assert_eq!(out.errors.len(), 1);
    assert!(out.findings.is_empty());

    // A huge count or length must not use memory or panic.
    let mut bad = JKS_MAGIC.to_vec();
    bad.extend_from_slice(&[0, 0, 0, 2, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(scan_jks(&bad).is_err());
}

#[test]
fn keystore_private_material_not_in_results() {
    let dir = tempfile::tempdir().unwrap();
    let encrypted_key = pseudo_random(7, 400);
    let jks = dir.path().join("server.jks");
    fs::write(&jks, two_entry_store(JKS_MAGIC, &encrypted_key)).unwrap();
    let p12_key = fs::read(fixture("store-pw.key.der")).unwrap();
    let p12 = fixture("store-pw.p12");
    let locked = dir.path().join("locked.p12");
    fs::copy(&p12, &locked).unwrap();

    let out = scan_with(&[jks, p12, locked], &[PASSWORD]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert!(!out.findings.is_empty());
    let json = serde_json::to_string(&out).unwrap();
    let debug = format!("{out:?}");
    for text in [&json, &debug] {
        assert_no_window(text, &encrypted_key, "jks key");
        assert_no_window(text, &p12_key, "p12 key");
    }
    // Also check the case of an unreadable store.
    let out = scan_with(&[fixture("store-pw.p12")], &[]);
    let json = serde_json::to_string(&out).unwrap();
    assert_no_window(&json, &p12_key, "p12 key, locked");
    assert!(!json.contains(PASSWORD));
}

#[test]
#[should_panic(expected = "hex window found")]
fn leak_check_detects_a_leak() {
    let secret = pseudo_random(9, 64);
    let text = format!("{{\"key\":\"{}\"}}", hex(&secret));
    assert_no_window(&text, &secret, "control");
}

#[test]
fn jks_alias_with_control_characters_is_clean() {
    let bytes = write_store(
        JCEKS_MAGIC,
        &[
            Entry::Trusted {
                alias: "ca",
                cert: pem_to_der("rsa2048-leaf.pem").remove(0),
            },
            Entry::Key {
                alias: "evil\u{1b}[2J\nname",
                encrypted_key: pseudo_random(3, 64),
                chain: vec![],
            },
        ],
    );
    let scan = scan_jks(&bytes).unwrap();
    assert_eq!(scan.errors.len(), 1);
    assert!(
        !scan.errors[0].chars().any(char::is_control),
        "{:?}",
        scan.errors
    );
    assert!(
        scan.errors[0].contains("evil?[2J?name"),
        "{:?}",
        scan.errors
    );
}
