//! Tests of the certificate scan with generated fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use pqaudit_core::{Finding, InventoryItem, Location, ThreatType};
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_files::{scan, ScanOptions, ScanOutput};
use uuid::Uuid;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn scan_paths(paths: &[PathBuf]) -> ScanOutput {
    scan(
        paths,
        &ScanOptions::default(),
        default_pack(),
        Uuid::new_v4(),
    )
}

fn scan_fixture(name: &str) -> ScanOutput {
    scan_paths(&[fixture(name)])
}

fn only_finding(out: &ScanOutput) -> &Finding {
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 1, "findings: {:?}", out.findings);
    &out.findings[0]
}

#[test]
fn rsa2048_leaf_is_classical_short_lived() {
    let out = scan_fixture("rsa2048-leaf.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "cert.classical-key");
    assert_eq!(finding.threat_type, ThreatType::ForgeryShortLived);
    assert!(finding.also.is_empty());
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "RSA");
    assert_eq!(algorithm.key_bits, Some(2048));
    let cert = finding.cert.as_ref().unwrap();
    assert_eq!(cert.subject, "CN=rsa2048.test");
    assert!(!cert.is_ca);
    assert_eq!(cert.sha256.len(), 64);
}

#[test]
fn rsa1024_is_weak_now_with_also_classical() {
    let out = scan_fixture("rsa1024-leaf.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "cert.weak-key");
    assert_eq!(finding.threat_type, ThreatType::ClassicalWeakNow);
    assert_eq!(finding.also, vec!["cert.classical-key".to_string()]);
    assert_eq!(finding.algorithm.as_ref().unwrap().key_bits, Some(1024));
}

#[test]
fn ecdsa_ca_is_long_lived() {
    let out = scan_fixture("ecdsa-p256-ca.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "cert.classical-key");
    assert_eq!(finding.threat_type, ThreatType::ForgeryLongLived);
    let cert = finding.cert.as_ref().unwrap();
    assert!(cert.is_ca);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "ECDSA");
    assert_eq!(algorithm.curve.as_deref(), Some("P-256"));
    assert_eq!(algorithm.key_bits, Some(256));
}

#[test]
fn sha1_sig_is_weak_sig_hash() {
    let out = scan_fixture("rsa2048-sha1.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "cert.weak-sig-hash");
    assert_eq!(finding.threat_type, ThreatType::ClassicalWeakNow);
    assert_eq!(finding.also, vec!["cert.classical-key".to_string()]);
    assert_eq!(
        finding.cert.as_ref().unwrap().signature_algorithm,
        "sha1WithRSAEncryption"
    );
}

#[test]
fn mldsa_cert_is_inventory_pq_ready() {
    let out = scan_fixture("mldsa65.pem");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert!(out.findings.is_empty());
    assert_eq!(out.inventory.len(), 1);
    let item: &InventoryItem = &out.inventory[0];
    assert!(item.pq_ready);
    assert_eq!(item.algorithm.as_ref().unwrap().name, "ML-DSA-65");
    assert_eq!(item.occurrences.len(), 1);
}

#[test]
fn chain_positions_recorded() {
    let out = scan_fixture("chain3.pem");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 3);
    let mut positions: Vec<(u8, String)> = out
        .findings
        .iter()
        .map(|f| {
            let cert = f.cert.as_ref().unwrap();
            (cert.chain_position.unwrap(), cert.subject.clone())
        })
        .collect();
    positions.sort();
    assert_eq!(
        positions,
        vec![
            (0, "CN=chain-leaf.test".to_string()),
            (1, "CN=chain-intermediate.test".to_string()),
            (2, "CN=chain-root.test".to_string()),
        ]
    );
    for finding in &out.findings {
        assert_eq!(finding.occurrences.len(), 1);
    }
}

#[test]
fn der_cert_detected() {
    let out = scan_fixture("rsa2048-leaf.der");
    let finding = only_finding(&out);
    assert_eq!(finding.cert.as_ref().unwrap().subject, "CN=rsa2048.test");
    match &finding.occurrences[0].location {
        Location::File { line, .. } => assert_eq!(*line, None),
        other => panic!("unexpected location {other:?}"),
    }
}

#[test]
fn cert_in_file_with_other_extension_is_found_by_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.txt");
    fs::copy(fixture("rsa2048-leaf.pem"), &path).unwrap();
    fs::write(dir.path().join("plain.txt"), "no certificate here\n").unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    let finding = only_finding(&out);
    assert_eq!(finding.occurrences.len(), 1);
}

#[test]
fn same_cert_two_files_one_finding_two_occurrences() {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), dir.path().join("a.pem")).unwrap();
    fs::copy(fixture("rsa2048-leaf.der"), dir.path().join("b.der")).unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    let finding = only_finding(&out);
    assert_eq!(finding.occurrences.len(), 2);
    let run_ids: Vec<_> = finding.occurrences.iter().map(|o| o.run_id).collect();
    assert_eq!(run_ids[0], run_ids[1]);
}

#[test]
fn finding_has_rule_cwe_from_pack() {
    let pack = default_pack();
    for (name, rule_id) in [
        ("rsa2048-leaf.pem", "cert.classical-key"),
        ("rsa1024-leaf.pem", "cert.weak-key"),
        ("rsa2048-sha1.pem", "cert.weak-sig-hash"),
    ] {
        let out = scan_fixture(name);
        let finding = only_finding(&out);
        assert_eq!(finding.rule_id, rule_id);
        let rule = pack.rule(&finding.rule_id).expect("the pack has the rule");
        assert!(!rule.cwe.is_empty());
    }
}

#[test]
fn private_key_in_bundle_is_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let mut text = fs::read_to_string(fixture("rsa2048-leaf.pem")).unwrap();
    text.push_str("-----BEGIN PRIVATE KEY-----\nSECRETSECRETSECRET\n-----END PRIVATE KEY-----\n");
    fs::write(dir.path().join("bundle.pem"), text).unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    let json = format!("{:?}{:?}{:?}", out.findings, out.inventory, out.errors);
    assert!(!json.contains("SECRETSECRET"));
    assert_eq!(out.findings.len(), 1);
}

#[test]
fn trusted_certificate_block_is_read_as_the_same_certificate() {
    let dir = tempfile::tempdir().unwrap();
    fs::copy(fixture("trusted.pem"), dir.path().join("trusted.pem")).unwrap();
    fs::copy(fixture("rsa2048-leaf.pem"), dir.path().join("plain.pem")).unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    // The trust data does not change the hash. Both files give one finding.
    let finding = only_finding(&out);
    assert_eq!(finding.occurrences.len(), 2);
}

#[test]
fn x509_certificate_block_label_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let text = fs::read_to_string(fixture("rsa2048-leaf.pem"))
        .unwrap()
        .replace("CERTIFICATE", "X509 CERTIFICATE");
    fs::write(dir.path().join("old.pem"), text).unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    only_finding(&out);
}

#[test]
fn pem_without_certificate_is_counted_as_not_read() {
    let out = scan_fixture("other-block.pem");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert!(out.findings.is_empty() && out.inventory.is_empty());
    assert_eq!(out.files_read, 0);
    assert_eq!(out.files_not_read, 1);
}

#[test]
fn rsa_pss_cert_is_classical_key() {
    let out = scan_fixture("rsa-pss.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "cert.classical-key");
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "RSA");
    assert_eq!(algorithm.key_bits, Some(2048));
}

#[test]
fn unknown_key_type_is_an_error_that_names_the_oid() {
    let mut der = fs::read(fixture("rsa2048-leaf.der")).unwrap();
    // Change the key OID 1.2.840.113549.1.1.1 to 1.2.840.113549.1.1.7.
    let oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let at = der.windows(oid.len()).position(|w| w == oid).unwrap();
    der[at + oid.len() - 1] = 0x07;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("odd.der"), der).unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    assert!(out.findings.is_empty() && out.inventory.is_empty());
    assert_eq!(out.errors.len(), 1);
    assert!(
        out.errors[0].reason.contains("1.2.840.113549.1.1.7"),
        "{}",
        out.errors[0].reason
    );
}

#[test]
fn debug_output_of_options_hides_passwords() {
    let options = ScanOptions {
        passwords: vec![zeroize::Zeroizing::new("hunter2-secret".to_string())],
        ..ScanOptions::default()
    };
    let text = format!("{options:?}");
    assert!(!text.contains("hunter2"), "{text}");
}
