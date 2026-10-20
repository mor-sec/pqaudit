//! Tests of the SSH key, PEM key, and OpenPGP key scan.

mod support;

use std::fs;
use std::path::PathBuf;

use pqaudit_core::{
    Algorithm, Finding, Fingerprint, InventoryItem, InventoryKind, KeyInfo, KeyKind, Location,
    ThreatType,
};
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_files::{scan, ScanOptions, ScanOutput};
use sha2::{Digest, Sha256};
use support::{
    assert_no_window, decode_block, fixture, hex, key_fixture, pem_to_der, pseudo_random,
    secret_key_packets, write_store, Entry, JCEKS_MAGIC, JKS_MAGIC,
};
use uuid::Uuid;

fn scan_paths(paths: &[PathBuf]) -> ScanOutput {
    scan(
        paths,
        &ScanOptions::default(),
        default_pack(),
        Uuid::new_v4(),
    )
}

fn scan_key(name: &str) -> ScanOutput {
    scan_paths(&[key_fixture(name)])
}

/// Return the key facts and the algorithm of each finding and inventory item.
fn all_keys(out: &ScanOutput) -> Vec<(&KeyInfo, Option<&Algorithm>)> {
    let findings = out
        .findings
        .iter()
        .filter_map(|f| f.key.as_ref().map(|key| (key, f.algorithm.as_ref())));
    let inventory = out
        .inventory
        .iter()
        .filter_map(|i| i.key.as_ref().map(|key| (key, i.algorithm.as_ref())));
    findings.chain(inventory).collect()
}

fn only_finding(out: &ScanOutput) -> &Finding {
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 1, "findings: {:?}", out.findings);
    assert!(out.inventory.is_empty(), "inventory: {:?}", out.inventory);
    &out.findings[0]
}

fn only_inventory(out: &ScanOutput) -> &InventoryItem {
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert!(out.findings.is_empty(), "findings: {:?}", out.findings);
    assert_eq!(out.inventory.len(), 1, "inventory: {:?}", out.inventory);
    &out.inventory[0]
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// The SHA-256 hash of the SSH public blob in a `.pub` file.
fn blob_hash(name: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let text = fs::read_to_string(key_fixture(name)).unwrap();
    let blob = text.split_whitespace().nth(1).unwrap();
    sha256_hex(&STANDARD.decode(blob).unwrap())
}

fn lines_of(item_occurrences: &[pqaudit_core::Occurrence]) -> Vec<Option<u32>> {
    item_occurrences
        .iter()
        .map(|o| match &o.location {
            Location::File { line, .. } => *line,
            other => panic!("unexpected location {other:?}"),
        })
        .collect()
}

#[test]
fn ssh_rsa_ecdsa_ed25519_public_keys() {
    let cases = [
        (
            "id_rsa.pub",
            "RSA",
            Some(2048),
            None,
            "key.classical",
            ThreatType::ForgeryShortLived,
        ),
        (
            "id_ecdsa.pub",
            "ECDSA",
            Some(256),
            Some("P-256"),
            "key.classical",
            ThreatType::ForgeryShortLived,
        ),
        (
            "id_ed25519.pub",
            "Ed25519",
            Some(256),
            None,
            "key.classical",
            ThreatType::ForgeryShortLived,
        ),
        (
            "id_rsa1024.pub",
            "RSA",
            Some(1024),
            None,
            "key.weak",
            ThreatType::ClassicalWeakNow,
        ),
    ];
    for (name, algorithm, bits, curve, rule, threat) in cases {
        let out = scan_key(name);
        let finding = only_finding(&out);
        assert_eq!(finding.rule_id, rule, "{name}");
        assert_eq!(finding.threat_type, threat, "{name}");
        let found = finding.algorithm.as_ref().unwrap();
        assert_eq!(found.name, algorithm, "{name}");
        assert_eq!(found.key_bits, bits, "{name}");
        assert_eq!(found.curve.as_deref(), curve, "{name}");
        let key = finding.key.as_ref().unwrap();
        assert_eq!(key.kind, KeyKind::OpenSsh);
        assert_eq!(key.fingerprint_sha256, blob_hash(name), "{name}");
        assert_eq!(finding.fingerprint, Fingerprint::key(&blob_hash(name)));
        assert_eq!(
            key.comment.as_deref(),
            Some(format!("ssh-{}@ssh.example.test", &name[3..name.len() - 4]).as_str())
        );
        assert_eq!(out.files_read, 1);
        assert_eq!(out.files_not_read, 0);
    }
}

#[test]
fn authorized_keys_each_line_a_key() {
    let out = scan_key("authorized_keys");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    // The file has 4 key lines. The RSA key is on 2 of them.
    assert_eq!(out.findings.len(), 3);
    let occurrences: usize = out.findings.iter().map(|f| f.occurrences.len()).sum();
    assert_eq!(occurrences, 4);
    let rsa = out
        .findings
        .iter()
        .find(|f| f.algorithm.as_ref().unwrap().name == "RSA")
        .unwrap();
    assert_eq!(lines_of(&rsa.occurrences), vec![Some(2), Some(5)]);
    // The line with options still gives the ECDSA key.
    assert!(out
        .findings
        .iter()
        .any(|f| f.algorithm.as_ref().unwrap().name == "ECDSA"));
    assert_eq!(out.files_read, 1);
}

#[test]
fn known_hosts_hashed_entries_supported() {
    let out = scan_key("known_hosts");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    // 2 plain lines and 2 hashed lines. The Ed25519 key is on a plain and a hashed line.
    assert_eq!(out.findings.len(), 3);
    let ed = out
        .findings
        .iter()
        .find(|f| f.algorithm.as_ref().unwrap().name == "Ed25519")
        .unwrap();
    assert_eq!(ed.occurrences.len(), 2);
    // The results do not hold host names.
    let json = serde_json::to_string(&out).unwrap();
    assert!(!json.contains("pqaudit.test,"), "{json}");
    assert!(!json.contains("plain.pqaudit"), "{json}");
    assert!(!json.contains("192.0.2.10"), "{json}");
}

#[test]
fn encrypted_openssh_private_key_public_part_only() {
    let out = scan_key("id_ed25519_enc");
    let finding = only_finding(&out);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "Ed25519");
    let key = finding.key.as_ref().unwrap();
    assert_eq!(key.kind, KeyKind::OpenSsh);
    assert_eq!(key.fingerprint_sha256, blob_hash("id_ed25519_enc.pub"));
    assert!(finding.occurrences[0].evidence.contains("encrypted"));
    assert_eq!(out.files_read, 1);

    // The key file and the public file give one finding.
    let out = scan_paths(&[
        key_fixture("id_ed25519_enc"),
        key_fixture("id_ed25519_enc.pub"),
    ]);
    assert_eq!(only_finding(&out).occurrences.len(), 2);
}

#[test]
fn same_key_in_authorized_keys_and_pub_file_one_finding() {
    let out = scan_paths(&[
        key_fixture("authorized_keys"),
        key_fixture("id_rsa.pub"),
        key_fixture("id_rsa"),
    ]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    let rsa: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.algorithm.as_ref().unwrap().name == "RSA")
        .collect();
    assert_eq!(rsa.len(), 1);
    // Two lines in authorized_keys, the .pub file, and the private key file.
    assert_eq!(rsa[0].occurrences.len(), 4);
    assert_eq!(out.findings.len(), 3);
}

#[test]
fn pkcs8_rsa_bits_read() {
    let out = scan_key("pkcs8-rsa.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "key.classical");
    assert_eq!(finding.threat_type, ThreatType::ForgeryShortLived);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(
        (algorithm.name.as_str(), algorithm.key_bits),
        ("RSA", Some(2048))
    );
    let key = finding.key.as_ref().unwrap();
    assert_eq!(key.kind, KeyKind::Pkcs8Private);
    assert_eq!(out.files_read, 1);
    assert_eq!(out.files_not_read, 0);

    // The fingerprint is the hash of the SPKI. The public key file gives the same one.
    let spki = decode_block(&key_fixture("spki-rsa.pem"));
    assert_eq!(key.fingerprint_sha256, sha256_hex(&spki));
    let out = scan_paths(&[key_fixture("pkcs8-rsa.pem"), key_fixture("spki-rsa.pem")]);
    assert_eq!(only_finding(&out).occurrences.len(), 2);

    let out = scan_key("pkcs8-rsa1024.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.rule_id, "key.weak");
    assert_eq!(finding.threat_type, ThreatType::ClassicalWeakNow);
    assert_eq!(finding.algorithm.as_ref().unwrap().key_bits, Some(1024));
}

#[test]
fn pkcs8_ec_and_ed25519_keys_read() {
    let out = scan_key("pkcs8-ec.pem");
    let finding = only_finding(&out);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "ECDSA");
    assert_eq!(algorithm.curve.as_deref(), Some("P-256"));
    assert_eq!(algorithm.key_bits, Some(256));

    let out = scan_key("pkcs8-ed25519.pem");
    let finding = only_finding(&out);
    assert_eq!(finding.algorithm.as_ref().unwrap().name, "Ed25519");
    assert_eq!(finding.key.as_ref().unwrap().kind, KeyKind::Pkcs8Private);

    let out = scan_key("sec1-ec.pem");
    let finding = only_finding(&out);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "ECDSA");
    assert_eq!(algorithm.curve.as_deref(), Some("P-256"));
}

#[test]
fn pkcs1_rsa_detected() {
    let out = scan_key("pkcs1-rsa.pem");
    let finding = only_finding(&out);
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(
        (algorithm.name.as_str(), algorithm.key_bits),
        ("RSA", Some(2048))
    );
    assert_eq!(finding.key.as_ref().unwrap().kind, KeyKind::Pkcs8Private);
    assert_eq!(out.files_read, 1);
    assert_eq!(out.files_not_read, 0);
}

#[test]
fn encrypted_pkcs8_not_inspected() {
    let out = scan_key("pkcs8-rsa-enc.pem");
    let item = only_inventory(&out);
    assert_eq!(item.kind, InventoryKind::Key);
    assert!(!item.pq_ready);
    assert!(item.algorithm.is_none());
    let key = item.key.as_ref().unwrap();
    assert_eq!(key.kind, KeyKind::EncryptedPrivate);
    assert!(key.algorithm.is_none());
    assert!(item.occurrences[0].evidence.contains("ncrypted"));
    assert_eq!(out.files_read, 1);
    assert_eq!(out.files_not_read, 0);
}

#[test]
fn post_quantum_keys_and_certificates_are_inventory() {
    for (name, kind) in [
        ("spki-mlkem768.pem", InventoryKind::Key),
        ("pkcs8-mlkem768.pem", InventoryKind::Key),
        ("cert-mlkem768.pem", InventoryKind::Certificate),
    ] {
        let out = scan_key(name);
        let item = only_inventory(&out);
        assert_eq!(item.kind, kind, "{name}");
        assert!(item.pq_ready, "{name}");
        assert_eq!(
            item.algorithm.as_ref().unwrap().name,
            "ML-KEM-768",
            "{name}"
        );
    }
}

#[test]
fn gpg_rsa3072_and_ed25519() {
    let out = scan_key("gpg-rsa3072.pub.gpg");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    // A primary key and an encryption subkey.
    assert_eq!(out.findings.len(), 2);
    for finding in &out.findings {
        assert_eq!(finding.rule_id, "key.classical");
        let algorithm = finding.algorithm.as_ref().unwrap();
        assert_eq!(
            (algorithm.name.as_str(), algorithm.key_bits),
            ("RSA", Some(3072))
        );
        let key = finding.key.as_ref().unwrap();
        assert_eq!(key.kind, KeyKind::Pgp);
        assert_eq!(key.fingerprint_sha256.len(), 64);
    }
    let comments: Vec<_> = out
        .findings
        .iter()
        .filter_map(|f| f.key.as_ref().unwrap().comment.as_deref())
        .collect();
    assert_eq!(comments, ["Test RSA <rsa@pqaudit.test>"]);

    // The armored export. The primary key signs. The subkey only agrees on a key.
    let out = scan_key("gpg-ed25519.pub.asc");
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.findings.len(), 2);
    let ed = out
        .findings
        .iter()
        .find(|f| f.algorithm.as_ref().unwrap().name == "Ed25519")
        .unwrap();
    assert_eq!(ed.threat_type, ThreatType::ForgeryShortLived);
    let x = out
        .findings
        .iter()
        .find(|f| f.algorithm.as_ref().unwrap().name == "X25519")
        .unwrap();
    assert_eq!(x.threat_type, ThreatType::Hndl);

    // The fingerprints are the version 4 fingerprints that GnuPG shows.
    let both = scan_paths(&[
        key_fixture("gpg-rsa3072.pub.gpg"),
        key_fixture("gpg-ed25519.pub.asc"),
    ]);
    let expected = fs::read_to_string(key_fixture("gpg-fingerprints.txt")).unwrap();
    let expected: Vec<_> = expected.lines().map(Fingerprint::key).collect();
    assert_eq!(expected.len(), 4);
    for fingerprint in &expected {
        assert!(
            both.findings.iter().any(|f| &f.fingerprint == fingerprint),
            "missing {fingerprint:?}"
        );
    }
}

#[test]
fn kbx_is_unsupported_error() {
    for name in ["pubring.kbx", "ring.dat"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::copy(key_fixture("pubring.kbx"), &path).unwrap();
        let out = scan_paths(&[path]);
        assert_eq!(out.errors.len(), 1, "{name}: {:?}", out.errors);
        assert!(out.errors[0].reason.contains("nsupported format"));
        assert!(out.findings.is_empty() && out.inventory.is_empty());
    }
}

#[test]
fn key_files_without_known_names_are_found_by_content() {
    let dir = tempfile::tempdir().unwrap();
    for (from, to) in [
        ("id_rsa", "key.txt"),
        ("id_ed25519", "plain"),
        ("pkcs8-ec.pem", "ec-key"),
        ("id_ecdsa.pub", "ssh-public"),
        ("gpg-ed25519.pub.asc", "armor"),
        ("gpg-rsa3072.pub.gpg", "ring"),
        ("authorized_keys", "keys.list"),
    ] {
        fs::copy(key_fixture(from), dir.path().join(to)).unwrap();
    }
    // A text file with no key stays unread.
    fs::write(dir.path().join("notes.txt"), "ssh-rsa is a key type\n").unwrap();
    let out = scan_paths(&[dir.path().to_path_buf()]);
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(out.files_not_read, 0);
    assert_eq!(out.files_read, 8);
    let names: Vec<_> = all_keys(&out)
        .iter()
        .filter_map(|(_, a)| a.map(|a| a.name.clone()))
        .collect();
    for name in ["RSA", "ECDSA", "Ed25519", "X25519"] {
        assert!(names.iter().any(|n| n == name), "{name} missing: {names:?}");
    }
}

#[test]
fn malformed_key_files_are_errors_not_panics() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let rsa = fs::read_to_string(key_fixture("pkcs8-rsa.pem")).unwrap();
    // A PEM key with half of its text.
    let lines: Vec<_> = rsa.lines().collect();
    let half = format!(
        "{}\n{}\n-----END PRIVATE KEY-----\n",
        lines[0],
        lines[1..lines.len() / 2].join("\n")
    );
    fs::write(root.join("half.pem"), half).unwrap();
    // A key block with bad base64 text.
    fs::write(
        root.join("bad64.pem"),
        "-----BEGIN PRIVATE KEY-----\nSECRETSECRETSECRET\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    // Random bytes inside a key block.
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let random = STANDARD.encode(pseudo_random(5, 300));
    fs::write(
        root.join("random.pem"),
        format!("-----BEGIN RSA PRIVATE KEY-----\n{random}\n-----END RSA PRIVATE KEY-----\n"),
    )
    .unwrap();
    // A key block with no end line.
    fs::write(root.join("open.pem"), "-----BEGIN PRIVATE KEY-----\nAAAA\n").unwrap();
    // 10 000 bad key blocks.
    let block = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    fs::write(root.join("many.pem"), block.repeat(10_000)).unwrap();
    // SSH files with bad lines.
    fs::write(
        root.join("authorized_keys"),
        "ssh-rsa AAAAB3NzaC1yc2E\nssh-ed25519 !!!!\nnot a key at all\n",
    )
    .unwrap();
    fs::write(root.join("known_hosts"), vec![0xff_u8; 3000]).unwrap();
    // OpenSSH private key files that end too soon.
    let ssh = fs::read(key_fixture("id_ed25519")).unwrap();
    fs::write(root.join("id_cut"), &ssh[..ssh.len() / 3]).unwrap();
    // OpenPGP data that ends too soon.
    let gpg = fs::read(key_fixture("gpg-rsa3072.pub.gpg")).unwrap();
    fs::write(root.join("cut.gpg"), &gpg[..gpg.len() / 2]).unwrap();
    fs::write(root.join("junk.gpg"), vec![0x99_u8; 50]).unwrap();

    let out = scan_paths(&[root.to_path_buf()]);
    for name in [
        "half.pem",
        "bad64.pem",
        "random.pem",
        "open.pem",
        "many.pem",
        "authorized_keys",
        "known_hosts",
        "cut.gpg",
        "junk.gpg",
    ] {
        let errors: Vec<_> = out
            .errors
            .iter()
            .filter(|e| e.location.ends_with(name))
            .collect();
        assert_eq!(errors.len(), 1, "{name}: {:?}", out.errors);
        assert!(!errors[0].reason.is_empty());
        assert!(!errors[0].reason.contains("SECRETSECRET"));
    }
    // A cut OpenPGP file keeps the keys before the cut.
    assert!(out
        .findings
        .iter()
        .all(|f| f.key.as_ref().unwrap().kind == KeyKind::Pgp));
}

/// The private part of each private key fixture. The tool must not show any of it.
fn private_parts() -> Vec<(&'static str, Vec<u8>)> {
    let mut parts = Vec::new();
    for name in [
        "pkcs8-rsa.pem",
        "pkcs8-rsa1024.pem",
        "pkcs8-ec.pem",
        "pkcs8-ed25519.pem",
        "pkcs8-rsa-enc.pem",
        "pkcs8-mlkem768.pem",
        "pkcs1-rsa.pem",
        "sec1-ec.pem",
        "id_rsa",
        "id_rsa1024",
        "id_ecdsa",
        "id_ed25519",
        "id_ed25519_enc",
    ] {
        parts.push((name, decode_block(&key_fixture(name))));
    }
    let binary = fs::read(key_fixture("gpg-rsa3072.sec.gpg")).unwrap();
    parts.push(("gpg-rsa3072.sec.gpg", secret_key_packets(&binary)));
    // The armor export. The user ID is public and the tool shows it, so use the secret packets.
    let armored = decode_block(&key_fixture("gpg-ed25519.sec.asc"));
    parts.push(("gpg-ed25519.sec.asc", secret_key_packets(&armored)));
    parts
}

#[test]
fn private_key_material_never_in_results() {
    let parts = private_parts();
    let dir = tempfile::tempdir().unwrap();
    for (name, secret) in &parts {
        assert!(secret.len() > 32, "{name}");
        let out = scan_key(name);
        assert_eq!(out.files_read, 1, "{name}");
        assert!(out.errors.is_empty(), "{name}: {:?}", out.errors);
        assert!(!all_keys(&out).is_empty(), "{name}");
        let json = serde_json::to_string(&out).unwrap();
        let debug = format!("{out:?}");
        let reasons: String = out.errors.iter().map(|e| e.reason.as_str()).collect();
        for text in [&json, &debug, &reasons] {
            assert_no_window(text, secret, name);
        }
        // Damage the key in 3 ways. The errors must not show key bytes.
        let raw = fs::read(key_fixture(name)).unwrap();
        for (variant, bytes) in [
            ("cut", raw[..raw.len() * 2 / 3].to_vec()),
            ("flip", raw.iter().map(|b| b ^ 0x01).collect()),
            ("tail", raw[raw.len() / 2..].to_vec()),
        ] {
            let path = dir.path().join(format!("{variant}-{name}"));
            fs::write(&path, bytes).unwrap();
            let out = scan_paths(&[path]);
            let json = serde_json::to_string(&out).unwrap();
            assert_no_window(&json, secret, &format!("{name} {variant}"));
        }
    }
    // One scan of all files together.
    let out = scan_paths(&[
        key_fixture("pkcs8-rsa.pem"),
        key_fixture("id_rsa"),
        key_fixture("gpg-rsa3072.sec.gpg"),
    ]);
    let json = serde_json::to_string(&out).unwrap();
    for (name, secret) in &parts {
        assert_no_window(&json, secret, name);
    }
}

#[test]
fn key_blocks_with_bad_content_show_no_bytes() {
    // A key block with bad content next to the bytes of a real key.
    let secret = decode_block(&key_fixture("pkcs8-rsa.pem"));
    let mut broken = secret.clone();
    // Change the algorithm OID so the tool does not know the key type.
    let at = broken
        .windows(9)
        .position(|w| w == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
        .unwrap();
    broken[at + 8] = 0x7F;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("odd.pem");
    fs::write(
        &path,
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            STANDARD.encode(&broken)
        ),
    )
    .unwrap();
    let out = scan_paths(&[path]);
    assert_eq!(out.errors.len(), 1);
    assert!(out.errors[0].reason.contains("1.2.840.113549.1.1.127"));
    let json = serde_json::to_string(&out).unwrap();
    assert_no_window(&json, &secret, "unknown algorithm");
}

#[test]
fn keystore_error_paths_pass_the_same_window_check() {
    let dir = tempfile::tempdir().unwrap();

    // A JCEKS store that stops at a key entry. The "key" bytes follow the Java object marker.
    let key = pseudo_random(21, 400);
    let jceks = write_store(
        JCEKS_MAGIC,
        &[
            Entry::Trusted {
                alias: "ca",
                cert: pem_to_der("ecdsa-p256-ca.pem").remove(0),
            },
            Entry::Key {
                alias: "server",
                encrypted_key: key.clone(),
                chain: pem_to_der("chain3.pem"),
            },
        ],
    );
    let jceks_path = dir.path().join("keys.jceks");
    fs::write(&jceks_path, &jceks).unwrap();
    let out = scan_paths(&[jceks_path]);
    assert_eq!(out.errors.len(), 1, "errors: {:?}", out.errors);
    assert_no_window(
        &serde_json::to_string(&out).unwrap(),
        &key,
        "jceks key entry",
    );
    assert_no_window(&format!("{out:?}"), &key, "jceks key entry");

    // A JKS store with a key entry and a damaged end.
    let jks = write_store(
        JKS_MAGIC,
        &[Entry::Key {
            alias: "server",
            encrypted_key: key.clone(),
            chain: pem_to_der("chain3.pem"),
        }],
    );
    let cut_path = dir.path().join("cut.jks");
    fs::write(&cut_path, &jks[..jks.len() - 30]).unwrap();
    let out = scan_paths(&[cut_path]);
    assert!(!out.errors.is_empty());
    assert_no_window(&serde_json::to_string(&out).unwrap(), &key, "cut jks");

    // A corrupt PKCS#12 file. The whole file counts as secret.
    let mut p12 = fs::read(fixture("store-pw.p12")).unwrap();
    let header = if p12[1] & 0x80 == 0 {
        2
    } else {
        2 + usize::from(p12[1] & 0x7f)
    };
    p12[header + 3] = 0x31;
    let p12_path = dir.path().join("bad.p12");
    fs::write(&p12_path, &p12).unwrap();
    let options = ScanOptions {
        passwords: vec![zeroize::Zeroizing::new("pqaudit-test".to_string())],
        ..ScanOptions::default()
    };
    let out = scan(&[p12_path], &options, default_pack(), Uuid::new_v4());
    assert_eq!(out.errors.len(), 1, "errors: {:?}", out.errors);
    let key_der = fs::read(fixture("store-pw.key.der")).unwrap();
    for secret in [&p12, &key_der] {
        assert_no_window(&serde_json::to_string(&out).unwrap(), secret, "corrupt p12");
        assert_no_window(&format!("{out:?}"), secret, "corrupt p12");
    }

    // A bad certificate in a store. The unknown key type error must not show certificate bytes.
    let mut bad = pem_to_der("rsa2048-leaf.pem").remove(0);
    let oid = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let at = bad.windows(oid.len()).position(|w| w == oid).unwrap();
    bad[at + oid.len() - 1] = 0x7F;
    let store = write_store(
        JKS_MAGIC,
        &[Entry::Trusted {
            alias: "bad",
            cert: bad.clone(),
        }],
    );
    let bad_path = dir.path().join("bad-cert.jks");
    fs::write(&bad_path, &store).unwrap();
    let out = scan_paths(&[bad_path]);
    assert_eq!(out.errors.len(), 1, "errors: {:?}", out.errors);
    assert_no_window(
        &serde_json::to_string(&out).unwrap(),
        &bad,
        "bad certificate",
    );
    assert_no_window(&format!("{out:?}"), &bad, "bad certificate");
}

#[test]
#[should_panic(expected = "raw window found")]
fn leak_check_detects_a_raw_leak() {
    let secret = b"this-is-a-private-key-text".to_vec();
    assert_no_window("{\"x\":\"this-is-a-private-key-text\"}", &secret, "control");
}
