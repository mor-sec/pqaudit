//! Tests for merge and redaction of results files.

use chrono::{TimeZone, Utc};
use pqaudit_core::merge::{merge, redact, MergeError};
use pqaudit_core::*;
use std::net::IpAddr;
use uuid::Uuid;

fn time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 20, 8, 0, 0).unwrap()
}

fn alg() -> Algorithm {
    Algorithm {
        name: "RSA".into(),
        key_bits: Some(2048),
        curve: None,
    }
}

fn cert(sha: &str) -> CertInfo {
    CertInfo {
        sha256: sha.repeat(32),
        subject: "CN=pay.example.org,O=Secret Corp".into(),
        issuer: "CN=Internal Issuing CA".into(),
        not_before: time(),
        not_after: time(),
        is_ca: false,
        key_usage: vec![],
        ext_key_usage: vec![],
        public_key: alg(),
        signature_algorithm: "sha256WithRSAEncryption".into(),
        chain_position: Some(0),
    }
}

fn file_occurrence(path: &str, run: u128) -> Occurrence {
    Occurrence {
        location: Location::File {
            path: path.into(),
            line: Some(1),
        },
        evidence: format!("PEM block in {path}"),
        run_id: Uuid::from_u128(run),
    }
}

fn net_occurrence(host: &str, run: u128) -> Occurrence {
    Occurrence {
        location: Location::Endpoint {
            host: host.into(),
            ip: "192.0.2.77".parse::<IpAddr>().unwrap(),
            port: 443,
            protocol: Protocol::Tls,
        },
        evidence: format!("handshake with {host}"),
        run_id: Uuid::from_u128(run),
    }
}

fn finding(id: &str, fp: Fingerprint, rule: &str, occ: Vec<Occurrence>) -> Finding {
    Finding {
        id: id.into(),
        fingerprint: fp,
        rule_id: rule.into(),
        source: Source::File,
        algorithm: Some(alg()),
        purpose: Purpose::Signature,
        threat_type: ThreatType::ForgeryLongLived,
        agility: Agility::Unknown,
        fix_owner: FixOwner::Unknown,
        also: vec![],
        occurrences: occ,
        cert: None,
        key: None,
        endpoint: None,
    }
}

fn header(scanner: ScannerKind, run: u128, version: &str) -> ResultsHeader {
    ResultsHeader {
        schema_version: SCHEMA_VERSION,
        engagement: "acme".into(),
        tool_version: "0.1.0".into(),
        rules_pack: PackRef {
            id: "default".into(),
            version: version.into(),
            content_hash: "ab".repeat(32),
            origin: PackOriginRef::Embedded,
        },
        scanner,
        host: "scanner-host".into(),
        operator: "alice".into(),
        started: time(),
        finished: time(),
        scope_hash: None,
        audit_log_hash: None,
        runs: vec![RunInfo {
            run_id: Uuid::from_u128(run),
            scanner,
            host: "scanner-host".into(),
            started: time(),
        }],
        redacted: false,
    }
}

fn files_result() -> ResultsFile {
    let c = cert("aa");
    let fp = Fingerprint::cert(&c.sha256);
    let mut f = finding(
        "file-1",
        fp.clone(),
        "cert.rsa-2048",
        vec![file_occurrence("/srv/a.pem", 1)],
    );
    f.cert = Some(c);
    let other = finding(
        "file-2",
        Fingerprint::key(&"bb".repeat(32)),
        "key.rsa-2048",
        vec![file_occurrence("/srv/b.pem", 1)],
    );
    ResultsFile {
        header: header(ScannerKind::Files, 1, "1.0.0"),
        findings: vec![f, other],
        inventory: vec![],
        errors: vec![ScanError {
            location: "/srv/bad.pem".into(),
            reason: "not valid".into(),
        }],
    }
}

fn net_result() -> ResultsFile {
    let c = cert("aa");
    let fp = Fingerprint::cert(&c.sha256);
    let mut f = finding(
        "net-1",
        fp,
        "cert.rsa-2048",
        vec![net_occurrence("pay.example.org", 2)],
    );
    f.source = Source::Net;
    f.cert = Some(c);
    ResultsFile {
        header: header(ScannerKind::Net, 2, "1.0.0"),
        findings: vec![f],
        inventory: vec![],
        errors: vec![],
    }
}

#[test]
fn same_cert_from_files_and_net_merges() {
    let merged = merge(vec![files_result(), net_result()]).unwrap();
    assert_eq!(merged.header.scanner, ScannerKind::Merged);
    assert_eq!(merged.header.runs.len(), 2);
    let cert_findings: Vec<_> = merged
        .findings
        .iter()
        .filter(|f| f.fingerprint.0.starts_with("cert:"))
        .collect();
    assert_eq!(cert_findings.len(), 1);
    let kinds: Vec<_> = cert_findings[0]
        .occurrences
        .iter()
        .map(|o| matches!(o.location, Location::File { .. }))
        .collect();
    assert_eq!(kinds, vec![true, false]);
    assert_eq!(merged.errors.len(), 1);
}

#[test]
fn distinct_findings_kept() {
    let merged = merge(vec![files_result(), net_result()]).unwrap();
    assert_eq!(merged.findings.len(), 2);
    let ids: Vec<_> = merged.findings.iter().map(|f| f.id.clone()).collect();
    assert_eq!(ids, vec!["F-0001", "F-0002"]);
    let place = Fingerprint::place("host", "/etc/k");
    let mut a = files_result();
    a.findings
        .push(finding("x", place.clone(), "key.x", vec![]));
    let merged = merge(vec![a, net_result()]).unwrap();
    assert!(merged.findings.iter().any(|f| f.fingerprint == place));
}

#[test]
fn different_rules_for_one_subject_go_to_also() {
    let a = files_result();
    let mut b = net_result();
    b.findings[0].rule_id = "cert.expired".into();
    b.findings[0].also = vec!["cert.other".into()];
    let merged = merge(vec![a, b]).unwrap();
    let f = &merged.findings[0];
    assert_eq!(f.rule_id, "cert.rsa-2048");
    assert_eq!(f.also, vec!["cert.expired", "cert.other"]);
}

#[test]
fn occurrences_not_duplicated_on_remerge() {
    let ab = merge(vec![files_result(), net_result()]).unwrap();
    let again = merge(vec![ab.clone(), net_result()]).unwrap();
    assert_eq!(again.findings, ab.findings);
    assert_eq!(again.header.runs, ab.header.runs);
    assert_eq!(again.errors, ab.errors);
}

#[test]
fn inventory_is_merged_by_fingerprint() {
    let item = |path: &str, run: u128| InventoryItem {
        kind: InventoryKind::Certificate,
        fingerprint: Fingerprint::cert(&"aa".repeat(32)),
        pq_ready: false,
        algorithm: Some(alg()),
        cert: None,
        key: None,
        endpoint: None,
        occurrences: vec![file_occurrence(path, run)],
    };
    let mut a = files_result();
    a.inventory = vec![item("/a", 1)];
    let mut b = net_result();
    b.inventory = vec![item("/a", 1), item("/b", 2)];
    let merged = merge(vec![a, b]).unwrap();
    assert_eq!(merged.inventory.len(), 1);
    assert_eq!(merged.inventory[0].occurrences.len(), 2);
}

#[test]
fn engagement_mismatch_errors() {
    let mut b = net_result();
    b.header.engagement = "other".into();
    let err = merge(vec![files_result(), b]).unwrap_err();
    assert!(matches!(err, MergeError::EngagementMismatch { .. }));
    assert!(matches!(merge(vec![]), Err(MergeError::NoInputs)));
}

#[test]
fn pack_version_mismatch_warns() {
    let mut b = net_result();
    b.header.rules_pack.version = "1.10.0".into();
    let merged = merge(vec![files_result(), b]).unwrap();
    assert_eq!(merged.header.rules_pack.version, "1.10.0");
    let warning = merged
        .errors
        .iter()
        .find(|e| e.location == "merge")
        .expect("a merge warning");
    assert!(warning.reason.contains("1.0.0") && warning.reason.contains("1.10.0"));
}

/// Collect each string in a JSON value, with the keys.
fn strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
        serde_json::Value::Object(o) => o.values().for_each(|v| strings(v, out)),
        _ => {}
    }
}

/// A file where every sensitive string field holds a unique marker.
fn populated() -> (ResultsFile, Vec<String>) {
    let mut file = files_result();
    let mut f = file.findings.remove(0);
    f.occurrences = vec![
        file_occurrence("/home/bob/secret-path/a.pem", 1),
        net_occurrence("internal-host.corp.example", 1),
    ];
    f.cert.as_mut().unwrap().subject = "CN=subject-marker".into();
    f.cert.as_mut().unwrap().issuer = "CN=issuer-marker".into();
    f.key = Some(KeyInfo {
        fingerprint_sha256: "11".repeat(32),
        kind: KeyKind::OpenSsh,
        algorithm: Some(alg()),
        comment: Some("bob@comment-host".into()),
    });
    f.endpoint = Some(EndpointInfo {
        protocol: Protocol::Ssh,
        tls: Some(TlsObservation {
            pq_hybrid_supported: None,
            negotiated_version: None,
            negotiated_group: None,
            cipher_suite: None,
            legacy_versions: None,
            errors: vec!["bad certificate for tls-error-name.example".into()],
        }),
        ssh: Some(SshObservation {
            banner: "SSH-2.0-banner-marker".into(),
            kex: vec![],
            host_key_algorithms: vec![],
            ciphers: vec![],
            macs: vec![],
        }),
    });
    file.inventory = vec![InventoryItem {
        kind: InventoryKind::Certificate,
        fingerprint: f.fingerprint.clone(),
        pq_ready: false,
        algorithm: None,
        cert: f.cert.clone(),
        key: f.key.clone(),
        endpoint: f.endpoint.clone(),
        occurrences: f.occurrences.clone(),
    }];
    file.findings.insert(0, f);
    file.errors = vec![ScanError {
        location: "/var/err-location/x".into(),
        reason: "cannot read /var/err-reason/y on err-host".into(),
    }];
    file.header.host = "header-host-marker".into();
    file.header.operator = "operator-marker".into();
    file.header.scope_hash = Some("cc".repeat(32));
    file.header.rules_pack.origin = PackOriginRef::Unsigned {
        path: "/opt/pack-dir-marker".into(),
    };
    file.header.runs[0].host = "run-host-marker".into();
    let originals = [
        "secret-path",
        "internal-host.corp.example",
        "192.0.2.77",
        "subject-marker",
        "issuer-marker",
        "bob@comment-host",
        "tls-error-name",
        "banner-marker",
        "err-location",
        "err-reason",
        "err-host",
        "header-host-marker",
        "operator-marker",
        "pack-dir-marker",
        "run-host-marker",
        "PEM block in",
        "handshake with",
        "Secret Corp",
    ];
    (file, originals.map(String::from).to_vec())
}

#[test]
fn redact_keeps_fingerprints_and_removes_hosts() {
    let (mut file, originals) = populated();
    let before = file.clone();
    let hashes = before.header.scope_hash.clone();
    redact(&mut file);
    assert!(file.header.redacted);
    assert_eq!(file.header.scope_hash, hashes);
    for (a, b) in before.findings.iter().zip(&file.findings) {
        assert_eq!(a.fingerprint, b.fingerprint);
    }
    let json = serde_json::to_value(&file).unwrap();
    let mut all = Vec::new();
    strings(&json, &mut all);
    let text = serde_json::to_string(&json).unwrap();
    for original in &originals {
        assert!(!text.contains(original), "{original} survives");
    }
    // The values that must stay.
    assert!(text.contains(&"cc".repeat(32)));
    assert!(all
        .iter()
        .any(|s| s.starts_with("redacted:") && s.len() == 9 + 12));
}

#[test]
fn redact_is_stable_and_idempotent() {
    let (mut a, _) = populated();
    redact(&mut a);
    let once = a.clone();
    redact(&mut a);
    assert_eq!(a, once);
    let (mut b, _) = populated();
    redact(&mut b);
    assert_eq!(b, once);
}

#[test]
fn only_known_safe_strings_survive_redaction() {
    let (mut file, _) = populated();
    let mut before = Vec::new();
    strings(&serde_json::to_value(&file).unwrap(), &mut before);
    redact(&mut file);
    let mut after = Vec::new();
    strings(&serde_json::to_value(&file).unwrap(), &mut after);
    let safe = |s: &str| {
        s.starts_with("redacted:")
            || s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
            || s.starts_with("cert:")
            || s.starts_with("key:")
            || s.starts_with("F-")
            || s.starts_with("file-")
            || s.starts_with("2026-")
            || [
                "RSA", "default", "acme", "0.1.0", "1.0.0", "ssh", "tls", "file",
            ]
            .contains(&s)
            || s == "sha256WithRSAEncryption"
            || s == "cert.rsa-2048"
            || s == "key.rsa-2048"
            || s == "cert.rsa-any"
            || s == "open_ssh"
            || s == "forgery_long_lived"
            || s == "signature"
            || s == "unknown"
            || s == "certificate"
            || s == "embedded"
            || s == "endpoint"
            || s == "unsigned"
            || s == "files"
            || s == "net"
    };
    for s in after.iter().filter(|s| before.contains(s)) {
        assert!(safe(s), "string survives redaction: {s}");
    }
}
