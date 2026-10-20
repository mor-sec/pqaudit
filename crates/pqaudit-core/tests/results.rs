//! Tests for the results file.

use chrono::{TimeZone, Utc};
use pqaudit_core::*;
use std::net::IpAddr;
use uuid::Uuid;

fn sample() -> ResultsFile {
    let run_id = Uuid::from_u128(7);
    let t = Utc.with_ymd_and_hms(2026, 10, 20, 8, 0, 0).unwrap();
    let alg = Algorithm {
        name: "RSA".into(),
        key_bits: Some(2048),
        curve: None,
    };
    let occurrence = Occurrence {
        location: Location::Endpoint {
            host: "pay.example".into(),
            ip: "192.0.2.1".parse::<IpAddr>().unwrap(),
            port: 443,
            protocol: Protocol::Tls,
        },
        evidence: "negotiated group x25519".into(),
        run_id,
    };
    let file_occurrence = Occurrence {
        location: Location::File {
            path: "a/b.pem".into(),
            line: Some(3),
        },
        evidence: "PEM block".into(),
        run_id,
    };
    let cert = CertInfo {
        sha256: "00".repeat(32),
        subject: "CN=pay.example".into(),
        issuer: "CN=Test CA".into(),
        not_before: t,
        not_after: t,
        is_ca: false,
        key_usage: vec!["digitalSignature".into()],
        ext_key_usage: vec![],
        public_key: alg.clone(),
        signature_algorithm: "sha256WithRSAEncryption".into(),
        chain_position: Some(0),
    };
    let finding = Finding {
        id: "F-0001".into(),
        fingerprint: Fingerprint::cert(&cert.sha256),
        rule_id: "cert.rsa-2048".into(),
        source: Source::File,
        algorithm: Some(alg.clone()),
        purpose: Purpose::Signature,
        threat_type: ThreatType::ForgeryLongLived,
        agility: Agility::Unknown,
        fix_owner: FixOwner::Unknown,
        also: vec!["cert.rsa-any".into()],
        occurrences: vec![file_occurrence.clone(), occurrence.clone()],
        cert: Some(cert.clone()),
        key: Some(KeyInfo {
            fingerprint_sha256: "11".repeat(32),
            kind: KeyKind::X509Spki,
            algorithm: Some(alg.clone()),
            comment: None,
        }),
        endpoint: Some(EndpointInfo {
            protocol: Protocol::Tls,
            tls: Some(TlsObservation {
                pq_hybrid_supported: Some(false),
                negotiated_version: Some("TLS1.3".into()),
                negotiated_group: Some("x25519".into()),
                cipher_suite: None,
                legacy_versions: Some(vec![]),
                errors: vec![],
            }),
            ssh: Some(SshObservation {
                banner: "SSH-2.0-x".into(),
                kex: vec!["curve25519-sha256".into()],
                host_key_algorithms: vec![],
                ciphers: vec![],
                macs: vec![],
            }),
        }),
    };
    ResultsFile {
        header: ResultsHeader {
            schema_version: SCHEMA_VERSION,
            engagement: "test".into(),
            tool_version: "0.1.0".into(),
            rules_pack: PackRef {
                id: "default".into(),
                version: "1.0.0".into(),
                content_hash: "ff".repeat(32),
                origin: PackOriginRef::Installed {
                    path: "/p".into(),
                    signed_by: "k1".into(),
                    rotation_chain: vec!["k0".into(), "k1".into()],
                },
            },
            scanner: ScannerKind::Merged,
            host: "h".into(),
            operator: "o".into(),
            started: t,
            finished: t,
            scope_hash: Some("aa".into()),
            audit_log_hash: None,
            runs: vec![RunInfo {
                run_id,
                scanner: ScannerKind::Net,
                host: "h".into(),
                started: t,
            }],
            redacted: false,
        },
        inventory: vec![InventoryItem {
            kind: InventoryKind::Certificate,
            fingerprint: finding.fingerprint.clone(),
            pq_ready: false,
            algorithm: Some(alg),
            cert: Some(cert),
            key: None,
            endpoint: None,
            occurrences: vec![occurrence],
        }],
        findings: vec![finding],
        errors: vec![ScanError {
            location: "x".into(),
            reason: "y".into(),
        }],
    }
}

#[test]
fn roundtrip_plain_and_zstd() {
    let dir = tempfile::tempdir().unwrap();
    let value = sample();
    for compress in [false, true] {
        let path = dir.path().join(format!("r-{compress}.pqr"));
        value.write(&path, compress).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]), compress);
        assert_eq!(ResultsFile::read(&path).unwrap(), value);
    }
}

#[test]
fn newer_schema_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = sample();
    value.header.schema_version = 99;
    let path = dir.path().join("new.pqr");
    value.write(&path, false).unwrap();
    let err = ResultsFile::read(&path).unwrap_err();
    assert!(matches!(
        err,
        ResultsError::UnsupportedSchema {
            found: 99,
            supported: 1
        }
    ));
    let text = err.to_string();
    assert!(text.contains("99") && text.contains('1'));
}

#[test]
fn committed_schema_matches_generated() {
    let generated =
        serde_json::to_string_pretty(&schemars::schema_for!(ResultsFile)).unwrap() + "\n";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../schema/pqr.schema.json");
    if std::env::var_os("PQAUDIT_UPDATE_SCHEMA").is_some() {
        std::fs::write(path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(path).unwrap();
    assert_eq!(generated, committed);
}

fn write_raw(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[test]
fn zstd_bomb_is_rejected() {
    let bomb = zstd::encode_all(vec![b' '; 1 << 20].as_slice(), 19).unwrap();
    assert!(bomb.len() < 1000);
    let (_dir, path) = write_raw("bomb.pqr", &bomb);
    let err = ResultsFile::read_with_limit(&path, 1000).unwrap_err();
    assert!(matches!(err, ResultsError::TooLarge { limit: 1000 }));
}

#[test]
fn plain_file_over_cap_is_rejected() {
    let (_dir, path) = write_raw("big.pqr", &[b' '; 2000]);
    let err = ResultsFile::read_with_limit(&path, 1000).unwrap_err();
    assert!(matches!(err, ResultsError::TooLarge { limit: 1000 }));
}

#[test]
fn truncated_zstd_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("t.pqr");
    sample().write(&path, true).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert!(matches!(
        ResultsFile::read(&path),
        Err(ResultsError::Parse(_))
    ));
}

#[test]
fn corrupt_zstd_is_an_error() {
    let mut bytes = vec![0x28, 0xB5, 0x2F, 0xFD];
    bytes.extend_from_slice(&[0xFF; 64]);
    let (_dir, path) = write_raw("c.pqr", &bytes);
    assert!(matches!(
        ResultsFile::read(&path),
        Err(ResultsError::Parse(_))
    ));
}

#[test]
fn invalid_json_is_a_parse_error() {
    let (_dir, path) = write_raw("j.pqr", b"{not json");
    assert!(matches!(
        ResultsFile::read(&path),
        Err(ResultsError::Parse(_))
    ));
}

#[test]
fn missing_schema_version_is_a_parse_error() {
    let (_dir, path) = write_raw("m.pqr", br#"{"header":{}}"#);
    let err = ResultsFile::read(&path).unwrap_err();
    assert!(matches!(err, ResultsError::Parse(_)));
    assert!(err.to_string().contains("schema version"));
}

#[test]
fn missing_file_is_an_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = ResultsFile::read(&dir.path().join("none.pqr")).unwrap_err();
    assert!(matches!(err, ResultsError::Io(_)));
}

#[test]
fn max_limit_does_not_overflow() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ok.pqr");
    sample().write(&path, true).unwrap();
    assert_eq!(
        ResultsFile::read_with_limit(&path, u64::MAX).unwrap(),
        sample()
    );
}

#[test]
fn bad_schema_version_gives_the_standard_message() {
    let cases: [&[u8]; 5] = [
        b"{}",
        br#"{"header":{"schema_version":"1"}}"#,
        br#"{"header":{"schema_version":-1}}"#,
        br#"{"header":{"schema_version":1.5}}"#,
        br#"{"header":{"schema_version":99999999999999999999999}}"#,
    ];
    for case in cases {
        let (_dir, path) = write_raw("v.pqr", case);
        match ResultsFile::read(&path) {
            Err(ResultsError::Parse(text)) => {
                assert_eq!(text, pqaudit_core::messages::NO_SCHEMA_VERSION)
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
