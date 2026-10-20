//! Tests of the certificate rules.

use chrono::{Duration, NaiveDate, TimeZone, Utc};
use pqaudit_core::classify::classify_cert;
use pqaudit_core::{Algorithm, CertInfo, ThreatType};
use pqaudit_rules::embedded::default_pack;

fn cert(key: &str, bits: Option<u32>, signature: &str, valid_days: i64) -> CertInfo {
    let not_before = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    CertInfo {
        sha256: "00".repeat(32),
        subject: "CN=test".into(),
        issuer: "CN=test".into(),
        not_before,
        not_after: not_before + Duration::days(valid_days),
        is_ca: false,
        key_usage: vec![],
        ext_key_usage: vec![],
        public_key: Algorithm {
            name: key.into(),
            key_bits: bits,
            curve: None,
        },
        signature_algorithm: signature.into(),
        chain_position: Some(0),
    }
}

fn today() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
}

#[test]
fn three_years_is_short_and_one_day_more_is_long() {
    let pack = default_pack();
    let short = cert("RSA", Some(2048), "sha256WithRSAEncryption", 3 * 365);
    let long = cert("RSA", Some(2048), "sha256WithRSAEncryption", 3 * 365 + 1);
    assert_eq!(
        classify_cert(&short, pack, today()).unwrap().1,
        ThreatType::ForgeryShortLived
    );
    assert_eq!(
        classify_cert(&long, pack, today()).unwrap().1,
        ThreatType::ForgeryLongLived
    );
}

#[test]
fn code_signing_certificate_is_long_lived() {
    let mut signing = cert("RSA", Some(2048), "sha256WithRSAEncryption", 30);
    signing.ext_key_usage = vec!["codeSigning".into()];
    assert_eq!(
        classify_cert(&signing, default_pack(), today()).unwrap().1,
        ThreatType::ForgeryLongLived
    );
}

#[test]
fn weak_key_has_priority_over_weak_hash() {
    let weak = cert("RSA", Some(1024), "sha1WithRSAEncryption", 30);
    let (rule, threat, also) = classify_cert(&weak, default_pack(), today()).unwrap();
    assert_eq!(rule, "cert.weak-key");
    assert_eq!(threat, ThreatType::ClassicalWeakNow);
    assert_eq!(also, vec!["cert.weak-sig-hash", "cert.classical-key"]);
}

#[test]
fn post_quantum_key_has_no_rule() {
    let pq = cert("ML-DSA-65", None, "ML-DSA-65", 30);
    assert!(classify_cert(&pq, default_pack(), today()).is_none());
}

#[test]
fn unknown_key_algorithm_has_no_key_rule() {
    let unknown = cert("1.2.3.4", None, "sha256WithRSAEncryption", 30);
    assert!(classify_cert(&unknown, default_pack(), today()).is_none());
}
