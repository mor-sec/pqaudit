//! Tests for the priority score.

use chrono::{NaiveDate, TimeZone, Utc};
use pqaudit_core::assets::{AssetContext, Ctx};
use pqaudit_core::complexity::Complexity;
use pqaudit_core::deadlines::DeadlineRef;
use pqaudit_core::engagement::{Band, Exposure, ScoringConfig, Size};
use pqaudit_core::scoring::{band, score};
use pqaudit_core::*;
use uuid::Uuid;

fn today() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
}

fn occurrence(n: usize) -> Occurrence {
    Occurrence {
        location: Location::File {
            path: format!("/srv/{n}.pem"),
            line: None,
        },
        evidence: "e".into(),
        run_id: Uuid::from_u128(1),
    }
}

fn finding(threat: ThreatType, occurrences: usize) -> Finding {
    Finding {
        id: "F-00000001".into(),
        fingerprint: Fingerprint("key:aa".into()),
        rule_id: "key.classical".into(),
        source: Source::File,
        algorithm: None,
        purpose: Purpose::KeyExchange,
        threat_type: threat,
        agility: Agility::Unknown,
        fix_owner: FixOwner::Unknown,
        also: vec![],
        occurrences: (0..occurrences).map(occurrence).collect(),
        cert: None,
        key: None,
        endpoint: None,
    }
}

fn context(class: &str, lifespan: u32, exposure: Exposure) -> AssetContext {
    AssetContext {
        classification: Ctx::Assessed(class.into()),
        data_lifespan_years: Ctx::Assessed(lifespan),
        exposure: Ctx::Assessed(exposure),
        ..AssetContext::unassessed()
    }
}

fn deadline(y: i32, m: u32, d: u32) -> DeadlineRef {
    DeadlineRef {
        date: NaiveDate::from_ymd_opt(y, m, d).unwrap(),
        profile_id: "us".into(),
        description: "d".into(),
        source_title: "t".into(),
        source_url: "u".into(),
    }
}

fn complexity(years: f64) -> Complexity {
    Complexity {
        change_type: ChangeType::LibraryUpgrade,
        size: Size::M,
        migration_years: years,
        reasons: vec![],
    }
}

fn factor(b: &pqaudit_core::scoring::ScoreBreakdown, name: &str) -> f64 {
    b.factors.iter().find(|f| f.name == name).unwrap().value
}

#[test]
fn all_max_scores_100() {
    let f = finding(ThreatType::Hndl, 99);
    let ctx = context("secret", 25, Exposure::Internet);
    let b = score(
        &f,
        &ctx,
        Some(&deadline(2026, 1, 1)),
        &complexity(0.5),
        &ScoringConfig::default(),
        2035,
        today(),
    );
    assert!((b.total - 100.0).abs() < 1e-9, "total {}", b.total);
    assert_eq!(b.factors.len(), 6);
}

#[test]
fn worked_example() {
    let f = finding(ThreatType::Hndl, 1);
    let ctx = context("confidential", 5, Exposure::Internal);
    let b = score(
        &f,
        &ctx,
        Some(&deadline(2030, 12, 31)),
        &complexity(0.5),
        &ScoringConfig::default(),
        2035,
        today(),
    );
    assert!((b.total - 64.06).abs() < 0.2, "total {}", b.total);
    assert!((factor(&b, "mosca") - 0.65).abs() < 1e-9);
    assert!((factor(&b, "deadline") - 0.58).abs() < 0.01);
    assert!((factor(&b, "scale") - 0.1505).abs() < 0.001);
    let cfg = ScoringConfig::default();
    assert_eq!(band(b.total, &cfg.bands), Band::High);
    let sum: f64 = b.factors.iter().map(|f| f.contribution).sum();
    assert!((sum - b.total).abs() < 1e-9);
}

#[test]
fn factor_values_follow_the_brief() {
    let cfg = ScoringConfig::default();
    let value = |threat, exposure: Exposure, name: &str| {
        let f = finding(threat, 1);
        let ctx = context("public", 1, exposure);
        factor(
            &score(&f, &ctx, None, &complexity(0.5), &cfg, 2035, today()),
            name,
        )
    };
    assert_eq!(value(ThreatType::Hndl, Exposure::Internet, "threat"), 1.0);
    assert_eq!(
        value(ThreatType::ForgeryLongLived, Exposure::Internet, "threat"),
        0.8
    );
    assert_eq!(
        value(ThreatType::ClassicalWeakNow, Exposure::Internet, "threat"),
        1.0
    );
    assert_eq!(
        value(ThreatType::ForgeryShortLived, Exposure::Internet, "threat"),
        0.3
    );
    assert_eq!(value(ThreatType::Hndl, Exposure::Internet, "exposure"), 1.0);
    assert_eq!(value(ThreatType::Hndl, Exposure::Partner, "exposure"), 0.7);
    assert_eq!(value(ThreatType::Hndl, Exposure::Internal, "exposure"), 0.4);
    assert_eq!(value(ThreatType::Hndl, Exposure::Isolated, "exposure"), 0.2);
    assert_eq!(value(ThreatType::Hndl, Exposure::Isolated, "deadline"), 0.0);
}

#[test]
fn deadline_values() {
    let cfg = ScoringConfig::default();
    let f = finding(ThreatType::Hndl, 1);
    let ctx = context("public", 1, Exposure::Internal);
    let at = |d: Option<DeadlineRef>| {
        factor(
            &score(&f, &ctx, d.as_ref(), &complexity(0.5), &cfg, 2035, today()),
            "deadline",
        )
    };
    assert_eq!(at(None), 0.0);
    assert_eq!(at(Some(deadline(2026, 10, 20))), 1.0);
    assert_eq!(at(Some(deadline(2020, 1, 1))), 1.0);
    assert_eq!(at(Some(deadline(2040, 1, 1))), 0.0);
}

#[test]
fn mosca_boundaries() {
    let cfg = ScoringConfig::default();
    let f = finding(ThreatType::Hndl, 1);
    // The time to the quantum computer is 9 years.
    let at = |lifespan: u32, years: f64| {
        let ctx = context("public", lifespan, Exposure::Internal);
        factor(
            &score(&f, &ctx, None, &complexity(years), &cfg, 2035, today()),
            "mosca",
        )
    };
    assert_eq!(at(9, 0.0), 1.0);
    assert!((at(8, 0.0) - 0.9).abs() < 1e-9);
    assert!((at(0, 0.0) - 0.1).abs() < 1e-9);
    // A margin below -10 gives 0.
    let far = factor(
        &score(
            &f,
            &context("public", 0, Exposure::Internal),
            None,
            &complexity(0.0),
            &cfg,
            2060,
            today(),
        ),
        "mosca",
    );
    assert_eq!(far, 0.0);
}

#[test]
fn certificate_lifetime_extends_mosca_lifespan_for_long_lived_forgery() {
    let cfg = ScoringConfig::default();
    let mut f = finding(ThreatType::ForgeryLongLived, 1);
    let ctx = context("public", 1, Exposure::Internal);
    let plain = factor(
        &score(&f, &ctx, None, &complexity(0.0), &cfg, 2035, today()),
        "mosca",
    );
    assert!((plain - 0.2).abs() < 1e-9);
    f.cert = Some(CertInfo {
        sha256: "aa".into(),
        subject: "s".into(),
        issuer: "i".into(),
        not_before: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2040, 1, 1, 0, 0, 0).unwrap(),
        is_ca: false,
        key_usage: vec![],
        ext_key_usage: vec![],
        public_key: Algorithm {
            name: "RSA".into(),
            key_bits: Some(2048),
            curve: None,
        },
        signature_algorithm: "sha256WithRSA".into(),
        chain_position: Some(0),
    });
    let long = score(&f, &ctx, None, &complexity(0.0), &cfg, 2035, today());
    assert_eq!(factor(&long, "mosca"), 1.0);
    // A certificate on another threat type does not change the lifespan.
    f.threat_type = ThreatType::Hndl;
    let other = score(&f, &ctx, None, &complexity(0.0), &cfg, 2035, today());
    assert!((factor(&other, "mosca") - 0.2).abs() < 1e-9);
}

#[test]
fn unassessed_is_conservative_and_noted() {
    let cfg = ScoringConfig::default();
    let f = finding(ThreatType::Hndl, 1);
    let b = score(
        &f,
        &AssetContext::unassessed(),
        None,
        &complexity(0.5),
        &cfg,
        2035,
        today(),
    );
    assert_eq!(factor(&b, "exposure"), 1.0);
    assert_eq!(factor(&b, "sensitivity"), 1.0);
    // The lifespan is 25 years, so the margin is not negative.
    assert_eq!(factor(&b, "mosca"), 1.0);
    for name in ["exposure", "sensitivity", "mosca"] {
        let f = b.factors.iter().find(|f| f.name == name).unwrap();
        assert!(f.note.contains("unassessed"), "{name}: {}", f.note);
    }
}

#[test]
fn unknown_classification_is_one_with_a_note() {
    let cfg = ScoringConfig::default();
    let f = finding(ThreatType::Hndl, 1);
    let ctx = context("top-secret", 5, Exposure::Internal);
    let b = score(&f, &ctx, None, &complexity(0.5), &cfg, 2035, today());
    let s = b.factors.iter().find(|f| f.name == "sensitivity").unwrap();
    assert_eq!(s.value, 1.0);
    assert!(s.note.contains("top-secret"), "{}", s.note);
}

#[test]
fn bands_boundaries() {
    let bands = ScoringConfig::default().bands;
    assert_eq!(band(80.0, &bands), Band::Critical);
    assert_eq!(band(79.99, &bands), Band::High);
    assert_eq!(band(60.0, &bands), Band::High);
    assert_eq!(band(40.0, &bands), Band::Medium);
    assert_eq!(band(39.99, &bands), Band::Low);
}

#[test]
fn custom_weights_used() {
    let mut cfg = ScoringConfig::default();
    cfg.weights.threat = 1.0;
    cfg.weights.exposure = 0.0;
    cfg.weights.sensitivity = 0.0;
    cfg.weights.mosca = 0.0;
    cfg.weights.deadline = 0.0;
    cfg.weights.scale = 0.0;
    let f = finding(ThreatType::ForgeryShortLived, 1);
    let ctx = context("secret", 25, Exposure::Internet);
    let b = score(&f, &ctx, None, &complexity(0.5), &cfg, 2035, today());
    assert!((b.total - 30.0).abs() < 1e-9, "total {}", b.total);
    let t = b.factors.iter().find(|f| f.name == "threat").unwrap();
    assert_eq!(t.weight, 1.0);
}
