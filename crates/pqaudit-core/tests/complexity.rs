//! Tests for the complexity and the necessary tests.

use pqaudit_core::assets::{AssetContext, Ctx};
use pqaudit_core::complexity::{assess_complexity, testing_scope};
use pqaudit_core::engagement::{Exposure, ScoringConfig, Size};
use pqaudit_core::*;
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::pack::RuleDef;
use uuid::Uuid;

fn rule(id: &str) -> RuleDef {
    default_pack().rule(id).unwrap().clone()
}

fn finding(is_ca: Option<bool>) -> Finding {
    let cert = is_ca.map(|is_ca| CertInfo {
        sha256: "aa".into(),
        subject: "s".into(),
        issuer: "i".into(),
        not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
        not_after: "2030-01-01T00:00:00Z".parse().unwrap(),
        is_ca,
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
    Finding {
        id: "F-00000001".into(),
        fingerprint: Fingerprint("key:aa".into()),
        rule_id: "tls.no-pq-kex".into(),
        source: Source::Net,
        algorithm: None,
        purpose: Purpose::KeyExchange,
        threat_type: ThreatType::Hndl,
        agility: Agility::Unknown,
        fix_owner: FixOwner::Unknown,
        also: vec![],
        occurrences: vec![Occurrence {
            location: Location::File {
                path: "/x".into(),
                line: None,
            },
            evidence: "e".into(),
            run_id: Uuid::from_u128(1),
        }],
        cert,
        key: None,
        endpoint: None,
    }
}

#[test]
fn tls_no_pq_kex_is_m() {
    let c = assess_complexity(
        &finding(None),
        &rule("tls.no-pq-kex"),
        &AssetContext::unassessed(),
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::LibraryUpgrade);
    assert_eq!(c.size, Size::M);
    assert_eq!(c.migration_years, 0.5);
}

#[test]
fn ca_cert_is_l_protocol_partner() {
    let c = assess_complexity(
        &finding(Some(true)),
        &rule("tls.no-pq-kex"),
        &AssetContext::unassessed(),
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::ProtocolPartner);
    assert_eq!(c.size, Size::L);
    assert_eq!(c.migration_years, 1.0);
    // A leaf certificate does not change the type.
    let leaf = assess_complexity(
        &finding(Some(false)),
        &rule("tls.no-pq-kex"),
        &AssetContext::unassessed(),
        &ScoringConfig::default(),
    );
    assert_eq!(leaf.change_type, ChangeType::LibraryUpgrade);
}

#[test]
fn vendor_asset_is_xl() {
    let ctx = AssetContext {
        vendor: Ctx::Assessed(true),
        ..AssetContext::unassessed()
    };
    let c = assess_complexity(
        &finding(None),
        &rule("key.classical"),
        &ctx,
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::Vendor);
    assert_eq!(c.size, Size::XL);
    assert_eq!(c.migration_years, 2.0);
}

#[test]
fn hardware_asset_is_xl_and_vendor_wins_over_hardware() {
    let hw = AssetContext {
        hardware_constrained: Ctx::Assessed(true),
        ..AssetContext::unassessed()
    };
    let c = assess_complexity(
        &finding(None),
        &rule("key.weak"),
        &hw,
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::Hardware);
    assert_eq!(c.size, Size::XL);
    let both = AssetContext {
        vendor: Ctx::Assessed(true),
        ..hw
    };
    let c = assess_complexity(
        &finding(None),
        &rule("key.weak"),
        &both,
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::Vendor);
}

#[test]
fn false_flags_and_a_hard_rule_keep_the_rule_type() {
    let ctx = AssetContext {
        vendor: Ctx::Assessed(false),
        hardware_constrained: Ctx::Assessed(false),
        ..AssetContext::unassessed()
    };
    let c = assess_complexity(
        &finding(None),
        &rule("key.weak"),
        &ctx,
        &ScoringConfig::default(),
    );
    assert_eq!(c.change_type, ChangeType::Config);
    assert_eq!(c.size, Size::S);
}

#[test]
fn partner_exposure_bumps_size_and_adds_interop() {
    let ctx = AssetContext {
        exposure: Ctx::Assessed(Exposure::Partner),
        ..AssetContext::unassessed()
    };
    let cfg = ScoringConfig::default();
    let c = assess_complexity(&finding(None), &rule("key.weak"), &ctx, &cfg);
    assert_eq!(c.size, Size::M);
    let tests = testing_scope(&rule("key.weak"), &ctx, &cfg);
    assert!(tests.contains(&TestType::Interop));
    assert!(tests.contains(&TestType::Integration));
    // Two or more size impacts also bump the size. XL stays XL.
    let c = assess_complexity(
        &finding(None),
        &rule("cert.classical-key"),
        &AssetContext::unassessed(),
        &cfg,
    );
    assert_eq!(c.size, Size::M);
    let vendor = AssetContext {
        vendor: Ctx::Assessed(true),
        ..ctx
    };
    let c = assess_complexity(&finding(None), &rule("cert.classical-key"), &vendor, &cfg);
    assert_eq!(c.size, Size::XL);
}

#[test]
fn certification_comes_from_the_rule_or_a_sensitive_class() {
    let cfg = ScoringConfig::default();
    let secret = AssetContext {
        classification: Ctx::Assessed("secret".into()),
        ..AssetContext::unassessed()
    };
    let tests = testing_scope(&rule("key.weak"), &secret, &cfg);
    assert!(tests.contains(&TestType::Certification));
    let confidential = AssetContext {
        classification: Ctx::Assessed("confidential".into()),
        ..AssetContext::unassessed()
    };
    assert!(
        testing_scope(&rule("key.weak"), &confidential, &cfg).contains(&TestType::Certification)
    );
    let internal = AssetContext {
        classification: Ctx::Assessed("internal".into()),
        ..AssetContext::unassessed()
    };
    let tests = testing_scope(&rule("key.weak"), &internal, &cfg);
    assert!(!tests.contains(&TestType::Certification));
    assert!(
        !testing_scope(&rule("key.weak"), &AssetContext::unassessed(), &cfg)
            .contains(&TestType::Certification)
    );
    // No duplicates.
    let tests = testing_scope(
        &rule("tls.no-pq-kex"),
        &AssetContext {
            exposure: Ctx::Assessed(Exposure::Partner),
            ..AssetContext::unassessed()
        },
        &cfg,
    );
    assert_eq!(tests.iter().filter(|t| **t == TestType::Interop).count(), 1);
}

#[test]
fn reasons_non_empty() {
    let c = assess_complexity(
        &finding(None),
        &rule("tls.no-pq-kex"),
        &AssetContext::unassessed(),
        &ScoringConfig::default(),
    );
    assert!(!c.reasons.is_empty());
    assert!(c.reasons.iter().all(|r| !r.contains('{')));
}
