//! Tests for the assessment.

use chrono::{NaiveDate, TimeZone, Utc};
use pqaudit_core::assess::{assess, AssessError};
use pqaudit_core::assets::Ctx;
use pqaudit_core::engagement::{
    AssetsFile, Band, Engagement, EngagementConfig, OverridesFile, ScoringConfig,
};
use pqaudit_core::*;
use pqaudit_rules::embedded::default_pack;
use std::path::PathBuf;
use uuid::Uuid;

fn today() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 20).unwrap()
}

fn engagement(profiles: &[&str], assets: &str, overrides: &str) -> Engagement {
    let profiles = format!("{profiles:?}");
    let config: EngagementConfig = toml::from_str(&format!(
        "client = \"Acme\"\nassessor = \"Jo\"\n[deadlines]\nprofiles = {profiles}\n[assumptions]\ncrqc_year = 2035\n"
    ))
    .unwrap();
    Engagement {
        dir: PathBuf::from("."),
        config,
        assets: toml::from_str::<AssetsFile>(assets).unwrap(),
        overrides: toml::from_str::<OverridesFile>(overrides).unwrap(),
        scoring: ScoringConfig::default(),
    }
}

fn finding(fp: &str, host: &str) -> Finding {
    Finding {
        id: format!("F-{fp}"),
        fingerprint: Fingerprint(fp.into()),
        rule_id: "key.classical".into(),
        source: Source::Net,
        algorithm: None,
        purpose: Purpose::KeyExchange,
        threat_type: ThreatType::Hndl,
        agility: Agility::Unknown,
        fix_owner: FixOwner::Unknown,
        also: vec![],
        occurrences: vec![Occurrence {
            location: Location::Endpoint {
                host: host.into(),
                ip: "192.0.2.1".parse().unwrap(),
                port: 443,
                protocol: Protocol::Tls,
            },
            evidence: "e".into(),
            run_id: Uuid::from_u128(1),
        }],
        cert: None,
        key: None,
        endpoint: None,
    }
}

fn results(findings: Vec<Finding>) -> ResultsFile {
    let time = Utc.with_ymd_and_hms(2026, 10, 20, 8, 0, 0).unwrap();
    ResultsFile {
        header: ResultsHeader {
            schema_version: SCHEMA_VERSION,
            engagement: "acme".into(),
            tool_version: "0.1.0".into(),
            rules_pack: PackRef {
                id: default_pack().id.clone(),
                version: default_pack().version.to_string(),
                content_hash: default_pack().content_hash.clone(),
                origin: PackOriginRef::Embedded,
            },
            scanner: ScannerKind::Net,
            host: "h".into(),
            operator: "o".into(),
            started: time,
            finished: time,
            scope_hash: None,
            audit_log_hash: None,
            runs: vec![],
            redacted: false,
        },
        findings,
        inventory: vec![],
        errors: vec![ScanError {
            location: "x".into(),
            reason: "y".into(),
        }],
    }
}

const FULL_ASSET: &str = r#"
[[asset]]
name = "Pay"
business_unit = "Retail"
owner = "Team"
match = { hosts = ["pay.example"] }
classification = "secret"
data_lifespan_years = 10
exposure = "internet"
vendor = false
priority_tier = "standard"
hardware_constrained = false

[[asset]]
name = "Partial"
match = { hosts = ["part.example"] }
exposure = "partner"
"#;

#[test]
fn overrides_applied_by_fingerprint() {
    let overrides = r#"
[[override]]
fingerprint = "key:aa"
priority = "low"
reason = "The board asked for it."
by = "Jo"
date = 2026-10-01
"#;
    let eng = engagement(&["uk"], FULL_ASSET, overrides);
    let res = results(vec![
        finding("key:aa", "pay.example"),
        finding("key:bb", "pay.example"),
    ]);
    let out = assess(&res, &eng, default_pack(), today()).unwrap();
    let first = &out.findings[0];
    assert_eq!(
        first.override_.as_ref().unwrap().reason,
        "The board asked for it."
    );
    assert_eq!(first.effective_band, Band::Low);
    assert_eq!(first.band, Band::Critical);
    assert!(out.findings[1].override_.is_none());
    assert_eq!(out.findings[1].effective_band, out.findings[1].band);
    assert!(out.orphaned_overrides.is_empty());
    assert_eq!(first.asset.as_deref(), Some("Pay"));
    assert_eq!(first.context.business_unit.as_deref(), Some("Retail"));
    // The asset has the tier standard, so the UK date for all assets applies.
    assert_eq!(
        first.deadline.as_ref().unwrap().date.to_string(),
        "2035-12-31"
    );
    assert_eq!(first.rule.id, "key.classical");
    assert_eq!(out.errors.len(), 1);
    assert_eq!(out.planning_milestones.len(), 1);
    assert_eq!(out.assumptions.crqc_year, 2035);
    assert_eq!(out.pack.id, default_pack().id);
}

#[test]
fn orphaned_override_reported() {
    let overrides = r#"
[[override]]
fingerprint = "key:gone"
priority = "low"
reason = "r"
by = "Jo"
date = 2026-10-01
"#;
    let eng = engagement(&["uk"], FULL_ASSET, overrides);
    let res = results(vec![finding("key:aa", "pay.example")]);
    let out = assess(&res, &eng, default_pack(), today()).unwrap();
    assert_eq!(out.orphaned_overrides.len(), 1);
    assert_eq!(out.orphaned_overrides[0].fingerprint, "key:gone");
    assert!(out.findings[0].override_.is_none());
}

#[test]
fn unassessed_count_counts_findings_with_any_unassessed_field() {
    let eng = engagement(&["uk"], FULL_ASSET, "");
    let res = results(vec![
        finding("key:a", "pay.example"),     // all six fields set
        finding("key:b", "part.example"),    // some fields set
        finding("key:c", "nowhere.example"), // no asset
    ]);
    let out = assess(&res, &eng, default_pack(), today()).unwrap();
    assert_eq!(out.unassessed_count, 2);
    assert!(!out.findings[0].context.has_unassessed());
    assert!(out.findings[1].context.has_unassessed());
    assert_eq!(out.findings[2].asset, None);
    assert_eq!(out.findings[2].context.exposure, Ctx::Unassessed);
    // An unassessed tier gets the cautious UK date for high-tier assets.
    assert_eq!(
        out.findings[2].deadline.as_ref().unwrap().date.to_string(),
        "2031-12-31"
    );
}

#[test]
fn unknown_profile_errors() {
    let eng = engagement(&["uk", "xx"], "", "");
    let err = assess(&results(vec![]), &eng, default_pack(), today()).unwrap_err();
    assert_eq!(err, AssessError::UnknownProfile("xx".into()));
    assert!(err.to_string().contains("xx"));
}

#[test]
fn assessment_date_overrides_today() {
    let mut eng = engagement(&["uk"], "", "");
    eng.config.assessment_date = NaiveDate::from_ymd_opt(2027, 1, 2);
    let out = assess(&results(vec![]), &eng, default_pack(), today()).unwrap();
    assert_eq!(out.engagement.assessment_date.to_string(), "2027-01-02");
}

#[test]
fn first_matching_occurrence_gives_the_asset() {
    let eng = engagement(&["uk"], FULL_ASSET, "");
    let mut f = finding("key:aa", "nowhere.example");
    let mut second = f.occurrences[0].clone();
    second.location = Location::Endpoint {
        host: "PAY.example".into(),
        ip: "192.0.2.2".parse().unwrap(),
        port: 8443,
        protocol: Protocol::Tls,
    };
    f.occurrences.push(second);
    let out = assess(&results(vec![f]), &eng, default_pack(), today()).unwrap();
    assert_eq!(out.findings[0].asset.as_deref(), Some("Pay"));
}

#[test]
fn unknown_rule_and_bad_glob_error() {
    let eng = engagement(&["uk"], "", "");
    let mut f = finding("key:aa", "x");
    f.rule_id = "nope".into();
    let err = assess(&results(vec![f]), &eng, default_pack(), today()).unwrap_err();
    assert_eq!(err, AssessError::UnknownRule("nope".into()));

    let bad = "[[asset]]\nname = \"B\"\nmatch = { paths = [\"a[\"] }\n";
    let eng = engagement(&["uk"], bad, "");
    let err = assess(&results(vec![]), &eng, default_pack(), today()).unwrap_err();
    assert!(matches!(err, AssessError::InvalidGlob { .. }));
}

fn two_site_finding(first: &str, second: &str) -> Finding {
    let mut f = finding("key:aa", first);
    let mut other = f.occurrences[0].clone();
    other.location = Location::Endpoint {
        host: second.into(),
        ip: "192.0.2.2".parse().unwrap(),
        port: 443,
        protocol: Protocol::Tls,
    };
    f.occurrences.push(other);
    f
}

#[test]
fn earliest_asset_in_file_wins_in_both_occurrence_orders() {
    let eng = engagement(&["uk"], FULL_ASSET, "");
    for (a, b) in [
        ("pay.example", "part.example"),
        ("part.example", "pay.example"),
    ] {
        let out = assess(
            &results(vec![two_site_finding(a, b)]),
            &eng,
            default_pack(),
            today(),
        )
        .unwrap();
        assert_eq!(out.findings[0].asset.as_deref(), Some("Pay"));
    }
}

#[test]
fn pack_mismatch_errors() {
    let eng = engagement(&["uk"], "", "");
    let mut res = results(vec![]);
    res.header.rules_pack.content_hash = "cd".repeat(32);
    let err = assess(&res, &eng, default_pack(), today()).unwrap_err();
    assert!(matches!(err, AssessError::PackMismatch { .. }));
    let text = err.to_string();
    assert!(text.contains(&"cd".repeat(32)) && text.contains(&default_pack().content_hash));
    let mut res = results(vec![]);
    res.header.rules_pack.version = "9.9.9".into();
    assert!(matches!(
        assess(&res, &eng, default_pack(), today()),
        Err(AssessError::PackMismatch { .. })
    ));
}

#[test]
fn duplicate_override_errors() {
    let one = "[[override]]\nfingerprint = \"key:aa\"\npriority = \"low\"\nreason = \"r\"\nby = \"Jo\"\ndate = 2026-10-01\n";
    let eng = engagement(&["uk"], "", &format!("{one}{one}"));
    let err = assess(&results(vec![]), &eng, default_pack(), today()).unwrap_err();
    assert_eq!(err, AssessError::DuplicateOverride("key:aa".into()));
    assert!(err.to_string().contains("key:aa"));
}
