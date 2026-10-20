//! Tests for deadline selection.

use chrono::NaiveDate;
use pqaudit_core::assets::Ctx;
use pqaudit_core::deadlines::{planning, resolve};
use pqaudit_core::{ThreatType, Tier};
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::pack::{DeadlineProfile, MilestoneKind};

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

fn profile(id: &str) -> &'static DeadlineProfile {
    default_pack().profile(id).unwrap()
}

/// A custom profile with one milestone. `rule` is the YAML text of `applies_to`.
fn custom(id: &str, year: i32, kind: &str, rule: &str) -> DeadlineProfile {
    let text = format!(
        "id: {id}\nname: {id}\nmilestones:\n  - date: {year}-12-31\n    kind: {kind}\n    applies_to: {rule}\n    description: d\n    source_title: t\n    source_url: https://example.com\n    as_of: 2026-10-20\n"
    );
    serde_yaml::from_str(&text).unwrap()
}

#[test]
fn uk_high_tier_gets_2031() {
    let uk = profile("uk");
    let got = resolve(ThreatType::Hndl, Ctx::Assessed(Tier::High), None, &[uk]).unwrap();
    assert_eq!(got.date, date(2031, 12, 31));
    assert_eq!(got.profile_id, "uk");
    assert!(!got.source_url.is_empty() && !got.source_title.is_empty());
}

#[test]
fn uk_unassessed_tier_gets_2031() {
    let got = resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[profile("uk")]).unwrap();
    assert_eq!(got.date, date(2031, 12, 31));
}

#[test]
fn uk_standard_tier_gets_2035() {
    let got = resolve(
        ThreatType::Hndl,
        Ctx::Assessed(Tier::Standard),
        None,
        &[profile("uk")],
    )
    .unwrap();
    assert_eq!(got.date, date(2035, 12, 31));
}

#[test]
fn au_and_uk_strictest_is_au_2030() {
    let got = resolve(
        ThreatType::Hndl,
        Ctx::Assessed(Tier::High),
        None,
        &[profile("uk"), profile("au")],
    )
    .unwrap();
    assert_eq!(got.date, date(2030, 12, 31));
    assert_eq!(got.profile_id, "au");
}

#[test]
fn same_date_first_profile_wins() {
    let a = custom("a", 2030, "migration", "{tier: all}");
    let b = custom("b", 2030, "migration", "{tier: all}");
    let got = resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[&b, &a]).unwrap();
    assert_eq!(got.profile_id, "b");
}

#[test]
fn planning_never_attached() {
    let uk = profile("uk");
    // The UK profile holds a planning milestone for 2028. No finding gets it.
    for tier in [
        Ctx::Unassessed,
        Ctx::Assessed(Tier::High),
        Ctx::Assessed(Tier::Standard),
    ] {
        let got = resolve(ThreatType::Hndl, tier, None, &[uk]).unwrap();
        assert_ne!(got.date, date(2028, 12, 31));
    }
    let only_planning = custom("p", 2028, "planning", "{tier: all}");
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[&only_planning]).is_none());
    let list = planning(&[uk, profile("au")]);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0, "uk");
    assert_eq!(list[0].1.kind, MilestoneKind::Planning);
    assert_eq!(list[0].1.date, date(2028, 12, 31));
}

#[test]
fn migration_milestone_without_tier_does_not_apply() {
    let p = custom("n", 2029, "migration", "{}");
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[&p]).is_none());
}

#[test]
fn threat_type_filter_respected() {
    let p = custom(
        "sign",
        2030,
        "migration",
        "{tier: all, threat_types: [forgery_long_lived]}",
    );
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[&p]).is_none());
    assert!(resolve(ThreatType::ForgeryLongLived, Ctx::Unassessed, None, &[&p]).is_some());
}

#[test]
fn sector_filter_respected() {
    let p = custom("gov", 2030, "migration", "{tier: all, sector: government}");
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, None, &[&p]).is_none());
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, Some("finance"), &[&p]).is_none());
    assert!(resolve(ThreatType::Hndl, Ctx::Unassessed, Some("government"), &[&p]).is_some());
}
