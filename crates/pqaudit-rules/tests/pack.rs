//! Tests of the rules pack format and the default pack.

use std::fs;
use std::path::Path;

use chrono::NaiveDate;
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::pack::{MilestoneKind, PackError, RulesPack, TierScope};

fn date(text: &str) -> NaiveDate {
    text.parse().unwrap()
}

fn write(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

const RULE: &str = "- id: test.rule
  family: test
  aliases: [old.id]
  title: A test rule.
  description: This rule is for tests.
  remediation: Do nothing.
  change_type: config
";

fn small_pack(root: &Path, rules: &str) {
    write(root, "pack.toml", "id = \"test\"\nversion = \"1.2.3\"\n");
    write(root, "algorithms.yaml", "[]\n");
    write(root, "rules/test.yaml", rules);
}

fn has_milestone(
    pack: &RulesPack,
    profile: &str,
    on: &str,
    kind: MilestoneKind,
    tier: Option<TierScope>,
) -> bool {
    pack.profiles
        .iter()
        .find(|p| p.id == profile)
        .unwrap()
        .milestones
        .iter()
        .any(|m| m.date == date(on) && m.kind == kind && m.applies_to.tier == tier)
}

#[test]
fn embedded_pack_loads() {
    let pack = default_pack();
    for id in [
        "cert.classical-key",
        "cert.weak-key",
        "cert.weak-sig-hash",
        "key.classical",
        "key.weak",
        "tls.no-pq-kex",
        "tls.legacy-version",
        "ssh.no-pq-kex",
        "ssh.weak-kex",
        "ssh.classical-hostkey",
    ] {
        assert!(pack.rule(id).is_some(), "missing rule {id}");
    }
    for id in ["us", "uk", "au"] {
        assert!(pack.profiles.iter().any(|p| p.id == id), "missing {id}");
    }
    assert_eq!(pack.content_hash.len(), 64);
}

#[test]
fn rule_lookup_by_alias() {
    let dir = tempfile::tempdir().unwrap();
    small_pack(dir.path(), RULE);
    let pack = RulesPack::load_dir(dir.path()).unwrap();
    assert_eq!(pack.rule("old.id").unwrap().id, "test.rule");
    assert_eq!(pack.rule("test.rule").unwrap().id, "test.rule");
    assert!(pack.rule("none").is_none());
}

#[test]
fn uk_profile_milestones() {
    let pack = default_pack();
    assert!(has_milestone(
        pack,
        "uk",
        "2028-12-31",
        MilestoneKind::Planning,
        None
    ));
    assert!(has_milestone(
        pack,
        "uk",
        "2031-12-31",
        MilestoneKind::Migration,
        Some(TierScope::High)
    ));
    assert!(has_milestone(
        pack,
        "uk",
        "2035-12-31",
        MilestoneKind::Migration,
        Some(TierScope::All)
    ));
}

#[test]
fn au_profile_milestone() {
    assert!(has_milestone(
        default_pack(),
        "au",
        "2030-12-31",
        MilestoneKind::Migration,
        Some(TierScope::All)
    ));
}

#[test]
fn us_profile_milestones() {
    let pack = default_pack();
    assert!(has_milestone(
        pack,
        "us",
        "2030-12-31",
        MilestoneKind::Migration,
        Some(TierScope::All)
    ));
    assert!(has_milestone(
        pack,
        "us",
        "2035-12-31",
        MilestoneKind::Migration,
        Some(TierScope::All)
    ));
    let on_2035: Vec<&str> = pack
        .profile("us")
        .unwrap()
        .milestones
        .iter()
        .filter(|m| m.date == date("2035-12-31"))
        .map(|m| m.source_title.as_str())
        .collect();
    assert_eq!(on_2035.len(), 2, "{on_2035:?}");
    assert!(on_2035.iter().any(|t| t.contains("NIST IR 8547")));
    assert!(on_2035.iter().any(|t| t.contains("NSM-10")));
}

#[test]
fn every_milestone_has_source_and_as_of() {
    for profile in &default_pack().profiles {
        assert!(!profile.milestones.is_empty());
        for m in &profile.milestones {
            assert!(m.source_url.starts_with("https://"), "{}", m.source_url);
            assert!(!m.source_title.is_empty());
            assert!(m.as_of > date("2026-01-01"));
        }
    }
}

#[test]
fn rsa_weak_below_2048() {
    let pack = default_pack();
    assert_eq!(pack.algorithm("RSA").unwrap().weak_below_bits, Some(2048));
    assert!(pack.algorithm("SHA-1").unwrap().weak_always);
    assert!(pack.algorithm("ML-KEM-768").is_some());
}

#[test]
fn bad_yaml_is_error_with_file_name() {
    let dir = tempfile::tempdir().unwrap();
    small_pack(dir.path(), "- id: [unclosed\n");
    let error = RulesPack::load_dir(dir.path()).unwrap_err();
    assert!(matches!(error, PackError::Parse { .. }));
    assert!(error.to_string().contains("rules/test.yaml"), "{error}");
}

#[test]
fn content_hash_changes_with_content() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    small_pack(a.path(), RULE);
    small_pack(b.path(), &RULE.replace("Do nothing", "Do less"));
    let ha = RulesPack::load_dir(a.path()).unwrap().content_hash;
    let hb = RulesPack::load_dir(b.path()).unwrap().content_hash;
    assert_ne!(ha, hb);
}

const PROFILE: &str = "id: p\nname: P\nmilestones:\n  - date: 2030-12-31\n    kind: migration\n    applies_to: {teir: high}\n    description: d\n    source_title: t\n    source_url: https://example.com\n    as_of: 2026-10-20\n";

#[test]
fn unknown_field_is_error_with_file_name() {
    let dir = tempfile::tempdir().unwrap();
    small_pack(dir.path(), RULE);
    write(dir.path(), "profiles/p.yaml", PROFILE);
    let error = RulesPack::load_dir(dir.path()).unwrap_err();
    assert!(matches!(error, PackError::Parse { .. }), "{error}");
    assert!(error.to_string().contains("profiles/p.yaml"), "{error}");
    assert!(error.to_string().contains("teir"), "{error}");
}

#[test]
fn unknown_rule_field_is_error() {
    let dir = tempfile::tempdir().unwrap();
    small_pack(dir.path(), &format!("{RULE}  extra: 1\n"));
    let error = RulesPack::load_dir(dir.path()).unwrap_err();
    assert!(error.to_string().contains("rules/test.yaml"), "{error}");
}

#[test]
fn misplaced_yaml_files_are_errors() {
    for name in [
        "rules/test.yml",
        "other/x.yaml",
        "rules/sub/x.yaml",
        "stray.yaml",
    ] {
        let dir = tempfile::tempdir().unwrap();
        small_pack(dir.path(), RULE);
        write(dir.path(), name, "[]\n");
        let error = RulesPack::load_dir(dir.path()).unwrap_err();
        assert!(
            matches!(error, PackError::Misplaced { .. }),
            "{name}: {error}"
        );
        assert!(error.to_string().contains(name), "{error}");
    }
}

#[test]
fn trust_directory_is_not_pack_content() {
    let with_trust = |extra: bool| {
        let mut files = vec![
            (
                "pack.toml".to_string(),
                b"id = \"t\"\nversion = \"1.0.0\"\n".to_vec(),
            ),
            ("algorithms.yaml".to_string(), b"[]\n".to_vec()),
        ];
        if extra {
            files.push(("trust/keys.toml".to_string(), b"revoked = []\n".to_vec()));
        }
        RulesPack::from_files(files).unwrap()
    };
    assert_eq!(
        with_trust(true).content_hash,
        with_trust(false).content_hash
    );
}
