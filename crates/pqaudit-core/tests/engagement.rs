//! Tests for the engagement files.

use std::fs;
use std::path::Path;

use pqaudit_core::engagement::{
    AssetsFile, Band, Engagement, EngagementError, Exposure, OverridesFile, PasswordSource,
    ScoringConfig, Size,
};
use pqaudit_core::Tier;

const MINIMAL: &str = r#"
client = "Acme Corp"
assessor = "Jane Doe"

[deadlines]
profiles = ["au", "uk"]
sector = "government"

[assumptions]
crqc_year = 2035
"#;

fn write(dir: &Path, name: &str, text: &str) {
    fs::write(dir.join(name), text).unwrap();
}

#[test]
fn load_minimal_engagement() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.config.client, "Acme Corp");
    assert_eq!(e.config.assessor, "Jane Doe");
    assert_eq!(e.config.assessment_date, None);
    assert_eq!(e.config.deadlines.profiles, ["au", "uk"]);
    assert_eq!(e.config.deadlines.sector.as_deref(), Some("government"));
    assert_eq!(e.config.assumptions.crqc_year, 2035);
    assert!(e.config.passwords.is_none());
    assert_eq!(e.dir, dir.path());
}

#[test]
fn missing_optional_files_use_defaults() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.assets, AssetsFile::default());
    assert!(e.assets.asset.is_empty());
    assert_eq!(e.overrides, OverridesFile::default());
    assert_eq!(e.scoring, ScoringConfig::default());
}

#[test]
fn missing_engagement_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let error = Engagement::load(dir.path()).unwrap_err();
    assert!(matches!(error, EngagementError::Missing { .. }));
    assert!(error.to_string().contains("engagement.toml"), "{error}");
}

#[test]
fn scoring_defaults_match_spec() {
    let s = ScoringConfig::default();
    assert_eq!(s.weights.threat, 0.25);
    assert_eq!(s.weights.exposure, 0.20);
    assert_eq!(s.weights.sensitivity, 0.20);
    assert_eq!(s.weights.mosca, 0.15);
    assert_eq!(s.weights.deadline, 0.10);
    assert_eq!(s.weights.scale, 0.10);
    assert_eq!(s.classification.len(), 5);
    assert_eq!(s.classification["public"], 0.1);
    assert_eq!(s.classification["internal"], 0.4);
    assert_eq!(s.classification["confidential"], 0.7);
    assert_eq!(s.classification["secret"], 1.0);
    assert_eq!(s.classification["restricted"], 1.0);
    assert_eq!(s.bands.critical, 80.0);
    assert_eq!(s.bands.high, 60.0);
    assert_eq!(s.bands.medium, 40.0);
    assert_eq!(s.migration_years[&Size::S], 0.25);
    assert_eq!(s.migration_years[&Size::M], 0.5);
    assert_eq!(s.migration_years[&Size::L], 1.0);
    assert_eq!(s.migration_years[&Size::XL], 2.0);
}

#[test]
fn partial_scoring_file_keeps_other_defaults() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    write(
        dir.path(),
        "scoring.toml",
        "[weights]\nthreat = 0.5\nexposure = 0.1\nsensitivity = 0.1\nmosca = 0.1\ndeadline = 0.1\nscale = 0.1\n\n[migration_years]\nS = 1.0\nM = 2.0\nL = 3.0\nXL = 4.0\n",
    );
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.scoring.weights.threat, 0.5);
    assert_eq!(e.scoring.migration_years[&Size::XL], 4.0);
    assert_eq!(e.scoring.bands.critical, 80.0);
    assert_eq!(e.scoring.classification["secret"], 1.0);
}

#[test]
fn bad_toml_error_names_file_and_line() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    write(
        dir.path(),
        "assets.toml",
        "[[asset]]\nname = \"A\"\n\n[[asset]]\nname = = \"B\"\n",
    );
    let error = Engagement::load(dir.path()).unwrap_err();
    let text = error.to_string();
    assert!(text.contains("assets.toml"), "{text}");
    assert!(text.contains("line 5"), "{text}");
    assert!(matches!(error, EngagementError::Parse { line: 5, .. }));
}

#[test]
fn unknown_key_is_an_error_with_line() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "engagement.toml",
        "client = \"A\"\nassessor = \"B\"\nclient_name = \"C\"\n\n[assumptions]\ncrqc_year = 2035\n",
    );
    let text = Engagement::load(dir.path()).unwrap_err().to_string();
    assert!(text.contains("engagement.toml"), "{text}");
    assert!(text.contains("line 3"), "{text}");
}

#[test]
fn asset_match_key_parses() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    write(
        dir.path(),
        "assets.toml",
        r#"
[[asset]]
name = "Payments API"
business_unit = "Retail Banking"
match = { hosts = ["pay.acme.example"], cidrs = ["10.0.0.0/24"], paths = ["repos/**"] }
classification = "confidential"
data_lifespan_years = 10
exposure = "internet"
owner = "Payments Platform team"
vendor = false
priority_tier = "high"
hardware_constrained = false

[[asset]]
name = "Bare"
"#,
    );
    let e = Engagement::load(dir.path()).unwrap();
    let a = &e.assets.asset[0];
    assert_eq!(a.name, "Payments API");
    assert_eq!(a.matcher.hosts, ["pay.acme.example"]);
    assert_eq!(a.matcher.cidrs[0].to_string(), "10.0.0.0/24");
    assert_eq!(a.matcher.paths, ["repos/**"]);
    assert_eq!(a.exposure, Some(Exposure::Internet));
    assert_eq!(a.data_lifespan_years, Some(10));
    assert_eq!(a.priority_tier, Some(Tier::High));
    assert_eq!(a.hardware_constrained, Some(false));
    assert_eq!(a.vendor, Some(false));
    let bare = &e.assets.asset[1];
    assert!(bare.matcher.hosts.is_empty());
    assert_eq!(bare.exposure, None);
}

#[test]
fn overrides_parse() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    write(
        dir.path(),
        "overrides.toml",
        "[[override]]\nfingerprint = \"abc\"\npriority = \"low\"\nreason = \"Retired next year.\"\nby = \"Jane\"\ndate = 2026-10-20\n",
    );
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.overrides.r#override.len(), 1);
    assert_eq!(e.overrides.r#override[0].priority, Band::Low);
    assert_eq!(e.overrides.r#override[0].date.to_string(), "2026-10-20");
}

fn passwords_engagement(table: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "engagement.toml",
        &format!("client = \"A\"\nassessor = \"B\"\n\n[assumptions]\ncrqc_year = 2035\n\n[passwords]\n{table}"),
    );
    dir
}

#[test]
fn password_source_env_form() {
    let dir = passwords_engagement("env = \"PQAUDIT_PASSWORDS\"\n");
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(
        e.config.passwords,
        Some(PasswordSource::Env {
            env: "PQAUDIT_PASSWORDS".into()
        })
    );
}

#[test]
fn password_source_file_form() {
    let dir = passwords_engagement("file = \"pw.txt\"\n");
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(
        e.config.passwords,
        Some(PasswordSource::File {
            file: "pw.txt".into()
        })
    );
}

#[test]
fn password_source_with_both_keys_is_an_error() {
    let dir = passwords_engagement("env = \"X\"\nfile = \"pw.txt\"\n");
    let text = Engagement::load(dir.path()).unwrap_err().to_string();
    assert!(text.contains("engagement.toml"), "{text}");
    assert!(text.contains("env") && text.contains("file"), "{text}");
    assert!(text.contains("only one"), "{text}");
}

#[test]
fn password_source_with_no_key_is_an_error() {
    let dir = passwords_engagement("");
    let text = Engagement::load(dir.path()).unwrap_err().to_string();
    assert!(text.contains("engagement.toml"), "{text}");
    assert!(text.contains("env") && text.contains("file"), "{text}");
    assert!(text.contains("needs"), "{text}");
}

#[test]
fn password_source_stray_key_is_an_error_with_line() {
    let dir = passwords_engagement("env = \"X\"\npassword = \"secret\"\n");
    let text = Engagement::load(dir.path()).unwrap_err().to_string();
    assert!(text.contains("engagement.toml"), "{text}");
    assert!(text.contains("line 9"), "{text}");
    assert!(!text.contains("secret"), "{text}");
}

#[test]
fn assessment_date_parses_and_bad_date_has_line() {
    let dir = tempfile::tempdir().unwrap();
    let base = "client = \"A\"\nassessor = \"B\"\n";
    let tail = "\n[assumptions]\ncrqc_year = 2035\n";
    write(
        dir.path(),
        "engagement.toml",
        &format!("{base}assessment_date = 2026-10-20\n{tail}"),
    );
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.config.assessment_date.unwrap().to_string(), "2026-10-20");
    write(
        dir.path(),
        "engagement.toml",
        &format!("{base}assessment_date = \"soon\"\n{tail}"),
    );
    let text = Engagement::load(dir.path()).unwrap_err().to_string();
    assert!(text.contains("line 3"), "{text}");
}

/// Load an engagement with this `scoring.toml` text and return the error text.
fn scoring_error(text: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    write(dir.path(), "scoring.toml", text);
    Engagement::load(dir.path()).unwrap_err().to_string()
}

#[test]
fn all_zero_weights_are_rejected() {
    let text = scoring_error("[weights]\nthreat = 0\nexposure = 0\nsensitivity = 0\nmosca = 0\ndeadline = 0\nscale = 0\n");
    assert!(text.contains("scoring.toml"), "{text}");
    assert!(text.contains("weights"), "{text}");
    assert!(text.contains("more than 0"), "{text}");
}

#[test]
fn negative_weight_is_rejected() {
    let text = scoring_error("[weights]\nthreat = -0.1\n");
    assert!(text.contains("weights.threat"), "{text}");
    assert!(text.contains("0 or more"), "{text}");
}

#[test]
fn nan_weight_is_rejected() {
    let text = scoring_error("[weights]\nmosca = nan\n");
    assert!(text.contains("weights.mosca"), "{text}");
    assert!(text.contains("0 or more"), "{text}");
}

#[test]
fn classification_value_above_one_is_rejected() {
    let text = scoring_error("[classification]\nsecret = 2.0\n");
    assert!(text.contains("classification.secret"), "{text}");
    assert!(text.contains("0 to 1"), "{text}");
}

#[test]
fn unordered_bands_are_rejected() {
    let text = scoring_error("[bands]\ncritical = 50\nhigh = 60\nmedium = 40\n");
    assert!(text.contains("bands.critical"), "{text}");
    let text = scoring_error("[bands]\ncritical = 80\nhigh = 40\nmedium = 40\n");
    assert!(text.contains("bands.high"), "{text}");
    let text = scoring_error("[bands]\ncritical = 180\n");
    assert!(text.contains("bands"), "{text}");
    assert!(text.contains("0 to 100"), "{text}");
}

#[test]
fn bad_migration_time_is_rejected() {
    let text = scoring_error("[migration_years]\nM = 0\n");
    assert!(text.contains("migration_years.M"), "{text}");
    assert!(text.contains("more than 0"), "{text}");
    let text = scoring_error("[migration_years]\nL = nan\n");
    assert!(text.contains("migration_years.L"), "{text}");
    assert!(text.contains("finite number"), "{text}");
}

#[test]
fn overflowing_weight_sum_is_rejected() {
    let text = scoring_error("[weights]\nthreat = 1e308\nexposure = 1e308\n");
    assert!(text.contains("The key weights "), "{text}");
    assert!(text.contains("sum of the weights"), "{text}");
}

#[test]
fn max_pkcs12_work_has_a_default_and_must_be_positive() {
    use pqaudit_core::engagement::DEFAULT_MAX_PKCS12_WORK;
    assert_eq!(DEFAULT_MAX_PKCS12_WORK, 5_000_000);
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "engagement.toml", MINIMAL);
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.config.max_pkcs12_work, DEFAULT_MAX_PKCS12_WORK);

    let base = "client = \"A\"\nassessor = \"B\"\n";
    let tail = "\n[assumptions]\ncrqc_year = 2035\n";
    write(
        dir.path(),
        "engagement.toml",
        &format!("{base}max_pkcs12_work = 20000000\n{tail}"),
    );
    let e = Engagement::load(dir.path()).unwrap();
    assert_eq!(e.config.max_pkcs12_work, 20_000_000);

    for value in ["0", "-1", "\"many\""] {
        write(
            dir.path(),
            "engagement.toml",
            &format!("{base}max_pkcs12_work = {value}\n{tail}"),
        );
        let text = Engagement::load(dir.path()).unwrap_err().to_string();
        assert!(text.contains("line 3"), "{value}: {text}");
        assert!(
            text.contains(pqaudit_core::messages::PKCS12_WORK_POSITIVE),
            "{value}: {text}"
        );
    }
}
