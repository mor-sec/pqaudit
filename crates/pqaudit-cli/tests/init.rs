//! Tests for the `init` command.

use assert_cmd::Command;
use pqaudit_core::engagement::Engagement;
use predicates::prelude::*;

fn pqaudit() -> Command {
    Command::cargo_bin("pqaudit").unwrap()
}

#[test]
fn init_creates_layout() {
    let parent = tempfile::tempdir().unwrap();
    pqaudit()
        .args(["init", "acme", "--dir"])
        .arg(parent.path())
        .assert()
        .code(0);
    let root = parent.path().join("acme");
    for file in [
        "engagement.toml",
        "scope.toml",
        "assets.toml",
        "overrides.toml",
        "scoring.toml",
    ] {
        assert!(root.join(file).is_file(), "{file} missing");
    }
    assert!(root.join("results").is_dir());
    assert!(root.join("reports").is_dir());
}

#[test]
fn init_refuses_non_empty_dir() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("acme");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("keep.txt"), "x").unwrap();
    pqaudit()
        .args(["init", "acme", "--dir"])
        .arg(parent.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("not empty"));
    assert!(!root.join("engagement.toml").exists());
    assert_eq!(std::fs::read_to_string(root.join("keep.txt")).unwrap(), "x");
}

#[test]
fn init_accepts_empty_existing_dir() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::create_dir(parent.path().join("acme")).unwrap();
    pqaudit()
        .args(["init", "acme", "--dir"])
        .arg(parent.path())
        .assert()
        .code(0);
}

#[test]
fn init_templates_load() {
    let parent = tempfile::tempdir().unwrap();
    pqaudit()
        .args(["init", "acme", "--dir"])
        .arg(parent.path())
        .assert()
        .code(0);
    let root = parent.path().join("acme");
    let path = root.join("engagement.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let text = text.replace("client = \"\"", "client = \"Acme Corp\"");
    assert!(text.contains("Acme Corp"), "template has no client key");
    std::fs::write(&path, text).unwrap();
    let engagement = Engagement::load(&root).unwrap();
    assert_eq!(engagement.config.client, "Acme Corp");
    // The scoring template shows the default values.
    assert_eq!(
        engagement.scoring,
        pqaudit_core::engagement::ScoringConfig::default()
    );
}
