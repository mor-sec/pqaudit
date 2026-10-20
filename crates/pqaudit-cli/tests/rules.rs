//! Tests of the `rules` command.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use pqaudit_rules::archive::build_archive;
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::signing::HybridSigningKey;
use predicates::prelude::*;

/// A scratch directory, a data directory, a trust file, and a signing key.
struct Fixture {
    dir: tempfile::TempDir,
    key: HybridSigningKey,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Fixture {
            dir: tempfile::tempdir().unwrap(),
            key: HybridSigningKey::generate().unwrap(),
        };
        let (ed, ml) = fixture.key.public_pems().unwrap();
        let id = fixture.key.public_key().key_id();
        let trust = format!(
            "revoked = []\n[[key]]\nid = \"{id}\"\ned25519_spki_pem = '''{ed}'''\nml_dsa_65_spki_pem = '''{ml}'''\n"
        );
        fs::write(fixture.path("trust.toml"), trust).unwrap();
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn pqaudit(&self) -> Command {
        let mut cmd = Command::cargo_bin("pqaudit").expect("the pqaudit binary exists");
        cmd.env("PQAUDIT_DATA_DIR", self.path("data"))
            .env("PQAUDIT_TEST_TRUST_FILE", self.path("trust.toml"));
        cmd
    }

    /// Write a pack archive. Return its path.
    fn archive(&self, version: &str) -> PathBuf {
        let bytes = build_archive(vec![
            (
                "pack.toml".into(),
                format!("id = \"test\"\nversion = \"{version}\"\n").into_bytes(),
            ),
            ("algorithms.yaml".into(), b"[]\n".to_vec()),
        ])
        .unwrap();
        let path = self.path(&format!("rules-{version}.tar.zst"));
        fs::write(&path, bytes).unwrap();
        path
    }

    /// Sign an archive with a key. The signature goes to `<archive>.sig.json`.
    fn sign_with(&self, archive: &Path, key: &HybridSigningKey) {
        let sig = key.sign(&fs::read(archive).unwrap());
        let mut name = archive.as_os_str().to_os_string();
        name.push(".sig.json");
        fs::write(name, sig.to_json()).unwrap();
    }
}

#[test]
fn rules_verify_good_pack_exit_0() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.sign_with(&archive, &fx.key);
    fx.pqaudit()
        .args(["rules", "verify"])
        .arg(&archive)
        .assert()
        .code(0)
        .stdout(predicate::str::contains(fx.key.public_key().key_id()));
}

#[test]
fn rules_verify_unsigned_or_bad_pack_exit_1() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    // No signature file.
    fx.pqaudit()
        .args(["rules", "verify"])
        .arg(&archive)
        .assert()
        .code(1);
    // A signature of another key.
    fx.sign_with(&archive, &HybridSigningKey::generate().unwrap());
    fx.pqaudit()
        .args(["rules", "verify"])
        .arg(&archive)
        .assert()
        .code(1);
}

#[test]
fn rules_verify_accepts_an_explicit_signature_path() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.sign_with(&archive, &fx.key);
    let moved = fx.path("elsewhere.json");
    fs::rename(fx.path("rules-99.0.0.tar.zst.sig.json"), &moved).unwrap();
    fx.pqaudit()
        .args(["rules", "verify"])
        .arg(&archive)
        .arg("--sig")
        .arg(&moved)
        .assert()
        .code(0);
}

#[test]
fn rules_update_good_pack_installs_and_list_shows_it() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.sign_with(&archive, &fx.key);
    fx.pqaudit()
        .args(["rules", "update", "--from"])
        .arg(&archive)
        .assert()
        .code(0);
    assert!(fx.path("data/rules/99.0.0/rules-99.0.0.tar.zst").is_file());
    fx.pqaudit()
        .args(["rules", "list"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("99.0.0"))
        .stdout(predicate::str::contains("installed"));
}

#[test]
fn rules_update_bad_sig_exit_1() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.sign_with(&archive, &HybridSigningKey::generate().unwrap());
    fx.pqaudit()
        .args(["rules", "update", "--from"])
        .arg(&archive)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("trust list"));
    assert!(!fx.path("data").exists());
}

#[test]
fn rules_update_unsigned_without_flag_exit_1() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.pqaudit()
        .args(["rules", "update", "--from"])
        .arg(&archive)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--allow-unsigned-rules"));
    assert!(!fx.path("data").exists());
}

#[test]
fn rules_update_unsigned_with_flag_installs_and_warns() {
    let fx = Fixture::new();
    let archive = fx.archive("99.0.0");
    fx.pqaudit()
        .args(["--allow-unsigned-rules", "rules", "update", "--from"])
        .arg(&archive)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("Warning"));
    assert!(fx.path("data/rules/99.0.0/rules-99.0.0.tar.zst").is_file());
    // Without the flag, the program does not use the pack.
    fx.pqaudit()
        .args(["rules", "list"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("active  test 99.0.0").not());
    fx.pqaudit()
        .args(["--allow-unsigned-rules", "rules", "list"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("active").and(predicate::str::contains("unsigned")));
}

#[test]
fn rules_update_junk_archive_exit_1_even_with_flag() {
    let fx = Fixture::new();
    let junk = fx.path("junk.tar.zst");
    fs::write(&junk, b"junk").unwrap();
    fx.pqaudit()
        .args(["--allow-unsigned-rules", "rules", "update", "--from"])
        .arg(&junk)
        .assert()
        .code(1);
}

#[test]
fn rules_list_shows_embedded() {
    let fx = Fixture::new();
    let pack = default_pack();
    fx.pqaudit()
        .args(["rules", "list"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains(pack.version.to_string()))
        .stdout(predicate::str::contains("embedded"))
        .stdout(predicate::str::contains(&pack.content_hash));
}
