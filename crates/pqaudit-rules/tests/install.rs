//! Tests of the installation and the choice of the active rules pack.

use std::fs;
use std::path::Path;

use pqaudit_rules::archive::build_archive;
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::install::{InstallError, InstalledState, PackOrigin, RulesStore};
use pqaudit_rules::signing::HybridSigningKey;
use pqaudit_rules::verify::TrustStore;

fn archive_of(version: &str) -> Vec<u8> {
    build_archive(vec![
        (
            "pack.toml".into(),
            format!("id = \"test\"\nversion = \"{version}\"\n").into_bytes(),
        ),
        ("algorithms.yaml".into(), b"[]\n".to_vec()),
    ])
    .unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    key: HybridSigningKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Fixture {
            root: dir.path().join("data"),
            _dir: dir,
            key: HybridSigningKey::generate().unwrap(),
        }
    }
    fn store(&self) -> RulesStore {
        RulesStore::new(
            self.root.clone(),
            TrustStore::new(vec![self.key.public_key()], vec![]),
        )
    }
    /// Write a signed archive and its signature in the scratch directory.
    fn signed(&self, version: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let archive = archive_of(version);
        let path = self
            .root
            .parent()
            .unwrap()
            .join(format!("in-{version}.tar.zst"));
        fs::write(&path, &archive).unwrap();
        let sig = self
            .root
            .parent()
            .unwrap()
            .join(format!("in-{version}.sig.json"));
        fs::write(&sig, self.key.sign(&archive).to_json()).unwrap();
        (path, sig)
    }
}

fn installed_files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn install_keeps_archive_and_signature() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let dir = fx.store().install(&archive, &sig).unwrap();
    assert!(dir.ends_with("rules/99.0.0"));
    assert_eq!(
        installed_files(&dir),
        ["rules-99.0.0.tar.zst", "rules-99.0.0.tar.zst.sig.json"]
    );
}

#[test]
fn install_with_bad_signature_changes_nothing() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let other = HybridSigningKey::generate().unwrap();
    fs::write(&sig, other.sign(&fs::read(&archive).unwrap()).to_json()).unwrap();
    let result = fx.store().install(&archive, &sig);
    assert!(matches!(result, Err(InstallError::Verify(_))), "{result:?}");
    assert!(!fx.root.join("rules").exists());
}

#[test]
fn active_pack_prefers_a_newer_installed_pack() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let store = fx.store();
    store.install(&archive, &sig).unwrap();
    let active = store.active_pack(false).unwrap();
    assert_eq!(active.pack.version.to_string(), "99.0.0");
    match active.origin {
        PackOrigin::Installed {
            signed_by,
            rotation_chain,
            ..
        } => {
            assert_eq!(signed_by, fx.key.public_key().key_id());
            assert_eq!(rotation_chain, vec![signed_by]);
        }
        other => panic!("wrong origin: {other:?}"),
    }
    match &store.list_installed(false)[0].state {
        InstalledState::Verified { rotation_chain, .. } => assert_eq!(rotation_chain.len(), 1),
        other => panic!("wrong state: {other:?}"),
    }
}

#[test]
fn active_pack_ignores_an_older_installed_pack() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("0.0.1");
    let store = fx.store();
    store.install(&archive, &sig).unwrap();
    let active = store.active_pack(false).unwrap();
    assert_eq!(active.pack.version, default_pack().version);
    assert!(matches!(active.origin, PackOrigin::Embedded));
}

#[test]
fn installed_pack_is_checked_again_when_it_loads() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let store = fx.store();
    let dir = store.install(&archive, &sig).unwrap();
    // Change the installed archive. The signature no longer fits.
    fs::write(
        dir.join("rules-99.0.0.tar.zst"),
        archive_of("99.0.0").into_iter().rev().collect::<Vec<_>>(),
    )
    .unwrap();
    let active = store.active_pack(false).unwrap();
    assert!(matches!(active.origin, PackOrigin::Embedded));
    // The same change is also not accepted as "unsigned" without the flag.
    let listed = store.list_installed(false);
    assert_eq!(listed.len(), 1);
    assert!(!matches!(listed[0].state, InstalledState::Verified { .. }));
    let loose = store.active_pack(true).unwrap();
    assert!(!matches!(loose.origin, PackOrigin::Installed { .. }));
}

#[test]
fn revoked_key_stops_an_installed_pack() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    fx.store().install(&archive, &sig).unwrap();
    let revoked = RulesStore::new(
        fx.root.clone(),
        TrustStore::new(
            vec![fx.key.public_key()],
            vec![fx.key.public_key().key_id()],
        ),
    );
    let active = revoked.active_pack(false).unwrap();
    assert!(matches!(active.origin, PackOrigin::Embedded));
}

#[test]
fn unsigned_install_needs_the_flag_to_be_active() {
    let fx = Fixture::new();
    let path = fx.root.parent().unwrap().join("plain.tar.zst");
    fs::write(&path, archive_of("99.0.0")).unwrap();
    let store = fx.store();
    let dir = store.install_unsigned(&path).unwrap();
    assert_eq!(installed_files(&dir), ["rules-99.0.0.tar.zst"]);
    let without = store.active_pack(false).unwrap();
    assert!(matches!(without.origin, PackOrigin::Embedded));
    let with = store.active_pack(true).unwrap();
    assert!(matches!(with.origin, PackOrigin::Unsigned { .. }));
    assert_eq!(with.pack.version.to_string(), "99.0.0");
}

#[test]
fn unsigned_install_rejects_a_bad_archive() {
    let fx = Fixture::new();
    let path = fx.root.parent().unwrap().join("junk.tar.zst");
    fs::write(&path, b"junk").unwrap();
    assert!(fx.store().install_unsigned(&path).is_err());
}

#[test]
fn install_replaces_the_same_version() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let store = fx.store();
    store.install(&archive, &sig).unwrap();
    store.install(&archive, &sig).unwrap();
    assert_eq!(store.list_installed(false).len(), 1);
}

#[test]
fn data_dir_uses_the_environment_variable() {
    // This test is the only one that changes the environment.
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("PQAUDIT_DATA_DIR", dir.path());
    let root = pqaudit_rules::install::data_root().unwrap();
    std::env::remove_var("PQAUDIT_DATA_DIR");
    assert_eq!(root, dir.path());
}

#[test]
fn rotation_chain_survives_into_the_active_pack() {
    use pqaudit_rules::signing::make_rotation;
    let dir = tempfile::tempdir().unwrap();
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let c = HybridSigningKey::generate().unwrap();
    let mut files = vec![
        (
            "pack.toml".to_string(),
            b"id = \"test\"\nversion = \"99.0.0\"\n".to_vec(),
        ),
        ("algorithms.yaml".to_string(), b"[]\n".to_vec()),
    ];
    for (index, (old, new)) in [(&a, &b), (&b, &c)].iter().enumerate() {
        let (statement, sig) = make_rotation(old, &new.public_key(), "2026-10-20").unwrap();
        files.push((format!("rotations/{:03}.json", index + 1), statement));
        files.push((
            format!("rotations/{:03}.json.sig.json", index + 1),
            sig.to_json().into_bytes(),
        ));
    }
    let archive = build_archive(files).unwrap();
    let archive_path = dir.path().join("in.tar.zst");
    let sig_path = dir.path().join("in.sig.json");
    fs::write(&archive_path, &archive).unwrap();
    fs::write(&sig_path, c.sign(&archive).to_json()).unwrap();
    // Only A is in the trust list.
    let store = RulesStore::new(
        dir.path().join("data"),
        TrustStore::new(vec![a.public_key()], vec![]),
    );
    store.install(&archive_path, &sig_path).unwrap();
    let expected: Vec<String> = [&a, &b, &c]
        .iter()
        .map(|k| k.public_key().key_id())
        .collect();
    match store.active_pack(false).unwrap().origin {
        PackOrigin::Installed {
            signed_by,
            rotation_chain,
            ..
        } => {
            assert_eq!(signed_by, expected[2]);
            assert_eq!(rotation_chain, expected);
        }
        other => panic!("wrong origin: {other:?}"),
    }
}

#[test]
fn active_pack_reports_each_skipped_installed_pack() {
    let fx = Fixture::new();
    let store = fx.store();
    // An unsigned pack.
    let plain = fx.root.parent().unwrap().join("plain.tar.zst");
    fs::write(&plain, archive_of("97.0.0")).unwrap();
    store.install_unsigned(&plain).unwrap();
    // A pack with a bad signature.
    let (archive, sig) = fx.signed("98.0.0");
    let other = HybridSigningKey::generate().unwrap();
    fs::write(&sig, other.sign(&fs::read(&archive).unwrap()).to_json()).unwrap();
    let bad_dir = fx.root.join("rules").join("98.0.0");
    fs::create_dir_all(&bad_dir).unwrap();
    fs::copy(&archive, bad_dir.join("rules-98.0.0.tar.zst")).unwrap();
    fs::copy(&sig, bad_dir.join("rules-98.0.0.tar.zst.sig.json")).unwrap();
    // A pack that the tool cannot load.
    let junk_dir = fx.root.join("rules").join("99.0.0");
    fs::create_dir_all(&junk_dir).unwrap();
    fs::write(junk_dir.join("rules-99.0.0.tar.zst"), b"junk").unwrap();

    let strict = store.active_pack(false).unwrap();
    assert!(matches!(strict.origin, PackOrigin::Embedded));
    let versions: Vec<&str> = strict.skipped.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions, ["97.0.0", "98.0.0", "99.0.0"]);
    assert!(strict.skipped.iter().all(|s| !s.reason.is_empty()));

    // With the flag, the tool uses the unsigned packs. It still skips the invalid pack.
    let loose = store.active_pack(true).unwrap();
    assert!(matches!(loose.origin, PackOrigin::Unsigned { .. }));
    let versions: Vec<&str> = loose.skipped.iter().map(|s| s.version.as_str()).collect();
    assert_eq!(versions, ["99.0.0"]);
}

#[test]
fn active_pack_skips_nothing_when_all_packs_are_good() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let store = fx.store();
    store.install(&archive, &sig).unwrap();
    assert!(store.active_pack(false).unwrap().skipped.is_empty());
}

#[test]
fn failed_signature_does_not_parse_the_pack_without_the_flag() {
    let fx = Fixture::new();
    let (archive, sig) = fx.signed("99.0.0");
    let store = fx.store();
    let dir = store.install(&archive, &sig).unwrap();
    // Put an archive with YAML that is not valid in place of the signed one.
    let bad = build_archive(vec![
        (
            "pack.toml".into(),
            b"id = \"test\"\nversion = \"99.0.0\"\n".to_vec(),
        ),
        ("algorithms.yaml".into(), b"{ not: [valid yaml\n".to_vec()),
    ])
    .unwrap();
    fs::write(dir.join("rules-99.0.0.tar.zst"), &bad).unwrap();
    let parse_error = pqaudit_rules::verify::load_unverified(&bad)
        .unwrap_err()
        .to_string();

    let active = store.active_pack(false).unwrap();
    assert!(matches!(active.origin, PackOrigin::Embedded));
    assert_eq!(active.skipped.len(), 1, "{:?}", active.skipped);
    let reason = &active.skipped[0].reason;
    assert_ne!(reason, &parse_error, "the tool parsed the pack");
    assert!(!reason.contains("yaml"), "{reason}");
    assert!(reason.contains("signature"), "{reason}");
    let listed = store.list_installed(false);
    assert!(matches!(
        listed[0].state,
        InstalledState::SignatureFailed { .. }
    ));

    // With the flag, the tool reads the pack and finds the YAML error.
    let loose = store.active_pack(true).unwrap();
    assert_eq!(loose.skipped.len(), 1);
    assert_eq!(loose.skipped[0].reason, parse_error);
}
