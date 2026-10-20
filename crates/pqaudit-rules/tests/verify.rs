//! Tests of hybrid signatures, pack archives, and key rotation.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use pqaudit_rules::archive::build_archive;
use pqaudit_rules::signing::{make_rotation, HybridSigningKey};
use pqaudit_rules::verify::{verify_hybrid, verify_pack_archive, SigFile, TrustStore, VerifyError};

fn pack_files(version: &str) -> Vec<(String, Vec<u8>)> {
    vec![
        (
            "pack.toml".into(),
            format!("id = \"test\"\nversion = \"{version}\"\n").into_bytes(),
        ),
        ("algorithms.yaml".into(), b"[]\n".to_vec()),
        ("rules/empty.yaml".into(), b"[]\n".to_vec()),
    ]
}

fn trust_of(keys: &[&HybridSigningKey], revoked: &[&HybridSigningKey]) -> TrustStore {
    TrustStore::new(
        keys.iter().map(|k| k.public_key()).collect(),
        revoked.iter().map(|k| k.public_key().key_id()).collect(),
    )
}

/// Add rotation files to a pack. Each item is (old key, new key).
fn rotation_files(chain: &[(&HybridSigningKey, &HybridSigningKey)]) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for (index, (old, new)) in chain.iter().enumerate() {
        let (statement, sig) = make_rotation(old, &new.public_key(), "2026-10-20").unwrap();
        files.push((format!("rotations/{:03}.json", index + 1), statement));
        files.push((
            format!("rotations/{:03}.json.sig.json", index + 1),
            sig.to_json().into_bytes(),
        ));
    }
    files
}

fn change_sig(sig: &SigFile, ed: bool) -> SigFile {
    let mut bad = sig.clone();
    let field = if ed {
        &mut bad.ed25519
    } else {
        &mut bad.ml_dsa_65
    };
    let mut bytes = B64.decode(field.as_bytes()).unwrap();
    bytes[3] ^= 1;
    *field = B64.encode(bytes);
    bad
}

#[test]
fn valid_hybrid_sig_verifies() {
    let key = HybridSigningKey::generate().unwrap();
    let sig = key.sign(b"hello");
    assert_eq!(sig.key_id, key.public_key().key_id());
    verify_hybrid(b"hello", &sig, &key.public_key()).unwrap();
}

#[test]
fn key_id_is_hex_sha256_of_both_spki() {
    let key = HybridSigningKey::generate().unwrap();
    let public = key.public_key();
    let id = public.key_id();
    assert_eq!(id.len(), 64);
    assert!(id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}

#[test]
fn ed25519_only_tampered_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let sig = change_sig(&key.sign(b"hello"), true);
    let result = verify_hybrid(b"hello", &sig, &key.public_key());
    assert!(
        matches!(result, Err(VerifyError::BadSignature(_))),
        "{result:?}"
    );
}

#[test]
fn mldsa_only_tampered_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let sig = change_sig(&key.sign(b"hello"), false);
    let result = verify_hybrid(b"hello", &sig, &key.public_key());
    assert!(
        matches!(result, Err(VerifyError::BadSignature(_))),
        "{result:?}"
    );
}

#[test]
fn modified_data_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let sig = key.sign(b"hello");
    assert!(verify_hybrid(b"hellO", &sig, &key.public_key()).is_err());
}

#[test]
fn signature_of_another_key_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let other = HybridSigningKey::generate().unwrap();
    let sig = other.sign(b"hello");
    assert!(verify_hybrid(b"hello", &sig, &key.public_key()).is_err());
}

#[test]
fn wrong_format_or_bad_base64_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let mut sig = key.sign(b"hello");
    sig.format = "other/1".into();
    assert!(verify_hybrid(b"hello", &sig, &key.public_key()).is_err());
    let mut sig = key.sign(b"hello");
    sig.ml_dsa_65 = "not base64 !!".into();
    assert!(verify_hybrid(b"hello", &sig, &key.public_key()).is_err());
    let mut sig = key.sign(b"hello");
    sig.ed25519 = B64.encode([0u8; 10]);
    assert!(verify_hybrid(b"hello", &sig, &key.public_key()).is_err());
}

#[test]
fn sig_file_json_round_trip_and_unknown_field() {
    let key = HybridSigningKey::generate().unwrap();
    let sig = key.sign(b"x");
    let again = SigFile::parse(sig.to_json().as_bytes()).unwrap();
    assert_eq!(sig, again);
    let extra = sig.to_json().replace('{', "{\"extra\":1,");
    assert!(SigFile::parse(extra.as_bytes()).is_err());
}

#[test]
fn good_archive_verifies() {
    let key = HybridSigningKey::generate().unwrap();
    let archive = build_archive(pack_files("1.0.0")).unwrap();
    let sig = key.sign(&archive);
    let verified = verify_pack_archive(&archive, &sig, &trust_of(&[&key], &[])).unwrap();
    assert_eq!(verified.pack.version.to_string(), "1.0.0");
    assert_eq!(verified.signed_by, key.public_key().key_id());
    assert_eq!(verified.rotation_chain, vec![key.public_key().key_id()]);
}

#[test]
fn modified_archive_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let archive = build_archive(pack_files("1.0.0")).unwrap();
    let sig = key.sign(&archive);
    let mut other = archive.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    assert!(verify_pack_archive(&other, &sig, &trust_of(&[&key], &[])).is_err());
    let newer = build_archive(pack_files("9.0.0")).unwrap();
    assert!(verify_pack_archive(&newer, &sig, &trust_of(&[&key], &[])).is_err());
}

#[test]
fn unknown_key_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let stranger = HybridSigningKey::generate().unwrap();
    let archive = build_archive(pack_files("1.0.0")).unwrap();
    let sig = stranger.sign(&archive);
    let result = verify_pack_archive(&archive, &sig, &trust_of(&[&key], &[]));
    assert!(
        matches!(result, Err(VerifyError::UnknownKey(_))),
        "{result:?}"
    );
}

#[test]
fn revoked_trusted_key_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let archive = build_archive(pack_files("1.0.0")).unwrap();
    let sig = key.sign(&archive);
    let result = verify_pack_archive(&archive, &sig, &trust_of(&[&key], &[&key]));
    assert!(matches!(result, Err(VerifyError::Revoked(_))), "{result:?}");
}

#[test]
fn rotation_chain_accepts_new_key() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let archive = build_archive(files).unwrap();
    let sig = b.sign(&archive);
    let verified = verify_pack_archive(&archive, &sig, &trust_of(&[&a], &[])).unwrap();
    assert_eq!(
        verified.rotation_chain,
        vec![a.public_key().key_id(), b.public_key().key_id()]
    );
    assert_eq!(verified.signed_by, b.public_key().key_id());
    // The rotation files are not part of the pack content.
    let plain = build_archive(pack_files("1.1.0")).unwrap();
    let plain_pack = verify_pack_archive(&plain, &a.sign(&plain), &trust_of(&[&a], &[])).unwrap();
    assert_eq!(verified.pack.content_hash, plain_pack.pack.content_hash);
}

#[test]
fn rotation_chain_with_two_steps() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let c = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b), (&b, &c)]));
    let archive = build_archive(files).unwrap();
    let verified = verify_pack_archive(&archive, &c.sign(&archive), &trust_of(&[&a], &[])).unwrap();
    assert_eq!(verified.rotation_chain.len(), 3);
}

#[test]
fn pack_signed_by_key_before_chain_end_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let archive = build_archive(files).unwrap();
    assert!(verify_pack_archive(&archive, &a.sign(&archive), &trust_of(&[&a], &[])).is_err());
}

#[test]
fn rotation_from_revoked_key_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let archive = build_archive(files).unwrap();
    let result = verify_pack_archive(&archive, &b.sign(&archive), &trust_of(&[&a], &[&a]));
    assert!(matches!(result, Err(VerifyError::Revoked(_))), "{result:?}");
}

#[test]
fn rotation_to_revoked_key_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let archive = build_archive(files).unwrap();
    let result = verify_pack_archive(&archive, &b.sign(&archive), &trust_of(&[&a], &[&b]));
    assert!(matches!(result, Err(VerifyError::Revoked(_))), "{result:?}");
}

#[test]
fn rotation_not_signed_by_old_key_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let evil = HybridSigningKey::generate().unwrap();
    // The statement names A as the old key, but the evil key signs it.
    let (statement, _) = make_rotation(&a, &b.public_key(), "2026-10-20").unwrap();
    let forged = evil.sign(&statement);
    let mut files = pack_files("1.1.0");
    files.push(("rotations/001.json".into(), statement));
    files.push((
        "rotations/001.json.sig.json".into(),
        forged.to_json().into_bytes(),
    ));
    let archive = build_archive(files).unwrap();
    let result = verify_pack_archive(&archive, &b.sign(&archive), &trust_of(&[&a], &[]));
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn rotation_from_untrusted_start_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let trusted = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let archive = build_archive(files).unwrap();
    let result = verify_pack_archive(&archive, &b.sign(&archive), &trust_of(&[&trusted], &[]));
    assert!(
        matches!(result, Err(VerifyError::UnknownKey(_))),
        "{result:?}"
    );
}

#[test]
fn rotation_with_missing_signature_or_gap_fails() {
    let a = HybridSigningKey::generate().unwrap();
    let b = HybridSigningKey::generate().unwrap();
    let trust = trust_of(&[&a], &[]);
    let mut files = pack_files("1.1.0");
    files.extend(rotation_files(&[(&a, &b)]));
    let without_sig: Vec<_> = files
        .iter()
        .filter(|(name, _)| !name.ends_with(".sig.json"))
        .cloned()
        .collect();
    let archive = build_archive(without_sig).unwrap();
    assert!(verify_pack_archive(&archive, &b.sign(&archive), &trust).is_err());
    let gap: Vec<_> = files
        .iter()
        .map(|(name, bytes)| (name.replace("001", "002"), bytes.clone()))
        .collect();
    let archive = build_archive(gap).unwrap();
    assert!(verify_pack_archive(&archive, &b.sign(&archive), &trust).is_err());
}

#[test]
fn trust_directory_in_archive_fails() {
    let key = HybridSigningKey::generate().unwrap();
    let mut files = pack_files("1.0.0");
    files.push(("trust/keys.toml".into(), b"revoked = []\n".to_vec()));
    let archive = build_archive(files).unwrap();
    let result = verify_pack_archive(&archive, &key.sign(&archive), &trust_of(&[&key], &[]));
    assert!(matches!(result, Err(VerifyError::Archive(_))), "{result:?}");
}

#[test]
fn bad_archive_bytes_fail() {
    let key = HybridSigningKey::generate().unwrap();
    let junk = b"this is not an archive".to_vec();
    let result = verify_pack_archive(&junk, &key.sign(&junk), &trust_of(&[&key], &[]));
    assert!(matches!(result, Err(VerifyError::Archive(_))), "{result:?}");
}

#[test]
fn archive_with_bad_path_fails() {
    assert!(build_archive(vec![("../evil.yaml".into(), vec![])]).is_err());
    assert!(build_archive(vec![("/abs.yaml".into(), vec![])]).is_err());
}

#[test]
fn archive_build_is_deterministic() {
    let mut reversed = pack_files("1.0.0");
    reversed.reverse();
    assert_eq!(
        build_archive(pack_files("1.0.0")).unwrap(),
        build_archive(reversed).unwrap()
    );
}

#[test]
fn trust_store_parses_toml_and_checks_ids() {
    let key = HybridSigningKey::generate().unwrap();
    let pems = key.public_pems().unwrap();
    let id = key.public_key().key_id();
    let toml = format!(
        "revoked = [\"{r}\"]\n\n[[key]]\nid = \"{id}\"\ned25519_spki_pem = '''{ed}'''\nml_dsa_65_spki_pem = '''{ml}'''\n",
        r = "0".repeat(64),
        ed = pems.0,
        ml = pems.1,
    );
    let store = TrustStore::from_toml(&toml).unwrap();
    assert!(store.is_trusted(&id));
    assert!(store.is_revoked(&"0".repeat(64)));
    let wrong = toml.replace(&id, &"1".repeat(64));
    assert!(TrustStore::from_toml(&wrong).is_err());
}

#[test]
fn builtin_trust_store_loads() {
    let store = TrustStore::builtin();
    assert!(store.key_count() >= 1);
}
