//! Tests of the work limits for hostile PKCS#12 files.
//!
//! Each hostile file asks for much key derivation work. The scan must stop fast,
//! record an error, and count the file as not inspected.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pkcs5::der::Encode;
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_files::{scan, ScanOptions, ScanOutput};
use uuid::Uuid;
use zeroize::Zeroizing;

const TOO_MUCH_WORK: &str = "The key store asks for too much work. The tool did not open it.";

const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
const OID_SHROUDED_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
];
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_SCRYPT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// An Ed25519 private key in PKCS#8. The library can read it after decryption.
const ED25519_PKCS8: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn octets(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

fn int(value: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = value
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect();
    if bytes.first().is_none_or(|byte| byte & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn explicit(content: &[u8]) -> Vec<u8> {
    tlv(0xa0, content)
}

/// A PFX with these safes. A MAC with this iteration count is optional.
fn pfx(safes: &[Vec<u8>], mac_iterations: Option<u64>) -> Vec<u8> {
    let auth_safe = seq(&[oid(OID_DATA), explicit(&octets(&seq(safes)))]);
    let mut parts = vec![int(3), auth_safe];
    if let Some(count) = mac_iterations {
        let digest = seq(&[seq(&[oid(OID_SHA256), tlv(0x05, &[])]), octets(&[0; 32])]);
        parts.push(seq(&[digest, octets(&[7; 16]), int(count)]));
    }
    seq(&parts)
}

fn data_safe(bags: &[Vec<u8>]) -> Vec<u8> {
    seq(&[oid(OID_DATA), explicit(&octets(&seq(bags)))])
}

fn encrypted_safe(algorithm: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let info = seq(&[oid(OID_DATA), algorithm.to_vec(), tlv(0x80, ciphertext)]);
    seq(&[oid(OID_ENCRYPTED_DATA), explicit(&seq(&[int(0), info]))])
}

fn shrouded_bag(algorithm: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    seq(&[
        oid(OID_SHROUDED_KEY_BAG),
        explicit(&seq(&[algorithm.to_vec(), octets(ciphertext)])),
    ])
}

/// PBES2 with PBKDF2-SHA256 and AES-256-CBC. Encrypt the data with the empty password.
fn pbes2(iterations: u32, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let params =
        pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(iterations, &[9; 16], [3; 16])
            .unwrap();
    let ciphertext = params.encrypt("", plaintext).unwrap();
    let algorithm = seq(&[oid(OID_PBES2), params.to_der().unwrap()]);
    (algorithm, ciphertext)
}

/// PBES2 with scrypt and AES-256-CBC. The cost is N = 2^log_n, r = 8, p = 1.
fn scrypt_algorithm(log_n: u32) -> Vec<u8> {
    let kdf = seq(&[
        oid(OID_SCRYPT),
        seq(&[octets(&[5; 16]), int(1 << log_n), int(8), int(1)]),
    ]);
    let encryption = seq(&[oid(OID_AES256_CBC), octets(&[4; 16])]);
    seq(&[oid(OID_PBES2), seq(&[kdf, encryption])])
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// Scan the paths. Return the output and the time of the scan.
fn timed_scan(paths: &[PathBuf], options: &ScanOptions) -> (ScanOutput, Duration) {
    let start = Instant::now();
    let output = scan(paths, options, default_pack(), Uuid::new_v4());
    (output, start.elapsed())
}

/// Check that the scan of one hostile file is fast, gives the error, and counts no read.
fn assert_refused(bytes: &[u8], what: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "hostile.p12", bytes);
    let (output, elapsed) = timed_scan(&[path], &ScanOptions::default());
    assert!(elapsed < Duration::from_secs(1), "{what}: {elapsed:?}");
    assert_eq!(output.errors.len(), 1, "{what}: {:?}", output.errors);
    assert_eq!(output.errors[0].reason, TOO_MUCH_WORK, "{what}");
    assert!(output.errors[0].location.ends_with("hostile.p12"), "{what}");
    assert_eq!(output.files_read, 0, "{what}");
    assert_eq!(
        output.files_not_read, 1,
        "{what}: the file is not inspected"
    );
    assert!(output.findings.is_empty() && output.inventory.is_empty());
}

#[test]
fn huge_mac_iteration_count_is_refused() {
    // The library accepts 1 000 000 MAC iterations. The tool accepts 100 000.
    assert_refused(
        &pfx(&[data_safe(&[])], Some(1_000_000)),
        "1e6 MAC iterations",
    );
    assert_refused(
        &pfx(&[data_safe(&[])], Some(1 << 40)),
        "2^40 MAC iterations",
    );
}

#[test]
fn huge_bag_iteration_count_is_refused() {
    // The library accepts 1 000 000 PBKDF2 iterations. The tool accepts 100 000.
    let (_, ciphertext) = pbes2(1, ED25519_PKCS8);
    let params =
        pkcs5::pbes2::Parameters::generate_pbkdf2_sha256_aes256cbc(1_000_000, &[9; 16], [3; 16])
            .unwrap();
    let algorithm = seq(&[oid(OID_PBES2), params.to_der().unwrap()]);
    let bytes = pfx(&[data_safe(&[shrouded_bag(&algorithm, &ciphertext)])], None);
    assert_refused(&bytes, "1e6 PBKDF2 iterations");
}

#[test]
fn scrypt_is_refused() {
    let algorithm = scrypt_algorithm(20);
    let in_bag = pfx(&[data_safe(&[shrouded_bag(&algorithm, &[0; 48])])], None);
    assert_refused(&in_bag, "scrypt N=2^20 in a key bag");
    let in_safe = pfx(&[encrypted_safe(&algorithm, &[0; 48])], None);
    assert_refused(&in_safe, "scrypt N=2^20 in an encrypted safe");
}

#[test]
fn ten_thousand_bags_are_refused() {
    let (algorithm, ciphertext) = pbes2(2000, ED25519_PKCS8);
    let bag = shrouded_bag(&algorithm, &ciphertext);
    let bags = vec![bag; 10_000];
    assert_refused(&pfx(&[data_safe(&bags)], None), "10 000 key bags");
}

#[test]
fn bags_inside_an_encrypted_safe_count() {
    // Each bag is cheap. Twenty bags are more key derivations than the limit.
    let (bag_algorithm, bag_ciphertext) = pbes2(1, ED25519_PKCS8);
    let bags = vec![shrouded_bag(&bag_algorithm, &bag_ciphertext); 20];
    let (safe_algorithm, safe_ciphertext) = pbes2(1, &seq(&bags));
    let bytes = pfx(&[encrypted_safe(&safe_algorithm, &safe_ciphertext)], None);
    assert_refused(&bytes, "20 key bags in an encrypted safe");
}

#[test]
fn many_wrong_passwords_stop_at_the_file_limit() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/store-pw.p12");
    let options = ScanOptions {
        passwords: (0..1000)
            .map(|n| Zeroizing::new(format!("wrong-{n}")))
            .collect(),
        ..ScanOptions::default()
    };
    let (output, _) = timed_scan(&[fixture], &options);
    assert_eq!(output.errors.len(), 1, "{:?}", output.errors);
    assert_eq!(output.errors[0].reason, TOO_MUCH_WORK);
    assert_eq!(output.files_not_read, 1);
}

#[test]
fn normal_store_still_reads() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/store-empty.p12");
    let (output, _) = timed_scan(&[fixture], &ScanOptions::default());
    assert!(output.errors.is_empty(), "{:?}", output.errors);
    assert_eq!(output.files_read, 1);
    assert_eq!(output.findings.len(), 1);
}

#[test]
fn the_scan_budget_is_shared_by_all_files() {
    use pqaudit_scan_files::pkcs12::{scan_p12_with_budget, KdfBudget, StoreError};
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/store-empty.p12");
    let bytes = std::fs::read(&fixture).unwrap();
    // Find the cost of one file.
    let mut budget = KdfBudget::new(1_000_000);
    scan_p12_with_budget(&bytes, &[], &mut budget).unwrap();
    let cost = 1_000_000 - budget.remaining();
    assert!(cost > 0);
    // A budget for one file reads the first file only.
    let mut budget = KdfBudget::new(cost);
    scan_p12_with_budget(&bytes, &[], &mut budget).unwrap();
    assert_eq!(
        scan_p12_with_budget(&bytes, &[], &mut budget).unwrap_err(),
        StoreError::TooMuchWork
    );

    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = (0..3)
        .map(|n| write(dir.path(), &format!("copy-{n}.p12"), &bytes))
        .collect();
    let options = ScanOptions {
        max_kdf_work: cost,
        ..ScanOptions::default()
    };
    let (output, _) = timed_scan(&paths, &options);
    assert_eq!(output.files_read, 1);
    assert_eq!(output.files_not_read, 2);
    assert_eq!(output.errors.len(), 2, "{:?}", output.errors);
    assert!(output
        .errors
        .iter()
        .all(|error| error.reason == TOO_MUCH_WORK));
    // The default budget reads all three files.
    let (output, _) = timed_scan(&paths, &ScanOptions::default());
    assert_eq!(output.files_read, 3, "{:?}", output.errors);
}
