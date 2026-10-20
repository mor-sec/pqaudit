//! Tests for the fingerprints.

use pqaudit_core::Fingerprint;

#[test]
fn fingerprint_endpoint_case_insensitive_host() {
    assert_eq!(
        Fingerprint::endpoint("Pay.Example", 443, "tls.no-pq-kex"),
        Fingerprint::endpoint("pay.example", 443, "tls.no-pq-kex")
    );
}

#[test]
fn fingerprint_distinct_kinds() {
    let x = "ab".repeat(32);
    assert_ne!(Fingerprint::cert(&x), Fingerprint::key(&x));
}

#[test]
fn fingerprint_stable_value() {
    let fp = Fingerprint::cert(&"00".repeat(32));
    assert_eq!(fp.0, "cert:b37e0623f2b152766c95e0219d23d29b");
}
