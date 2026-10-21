//! Tests of the cleaning of untrusted text.

use pqaudit_core::text::clean;

#[test]
fn control_characters_become_question_marks() {
    assert_eq!(clean("a\u{1b}[31mb\nc\r\t\u{7}d"), "a?[31mb?c???d");
    assert_eq!(clean("x\u{7f}\u{9b}y"), "x??y");
}

#[test]
fn printable_unicode_stays() {
    assert_eq!(
        clean("CN=Müller Straße, O=日本 ✓"),
        "CN=Müller Straße, O=日本 ✓"
    );
}

#[test]
fn bidirectional_controls_and_line_separators_become_question_marks() {
    assert_eq!(clean("a\u{202e}b\u{2066}c\u{2028}d"), "a?b?c?d");
}

#[test]
fn certificate_subject_with_escape_and_new_line_is_clean() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![String::from("x.test")]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("evil\u{1b}[2J\nname".to_string()),
    );
    let cert = params.self_signed(&key).unwrap();
    let info = pqaudit_core::x509::parse_certificate(cert.der(), 0).unwrap();
    for text in [&info.subject, &info.issuer] {
        assert!(!text.chars().any(char::is_control), "{text:?}");
        assert!(text.contains("evil?[2J?name"), "{text:?}");
    }
}
