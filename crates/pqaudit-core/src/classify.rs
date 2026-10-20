//! Rules that classify a certificate. The file scanner and the network scanner share them.

use chrono::{Duration, NaiveDate};
use pqaudit_rules::pack::{RulesPack, ThreatType};

use crate::finding::CertInfo;

/// The ID of the rule for a key that is too small.
pub const RULE_WEAK_KEY: &str = "cert.weak-key";
/// The ID of the rule for a weak signature hash.
pub const RULE_WEAK_SIG_HASH: &str = "cert.weak-sig-hash";
/// The ID of the rule for a key that a quantum computer can break.
pub const RULE_CLASSICAL_KEY: &str = "cert.classical-key";

/// The extended key usage name of code signing.
pub const EKU_CODE_SIGNING: &str = "codeSigning";

/// A validity longer than this number of days makes a certificate long-lived. It is 3 years.
const LONG_LIVED_DAYS: i64 = 3 * 365;

/// Classify a certificate with the rules of the pack.
///
/// Return the primary rule ID, the threat type, and the IDs of the other rules that match.
/// The priority is `cert.weak-key`, then `cert.weak-sig-hash`, then `cert.classical-key`.
/// Return `None` if no rule matches, for example for a post-quantum key.
/// The argument `_today` is for later use. No rule uses the date now.
pub fn classify_cert(
    cert: &CertInfo,
    pack: &RulesPack,
    _today: NaiveDate,
) -> Option<(String, ThreatType, Vec<String>)> {
    let fact = pack.algorithm(&cert.public_key.name);
    let weak_key = fact.is_some_and(|fact| {
        fact.weak_always
            || match (cert.public_key.key_bits, fact.weak_below_bits) {
                (Some(bits), Some(minimum)) => bits < minimum,
                _ => false,
            }
    });
    let weak_hash = has_weak_hash(&cert.signature_algorithm);
    let classical = fact.is_some_and(|fact| fact.quantum_vulnerable);

    let mut matches = Vec::new();
    if weak_key {
        matches.push(RULE_WEAK_KEY);
    }
    if weak_hash {
        matches.push(RULE_WEAK_SIG_HASH);
    }
    if classical {
        matches.push(RULE_CLASSICAL_KEY);
    }
    let (primary, rest) = matches.split_first()?;

    let threat = if weak_key || weak_hash {
        ThreatType::ClassicalWeakNow
    } else if is_long_lived(cert) {
        ThreatType::ForgeryLongLived
    } else {
        ThreatType::ForgeryShortLived
    };
    Some((
        (*primary).to_string(),
        threat,
        rest.iter().map(|id| (*id).to_string()).collect(),
    ))
}

/// Return true if the signature algorithm name shows SHA-1, MD5, MD4, or MD2.
fn has_weak_hash(signature_algorithm: &str) -> bool {
    let name = signature_algorithm.to_ascii_lowercase();
    ["sha1", "md5", "md4", "md2"]
        .iter()
        .any(|weak| name.contains(weak))
}

/// Return true if the certificate is a CA, signs code, or is valid for more than 3 years.
fn is_long_lived(cert: &CertInfo) -> bool {
    cert.is_ca
        || cert
            .ext_key_usage
            .iter()
            .any(|usage| usage == EKU_CODE_SIGNING)
        || cert.not_after - cert.not_before > Duration::days(LONG_LIVED_DAYS)
}
