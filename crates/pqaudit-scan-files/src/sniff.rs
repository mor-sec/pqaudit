//! Find the format of a file from its name and its first bytes.

use std::path::Path;

use crate::pem::{self, BlockKind};
use crate::{der, privkey};
use crate::{gpg, jks, pkcs12, ssh};

/// The kind of key store file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum StoreKind {
    /// A PKCS#12 file.
    Pkcs12,
    /// A JKS or JCEKS file.
    Java,
}

/// The format of a file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Format {
    /// A key store with certificates and keys.
    Store(StoreKind),
    /// A file with a certificate name. It holds PEM text or one DER certificate.
    CertFile,
    /// Text with PEM blocks: certificates, keys, or both.
    Pem,
    /// Text with SSH public keys, one for each line.
    SshKeys,
    /// One key in DER form, for a file with no name that shows it.
    DerKey,
    /// OpenPGP keys, in binary form or as armor.
    Pgp,
    /// A GnuPG key box.
    Kbx,
}

/// Find the kind of key store from the first bytes of the file. Return `None` for other files.
fn store_by_content(head: &[u8]) -> Option<StoreKind> {
    if jks::has_jks_magic(head) {
        Some(StoreKind::Java)
    } else if pkcs12::looks_like_p12(head) {
        Some(StoreKind::Pkcs12)
    } else {
        None
    }
}

/// Find the format from the name of the file. Return `None` if the name says nothing.
pub(crate) fn by_name(path: &Path) -> Option<Format> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "authorized_keys" | "authorized_keys2" | "known_hosts" | "known_hosts2" | "ssh_known_hosts"
    ) {
        return Some(Format::SshKeys);
    }
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "p12" | "pfx" => Some(Format::Store(StoreKind::Pkcs12)),
        "jks" | "jceks" | "keystore" => Some(Format::Store(StoreKind::Java)),
        "pem" | "crt" | "cer" | "der" | "key" => Some(Format::CertFile),
        "kbx" => Some(Format::Kbx),
        _ => None,
    }
}

/// Find the format from the first bytes of a file. Return `None` for other files.
pub(crate) fn by_content(head: &[u8], key_extension: bool) -> Option<Format> {
    if let Some(kind) = store_by_content(head) {
        return Some(Format::Store(kind));
    }
    if pem::has_kind(head, BlockKind::Certificate) || pem::has_kind(head, BlockKind::Key) {
        return Some(Format::Pem);
    }
    if pem::has_pgp_key_armor(head) || gpg::looks_like_packets(head, !key_extension) {
        return Some(Format::Pgp);
    }
    if head.get(8..12) == Some(b"KBXf") {
        return Some(Format::Kbx);
    }
    if ssh::looks_like_keys(head) {
        return Some(Format::SshKeys);
    }
    // A short DER key can sit inside the start of the file. A bigger file never matches.
    (head.first() == Some(&der::SEQUENCE) && privkey::parse_der(head, "").is_ok())
        .then_some(Format::DerKey)
}

/// Return true if the file name suggests a key file but does not prove it.
///
/// The tool reads such a file only if the content matches a key format.
pub(crate) fn has_key_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        matches!(
            extension.to_string_lossy().to_ascii_lowercase().as_str(),
            "pub" | "gpg" | "pgp" | "asc"
        )
    })
}

/// Find the format of a file from its name and its first bytes.
///
/// A key store magic number in the content beats the name.
pub(crate) fn resolve(named: Option<Format>, head: &[u8], key_extension: bool) -> Option<Format> {
    if let Some(kind) = store_by_content(head) {
        return Some(Format::Store(kind));
    }
    named.or_else(|| by_content(head, key_extension))
}
