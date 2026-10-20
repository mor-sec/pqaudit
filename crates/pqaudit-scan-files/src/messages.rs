//! User-facing text of this crate.

/// The error for a path that the tool cannot read. The tool fills in {reason}.
pub const CANNOT_READ: &str = "The tool cannot read this path. {reason}";

/// The error for a symbolic link loop.
pub const SYMLINK_LOOP: &str = "This path is in a loop of symbolic links. The tool skips it.";

/// The error for a file that is larger than the limit. The tool fills in {limit}.
pub const TOO_LARGE: &str =
    "The file is too large. The limit is {limit} bytes. The tool skips the file.";

/// The note for a file name that is not valid UTF-8.
pub const NAME_NOT_UTF8: &str =
    "The file name is not valid UTF-8. The results show a changed name. The tool scans the file.";

/// The error for a file that has no certificate data.
pub const NO_CERTIFICATE: &str = "The file has no certificate data in a known format.";

/// The error for a DER file that is not a valid certificate.
pub const DER_INVALID: &str = "The file is not a valid DER certificate.";

/// The error for a PEM file with bad blocks. The tool fills in {bad}, {total}, and {reason}.
pub const PEM_BLOCKS_INVALID: &str =
    "{bad} of {total} certificate blocks are not valid. The first problem: {reason}";

/// The reason for a PEM block that has no end line.
pub const PEM_NOT_CLOSED: &str = "A certificate block has no end line.";

/// The reason for a PEM block with bad base64 text.
pub const PEM_BAD_BASE64: &str = "A certificate block has bad base64 text.";

/// The reason for certificate data that the parser rejects.
pub const CERT_INVALID: &str = "The certificate data is not valid.";

/// The reason for a public key type that the tool does not know. The tool fills in {oid}.
pub const UNKNOWN_KEY: &str =
    "The certificate has a public key type that the tool does not know. The OID is {oid}.";

/// The note for symbolic links that the tool skipped. The tool fills in {count}.
pub const SYMLINKS_SKIPPED: &str =
    "The tool skipped {count} symbolic links. Use the flag --follow-symlinks to scan them.";

/// The text of the evidence for a certificate. The tool fills in {subject} and {position}.
pub const EVIDENCE: &str = "Certificate {subject}, chain position {position}.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("CANNOT_READ", CANNOT_READ),
    ("SYMLINK_LOOP", SYMLINK_LOOP),
    ("TOO_LARGE", TOO_LARGE),
    ("NAME_NOT_UTF8", NAME_NOT_UTF8),
    ("NO_CERTIFICATE", NO_CERTIFICATE),
    ("DER_INVALID", DER_INVALID),
    ("PEM_BLOCKS_INVALID", PEM_BLOCKS_INVALID),
    ("PEM_NOT_CLOSED", PEM_NOT_CLOSED),
    ("PEM_BAD_BASE64", PEM_BAD_BASE64),
    ("CERT_INVALID", CERT_INVALID),
    ("UNKNOWN_KEY", UNKNOWN_KEY),
    ("SYMLINKS_SKIPPED", SYMLINKS_SKIPPED),
    ("EVIDENCE", EVIDENCE),
];
