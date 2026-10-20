//! User-facing text of this crate.

/// The error for a path that the tool cannot read. The tool fills in {reason}.
pub const CANNOT_READ: &str = "The tool cannot read this path. {reason}";

/// The error for a symbolic link loop.
pub const SYMLINK_LOOP: &str = "This path is in a loop of symbolic links. The tool skips it.";

/// The error for a file that is larger than the limit. The tool fills in {limit}.
pub const TOO_LARGE: &str =
    "The file is too large. The limit is {limit} bytes. The tool skips the file.";

/// The error for a file that changes while the tool reads it.
pub const FILE_CHANGED: &str = "The file changed while the tool read it. The tool skips the file.";

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

/// The note for symbolic links that the tool skipped. The tool fills in {count}.
pub const SYMLINKS_SKIPPED: &str =
    "The tool skipped {count} symbolic links. Use the flag --follow-symlinks to scan them.";

/// The text of the evidence for a certificate. The tool fills in {subject} and {position}.
pub const EVIDENCE: &str = "Certificate {subject}, chain position {position}.";

/// The error for a key store that is not valid.
pub const KEYSTORE_INVALID: &str = "The file is not a valid key store.";

/// The error for a key store that ends too soon.
pub const KEYSTORE_TRUNCATED: &str = "The key store ends too soon. The file can be cut short.";

/// The error for a key store that uses a feature that the tool does not read.
pub const KEYSTORE_UNSUPPORTED: &str =
    "The key store uses a version or an encryption method that the tool does not read.";

/// The error for a JCEKS key entry. The tool fills in {alias}.
pub const JCEKS_ENTRY_UNSUPPORTED: &str = "The tool cannot read the JCEKS key entry with the alias {alias}. It reads the entries before it and stops.";

/// The note for a key store that no password opens.
pub const ENCRYPTED_NOT_INSPECTED: &str =
    "Encrypted — not inspected. No password that the tool has opens this file.";

/// The error for a GnuPG key box file.
pub const KBX_UNSUPPORTED: &str = "Unsupported format. The file is a GnuPG key box. Export the keys with the command gpg --export. Then scan the export file.";

/// The reason for key data that is not valid.
pub const KEY_DATA_INVALID: &str = "The key data is not valid.";

/// The reason for a key with an algorithm that the tool does not know. The tool fills in {oid}.
pub const KEY_UNKNOWN_ALGORITHM: &str =
    "The key has an algorithm that the tool does not know. The OID is {oid}.";

/// The reason for a key with a type or a version that the tool does not read.
pub const KEY_UNSUPPORTED: &str = "The key has a type or a version that the tool does not read.";

/// The error for a file with bad key entries. The tool fills in {bad}, {total}, and {reason}.
pub const KEY_ENTRIES_INVALID: &str =
    "{bad} of {total} key entries are not valid. The first problem: {reason}";

/// The error for a file with bad key lines. The tool fills in {bad}, {total}, and {line}.
pub const KEY_LINES_INVALID: &str =
    "{bad} of {total} lines are not valid SSH public keys. The first bad line is line {line}.";

/// The note for an encrypted private key. The tool does not read it.
pub const ENCRYPTED_KEY_NOT_INSPECTED: &str =
    "Encrypted private key. Not inspected. The tool does not decrypt keys.";

/// The evidence for an SSH public key.
pub const EVIDENCE_SSH_PUBLIC: &str = "SSH public key.";

/// The evidence for an OpenSSH private key file. The tool reads the public part only.
pub const EVIDENCE_OPENSSH_PRIVATE: &str =
    "OpenSSH private key file. The tool read the public part only.";

/// The evidence for an OpenSSH private key file with an encrypted private part.
pub const EVIDENCE_OPENSSH_ENCRYPTED: &str =
    "OpenSSH private key file with an encrypted private part. The tool read the public part only.";

/// The evidence for a private key in a PEM file.
pub const EVIDENCE_PRIVATE_KEY: &str =
    "Private key. The tool read the algorithm and the key size only.";

/// The evidence for a public key in a PEM file.
pub const EVIDENCE_PUBLIC_KEY: &str = "Public key.";

/// The evidence for an OpenPGP public key.
pub const EVIDENCE_PGP_PUBLIC: &str = "OpenPGP public key.";

/// The evidence for an OpenPGP secret key. The tool reads the public part only.
pub const EVIDENCE_PGP_SECRET: &str = "OpenPGP secret key. The tool read the public part only.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("CANNOT_READ", CANNOT_READ),
    ("SYMLINK_LOOP", SYMLINK_LOOP),
    ("TOO_LARGE", TOO_LARGE),
    ("FILE_CHANGED", FILE_CHANGED),
    ("NAME_NOT_UTF8", NAME_NOT_UTF8),
    ("NO_CERTIFICATE", NO_CERTIFICATE),
    ("DER_INVALID", DER_INVALID),
    ("PEM_BLOCKS_INVALID", PEM_BLOCKS_INVALID),
    ("PEM_NOT_CLOSED", PEM_NOT_CLOSED),
    ("PEM_BAD_BASE64", PEM_BAD_BASE64),
    ("SYMLINKS_SKIPPED", SYMLINKS_SKIPPED),
    ("EVIDENCE", EVIDENCE),
    ("KEYSTORE_INVALID", KEYSTORE_INVALID),
    ("KEYSTORE_TRUNCATED", KEYSTORE_TRUNCATED),
    ("KEYSTORE_UNSUPPORTED", KEYSTORE_UNSUPPORTED),
    ("JCEKS_ENTRY_UNSUPPORTED", JCEKS_ENTRY_UNSUPPORTED),
    ("ENCRYPTED_NOT_INSPECTED", ENCRYPTED_NOT_INSPECTED),
    ("KBX_UNSUPPORTED", KBX_UNSUPPORTED),
    ("KEY_DATA_INVALID", KEY_DATA_INVALID),
    ("KEY_UNKNOWN_ALGORITHM", KEY_UNKNOWN_ALGORITHM),
    ("KEY_UNSUPPORTED", KEY_UNSUPPORTED),
    ("KEY_ENTRIES_INVALID", KEY_ENTRIES_INVALID),
    ("KEY_LINES_INVALID", KEY_LINES_INVALID),
    ("ENCRYPTED_KEY_NOT_INSPECTED", ENCRYPTED_KEY_NOT_INSPECTED),
    ("EVIDENCE_SSH_PUBLIC", EVIDENCE_SSH_PUBLIC),
    ("EVIDENCE_OPENSSH_PRIVATE", EVIDENCE_OPENSSH_PRIVATE),
    ("EVIDENCE_OPENSSH_ENCRYPTED", EVIDENCE_OPENSSH_ENCRYPTED),
    ("EVIDENCE_PRIVATE_KEY", EVIDENCE_PRIVATE_KEY),
    ("EVIDENCE_PUBLIC_KEY", EVIDENCE_PUBLIC_KEY),
    ("EVIDENCE_PGP_PUBLIC", EVIDENCE_PGP_PUBLIC),
    ("EVIDENCE_PGP_SECRET", EVIDENCE_PGP_SECRET),
];
