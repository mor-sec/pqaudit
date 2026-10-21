//! User-facing text of this crate.

/// The warning when a test trust list replaces the trust list of the program.
pub const TEST_TRUST_WARNING: &str =
    "Warning: a test trust list replaces the trust list of the program. Use this only in tests.";

/// The error when the tool cannot find the data directory. The tool fills in {variable}.
pub const NO_DATA_DIR: &str = "The tool cannot find the data directory. Set {variable}.";

/// The error when the tool cannot read or write a file. The tool fills in {path} and {message}.
pub const FILE_IO: &str = "The tool cannot use the file {path}. {message}";

/// The error for a file that is not a normal file or is too large. The tool fills in {path}.
pub const BAD_FILE: &str = "The file {path} is not a normal file, or it is too large.";

/// The error for a pack that is not valid. The tool fills in {reason}.
pub const PACK_INVALID: &str = "The pack is not valid. {reason}";

/// The reason when the directory name of an installed pack is not its version.
pub const DIR_NOT_VERSION: &str = "The directory name is not the version of the pack.";

/// The reason when an installed pack has no signature file.
pub const NO_SIGNATURE: &str = "The pack has no signature.";

/// The error for a path that an archive must not have. The tool fills in {path}.
pub const ARCHIVE_BAD_PATH: &str = "The path {path} is not allowed in a pack archive.";

/// The error for a path that is in an archive two times. The tool fills in {path}.
pub const ARCHIVE_DUPLICATE: &str = "The path {path} is in the archive more than one time.";

/// The error for an archive that is too large.
pub const ARCHIVE_TOO_LARGE: &str = "The archive is too large.";

/// The error for an archive entry that is not a normal file. The tool fills in {path}.
pub const ARCHIVE_NOT_A_FILE: &str = "The entry {path} is not a normal file.";

/// The error when the tool cannot read an archive. The tool fills in {reason}.
pub const ARCHIVE_READ: &str = "The tool cannot read the archive. {reason}";

/// The text in place of a path that is not UTF-8.
pub const NOT_UTF8: &str = "(not UTF-8)";

/// The error for a signature file that is not valid. The tool fills in {reason}.
pub const SIG_FILE_INVALID: &str = "The signature file is not valid. {reason}";

/// The error for a key that is not valid. The tool fills in {reason}.
pub const KEY_INVALID: &str = "A key is not valid. {reason}";

/// The error for a signature that is not correct. The tool fills in {algorithm}.
pub const BAD_SIGNATURE: &str = "The {algorithm} signature is not correct.";

/// The error when the signature file names a different key. The tool fills in {key}.
pub const KEY_MISMATCH: &str =
    "The signature file names the key {key}. The check needs a different key.";

/// The error for a key that is not in the trust list. The tool fills in {key}.
pub const UNKNOWN_KEY: &str = "The key {key} is not in the trust list.";

/// The error for a key that the trust list revokes. The tool fills in {key}.
pub const KEY_REVOKED: &str = "The trust list revokes the key {key}.";

/// The error for an archive that is not valid. The tool fills in {reason}.
pub const ARCHIVE_INVALID: &str = "The archive is not valid. {reason}";

/// The error for a key rotation that is not valid. The tool fills in {reason}.
pub const ROTATION_INVALID: &str = "A key rotation is not valid. {reason}";

/// The error when the tool cannot read a pack file. The tool fills in {path} and {message}.
pub const PACK_READ: &str = "The tool cannot read {path}. {message}";

/// The error when the tool cannot parse a pack file. The tool fills in {path} and {message}.
pub const PACK_PARSE: &str = "The tool cannot parse {path}. {message}";

/// The error when the pack has no file that it needs. The tool fills in {path}.
pub const PACK_MISSING: &str = "The pack has no file {path}.";

/// The error for a YAML file in a wrong place. The tool fills in {path}.
pub const PACK_MISPLACED: &str =
    "The file {path} is in a wrong place. Use a .yaml file in rules/ or profiles/.";

/// The error for an ID that two rules use. The tool fills in {id}.
pub const PACK_DUPLICATE_ID: &str = "The ID {id} is in the pack more than one time.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("TEST_TRUST_WARNING", TEST_TRUST_WARNING),
    ("NO_DATA_DIR", NO_DATA_DIR),
    ("FILE_IO", FILE_IO),
    ("BAD_FILE", BAD_FILE),
    ("PACK_INVALID", PACK_INVALID),
    ("DIR_NOT_VERSION", DIR_NOT_VERSION),
    ("NO_SIGNATURE", NO_SIGNATURE),
    ("ARCHIVE_BAD_PATH", ARCHIVE_BAD_PATH),
    ("ARCHIVE_DUPLICATE", ARCHIVE_DUPLICATE),
    ("ARCHIVE_TOO_LARGE", ARCHIVE_TOO_LARGE),
    ("ARCHIVE_NOT_A_FILE", ARCHIVE_NOT_A_FILE),
    ("ARCHIVE_READ", ARCHIVE_READ),
    ("NOT_UTF8", NOT_UTF8),
    ("SIG_FILE_INVALID", SIG_FILE_INVALID),
    ("KEY_INVALID", KEY_INVALID),
    ("BAD_SIGNATURE", BAD_SIGNATURE),
    ("KEY_MISMATCH", KEY_MISMATCH),
    ("UNKNOWN_KEY", UNKNOWN_KEY),
    ("KEY_REVOKED", KEY_REVOKED),
    ("ARCHIVE_INVALID", ARCHIVE_INVALID),
    ("ROTATION_INVALID", ROTATION_INVALID),
    ("PACK_READ", PACK_READ),
    ("PACK_PARSE", PACK_PARSE),
    ("PACK_MISSING", PACK_MISSING),
    ("PACK_MISPLACED", PACK_MISPLACED),
    ("PACK_DUPLICATE_ID", PACK_DUPLICATE_ID),
];
