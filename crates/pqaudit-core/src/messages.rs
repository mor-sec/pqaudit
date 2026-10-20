//! User-facing text of this crate.

/// The error for a results file with a newer schema. The tool fills in {found} and {supported}.
pub const UNSUPPORTED_SCHEMA: &str = "The results file uses schema version {found}. This tool supports schema version {supported} and older versions. Update the tool.";

/// The error for a results file that the tool cannot parse. The tool fills in {reason}.
pub const RESULTS_PARSE: &str = "The results file is not valid. {reason}";

/// The error for a results file that the tool cannot read. The tool fills in {reason}.
pub const RESULTS_IO: &str = "The tool cannot read the results file. {reason}";

/// The error for a results file that is too large. The tool fills in {limit}.
pub const RESULTS_TOO_LARGE: &str =
    "The results file is too large. The limit is {limit} bytes. The limit applies after decompression too.";

/// The error for a results file with no schema version in its header.
pub const NO_SCHEMA_VERSION: &str = "The header of the results file has no schema version.";

/// The error for a necessary engagement file that does not exist. The tool fills in {file} and {dir}.
pub const ENGAGEMENT_MISSING: &str =
    "The file {file} does not exist in {dir}. Run the command init to make the engagement files.";

/// The error for an engagement file that the tool cannot read. The tool fills in {file} and {reason}.
pub const ENGAGEMENT_IO: &str = "The tool cannot read the file {file}. {reason}";

/// The error for an engagement file that is not valid. The tool fills in {file}, {line}, and {reason}.
pub const ENGAGEMENT_PARSE: &str = "The file {file} is not valid at line {line}. {reason}";

/// The error for a value that must be a date. The format is YEAR-MONTH-DAY.
pub const DATE_EXPECTED: &str =
    "This value must be a date in the format YEAR-MONTH-DAY, for example 2026-10-20.";

/// The error for a passwords table with both keys.
pub const PASSWORDS_BOTH: &str =
    "The table passwords has the keys env and file. Use only one of these keys.";

/// The error for a passwords table with no key.
pub const PASSWORDS_NONE: &str = "The table passwords needs one of the keys env and file.";

/// The reason for certificate data that the parser rejects.
pub const CERT_INVALID: &str = "The certificate data is not valid.";

/// The reason for a public key type that the tool does not know. The tool fills in {oid}.
pub const UNKNOWN_KEY: &str =
    "The certificate has a public key type that the tool does not know. The OID is {oid}.";

/// The error when a merge has no input files.
pub const MERGE_NO_INPUTS: &str = "The merge has no input files.";

/// The error when results files belong to different engagements. The tool fills in {first} and {other}.
pub const MERGE_ENGAGEMENT_MISMATCH: &str =
    "The results files belong to different engagements: {first} and {other}. Merge files of one engagement only.";

/// The warning when the rules packs differ. The tool fills in {versions}.
pub const MERGE_PACK_MISMATCH: &str =
    "The input files used different rules packs: {versions}. The merged file names the pack with the highest version.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("MERGE_NO_INPUTS", MERGE_NO_INPUTS),
    ("MERGE_ENGAGEMENT_MISMATCH", MERGE_ENGAGEMENT_MISMATCH),
    ("MERGE_PACK_MISMATCH", MERGE_PACK_MISMATCH),
    ("UNSUPPORTED_SCHEMA", UNSUPPORTED_SCHEMA),
    ("RESULTS_PARSE", RESULTS_PARSE),
    ("RESULTS_IO", RESULTS_IO),
    ("RESULTS_TOO_LARGE", RESULTS_TOO_LARGE),
    ("NO_SCHEMA_VERSION", NO_SCHEMA_VERSION),
    ("ENGAGEMENT_MISSING", ENGAGEMENT_MISSING),
    ("ENGAGEMENT_IO", ENGAGEMENT_IO),
    ("ENGAGEMENT_PARSE", ENGAGEMENT_PARSE),
    ("DATE_EXPECTED", DATE_EXPECTED),
    ("PASSWORDS_BOTH", PASSWORDS_BOTH),
    ("PASSWORDS_NONE", PASSWORDS_NONE),
    ("CERT_INVALID", CERT_INVALID),
    ("UNKNOWN_KEY", UNKNOWN_KEY),
];
