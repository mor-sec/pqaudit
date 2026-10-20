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

/// The error when the inputs of a merge are a mix of two kinds of file.
pub const MERGE_MIXED_REDACTION: &str =
    "The input files are a mix of redacted files and plain files. Add the flag --redact to the command.";

/// The error when results files belong to different engagements. The tool fills in {first} and {other}.
pub const MERGE_ENGAGEMENT_MISMATCH: &str =
    "The results files belong to different engagements: {first} and {other}. Merge files of one engagement only.";

/// The warning when the rules packs differ. The tool fills in {versions}.
pub const MERGE_PACK_MISMATCH: &str =
    "The input files used different rules packs: {versions}. The merged file names the pack with the highest version.";

/// The error when the tool cannot use the redaction key file. The tool fills in {path} and {reason}.
pub const REDACT_KEY_IO: &str = "The tool cannot use the redaction key file {path}. {reason}";

/// The error when the redaction key file is not valid. The tool fills in {path}.
pub const REDACT_KEY_INVALID: &str =
    "The redaction key file {path} is not valid. It must hold 64 hex digits.";

/// The error when the system cannot make a random key. The tool fills in {reason}.
pub const REDACT_KEY_RANDOM: &str = "The tool cannot make a random redaction key. {reason}";

/// The error for a deadline profile that the rules pack does not have. The tool fills in {profile}.
pub const UNKNOWN_PROFILE: &str =
    "The engagement uses the deadline profile {profile}. The rules pack does not have this profile.";

/// The error for a finding with a rule that the rules pack does not have. The tool fills in {rule}.
pub const UNKNOWN_RULE: &str =
    "A finding uses the rule {rule}. The rules pack does not have this rule. Use the rules pack that made the results.";

/// The error for a path glob that is not valid. The tool fills in {asset} and {pattern}.
pub const INVALID_GLOB: &str =
    "The asset {asset} has the path pattern {pattern}. This pattern is not valid.";

/// The error for results from another rules pack. The tool fills in {results} and {pack}.
pub const PACK_MISMATCH: &str =
    "The results come from the rules pack {results}. The tool got the rules pack {pack}. Use the pack that made the results, or scan again.";

/// The error for two overrides with the same fingerprint. The tool fills in {fingerprint}.
pub const DUPLICATE_OVERRIDE: &str =
    "Two overrides have the fingerprint {fingerprint}. Keep one override for each fingerprint.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("UNKNOWN_PROFILE", UNKNOWN_PROFILE),
    ("UNKNOWN_RULE", UNKNOWN_RULE),
    ("INVALID_GLOB", INVALID_GLOB),
    ("PACK_MISMATCH", PACK_MISMATCH),
    ("DUPLICATE_OVERRIDE", DUPLICATE_OVERRIDE),
    ("REDACT_KEY_IO", REDACT_KEY_IO),
    ("REDACT_KEY_INVALID", REDACT_KEY_INVALID),
    ("REDACT_KEY_RANDOM", REDACT_KEY_RANDOM),
    ("MERGE_MIXED_REDACTION", MERGE_MIXED_REDACTION),
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
