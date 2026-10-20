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

/// The note for a threat type. The tool fills in {threat}.
pub const NOTE_THREAT: &str = "The threat type is {threat}.";

/// The note for an exposure. The tool fills in {exposure}.
pub const NOTE_EXPOSURE: &str = "The exposure is {exposure}.";

/// The note for an exposure that the customer did not set.
pub const NOTE_EXPOSURE_UNASSESSED: &str =
    "The exposure has the status unassessed. The tool uses the cautious value 1.0.";

/// The note for a classification. The tool fills in {class}.
pub const NOTE_SENSITIVITY: &str = "The classification is {class}.";

/// The note for a classification that the customer did not set.
pub const NOTE_SENSITIVITY_UNASSESSED: &str =
    "The classification has the status unassessed. The tool uses the cautious value 1.0.";

/// The note for a classification that the map does not list. The tool fills in {class}.
pub const NOTE_SENSITIVITY_UNKNOWN: &str =
    "The classification {class} is not in the classification map. The tool uses the cautious value 1.0.";

/// The note for a data lifespan that the customer did not set. The tool fills in {years}.
pub const NOTE_LIFESPAN_UNASSESSED: &str =
    "The data lifespan has the status unassessed. The tool uses {years} years.";

/// The note for the certificate lifetime in the Mosca factor. The tool fills in {years}.
pub const NOTE_LIFESPAN_CERT: &str =
    "The certificate stays valid for {years} years. The tool uses this time as the lifespan.";

/// The note for the Mosca margin. The tool fills in {lifespan}, {migration}, {until}, and {margin}.
pub const NOTE_MOSCA: &str = "The lifespan is {lifespan} years. The fix takes {migration} years. A quantum computer comes in {until} years. The margin is {margin} years.";

/// The note for a finding with no deadline.
pub const NOTE_DEADLINE_NONE: &str = "No deadline applies.";

/// The note for a deadline in the future. The tool fills in {date} and {years}.
pub const NOTE_DEADLINE: &str = "The deadline is {date}. {years} years remain.";

/// The note for a deadline in the past. The tool fills in {date}.
pub const NOTE_DEADLINE_PASSED: &str = "The deadline {date} has passed.";

/// The note for the number of occurrences. The tool fills in {count}.
pub const NOTE_SCALE: &str = "The number of occurrences is {count}.";

/// The reason for the change type of the rule. The tool fills in {change}.
pub const REASON_CHANGE: &str = "The fix needs this kind of change: {change}.";

/// The reason for a CA certificate.
pub const REASON_CA: &str = "The certificate is a CA. Each client that trusts it must also change.";

/// The reason for a hardware constraint.
pub const REASON_HARDWARE: &str =
    "The asset has a hardware constraint. The fix needs new hardware or firmware.";

/// The reason for a vendor asset.
pub const REASON_VENDOR: &str = "A vendor supplies the asset. The vendor must make the fix.";

/// The reason for an asset that partners can reach.
pub const REASON_PARTNER: &str = "Partners can reach the asset. The partners must also change.";

/// The reason for a rule with many size impacts. The tool fills in {count}.
pub const REASON_SIZE_IMPACT: &str =
    "The fix makes {count} parts larger. Test the size limits of each part.";

/// The reason that gives the size. The tool fills in {size} and {years}.
pub const REASON_SIZE: &str = "The size is {size}. The migration takes about {years} years.";

/// The error for a scoring value that is not valid. The tool fills in {file}, {key}, and {rule}.
pub const SCORING_INVALID: &str =
    "The file {file} is not valid. The key {key} breaks this rule: {rule}";

/// The rule for the weights: each weight is a number from 0 up.
pub const RULE_WEIGHT: &str = "Each weight must be a finite number of 0 or more.";

/// The rule for the sum of the weights.
pub const RULE_WEIGHT_SUM: &str = "The sum of the weights must be a finite number of more than 0.";

/// The rule for a classification value.
pub const RULE_CLASSIFICATION: &str = "Each classification value must be a number from 0 to 1.";

/// The rule for the bands.
pub const RULE_BANDS: &str =
    "Each band must be a number from 0 to 100. The value of critical must be more than high. The value of high must be more than medium.";

/// The rule for a migration time.
pub const RULE_MIGRATION: &str = "Each migration time must be a finite number of more than 0.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("SCORING_INVALID", SCORING_INVALID),
    ("RULE_WEIGHT", RULE_WEIGHT),
    ("RULE_WEIGHT_SUM", RULE_WEIGHT_SUM),
    ("RULE_CLASSIFICATION", RULE_CLASSIFICATION),
    ("RULE_BANDS", RULE_BANDS),
    ("RULE_MIGRATION", RULE_MIGRATION),
    ("NOTE_THREAT", NOTE_THREAT),
    ("NOTE_EXPOSURE", NOTE_EXPOSURE),
    ("NOTE_EXPOSURE_UNASSESSED", NOTE_EXPOSURE_UNASSESSED),
    ("NOTE_SENSITIVITY", NOTE_SENSITIVITY),
    ("NOTE_SENSITIVITY_UNASSESSED", NOTE_SENSITIVITY_UNASSESSED),
    ("NOTE_SENSITIVITY_UNKNOWN", NOTE_SENSITIVITY_UNKNOWN),
    ("NOTE_LIFESPAN_UNASSESSED", NOTE_LIFESPAN_UNASSESSED),
    ("NOTE_LIFESPAN_CERT", NOTE_LIFESPAN_CERT),
    ("NOTE_MOSCA", NOTE_MOSCA),
    ("NOTE_DEADLINE_NONE", NOTE_DEADLINE_NONE),
    ("NOTE_DEADLINE", NOTE_DEADLINE),
    ("NOTE_DEADLINE_PASSED", NOTE_DEADLINE_PASSED),
    ("NOTE_SCALE", NOTE_SCALE),
    ("REASON_CHANGE", REASON_CHANGE),
    ("REASON_CA", REASON_CA),
    ("REASON_HARDWARE", REASON_HARDWARE),
    ("REASON_VENDOR", REASON_VENDOR),
    ("REASON_PARTNER", REASON_PARTNER),
    ("REASON_SIZE_IMPACT", REASON_SIZE_IMPACT),
    ("REASON_SIZE", REASON_SIZE),
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
