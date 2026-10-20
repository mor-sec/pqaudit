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

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("UNSUPPORTED_SCHEMA", UNSUPPORTED_SCHEMA),
    ("RESULTS_PARSE", RESULTS_PARSE),
    ("RESULTS_IO", RESULTS_IO),
    ("RESULTS_TOO_LARGE", RESULTS_TOO_LARGE),
    ("NO_SCHEMA_VERSION", NO_SCHEMA_VERSION),
];
