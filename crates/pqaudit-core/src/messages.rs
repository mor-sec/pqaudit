//! User-facing text of this crate.

/// The error for a results file with a newer schema. The tool fills in {found} and {supported}.
pub const UNSUPPORTED_SCHEMA: &str = "The results file uses schema version {found}. This tool supports schema version {supported} and older versions. Update the tool.";

/// The error for a results file that the tool cannot parse. The tool fills in {reason}.
pub const RESULTS_PARSE: &str = "The results file is not valid. {reason}";

/// The error for a results file that the tool cannot read. The tool fills in {reason}.
pub const RESULTS_IO: &str = "The tool cannot read the results file. {reason}";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("UNSUPPORTED_SCHEMA", UNSUPPORTED_SCHEMA),
    ("RESULTS_PARSE", RESULTS_PARSE),
    ("RESULTS_IO", RESULTS_IO),
];
