//! User-facing text of the CLI crate.

/// The text of a command that is not ready yet.
pub const NOT_IMPLEMENTED: &str = "This command is not implemented yet.";

/// The text when a profile ID is not in the rules pack.
pub const UNKNOWN_PROFILE: &str = "This profile does not exist:";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("NOT_IMPLEMENTED", NOT_IMPLEMENTED),
    ("UNKNOWN_PROFILE", UNKNOWN_PROFILE),
];
