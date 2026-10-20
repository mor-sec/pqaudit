//! User-facing text of this crate.

/// The error when a template does not work. The tool fills in {reason}.
pub const TEMPLATE_FAILED: &str = "The tool cannot make the report from the template. {reason}";

/// The error when the tool cannot write the assessment as JSON. The tool fills in {reason}.
pub const JSON_FAILED: &str = "The tool cannot write the assessment as JSON. {reason}";

/// The value of a context field that the customer did not set.
pub const UNASSESSED: &str = "Unassessed";

/// The value when no asset matches.
pub const NO_ASSET: &str = "None";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("TEMPLATE_FAILED", TEMPLATE_FAILED),
    ("JSON_FAILED", JSON_FAILED),
    ("UNASSESSED", UNASSESSED),
    ("NO_ASSET", NO_ASSET),
];
