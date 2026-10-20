//! User-facing text of this crate.

/// The error when a template does not work. The tool fills in {reason}.
pub const TEMPLATE_FAILED: &str = "The tool cannot make the report from the template. {reason}";

/// The error when the tool cannot write the assessment as JSON. The tool fills in {reason}.
pub const JSON_FAILED: &str = "The tool cannot write the assessment as JSON. {reason}";

/// The value of a context field that the customer did not set.
pub const UNASSESSED: &str = "Unassessed";

/// The value when no asset matches.
pub const NO_ASSET: &str = "None";

/// The text of an override. The tool fills in {band}, {by}, {date}, and {reason}.
pub const OVERRIDE_TEXT: &str = "{band} by {by} on {date}. Reason: {reason}";

/// The value of a list that has no entries.
pub const NONE: &str = "none";

/// The answer when a statement is true.
pub const YES: &str = "Yes";

/// The answer when a statement is false.
pub const NO: &str = "No";

/// The size of a finding. The tool fills in {places}.
pub const PLACES: &str = "{places} places";

/// The lifespan of data. The tool fills in {years}.
pub const YEARS: &str = "{years} years";

/// The name of a certificate in a list.
pub const KIND_CERTIFICATE: &str = "certificate";

/// The name of a key in a list.
pub const KIND_KEY: &str = "key";

/// The name of an endpoint in a list.
pub const KIND_ENDPOINT: &str = "endpoint";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("TEMPLATE_FAILED", TEMPLATE_FAILED),
    ("JSON_FAILED", JSON_FAILED),
    ("UNASSESSED", UNASSESSED),
    ("NO_ASSET", NO_ASSET),
    ("OVERRIDE_TEXT", OVERRIDE_TEXT),
    ("NONE", NONE),
    ("YES", YES),
    ("NO", NO),
    ("PLACES", PLACES),
    ("YEARS", YEARS),
    ("KIND_CERTIFICATE", KIND_CERTIFICATE),
    ("KIND_KEY", KIND_KEY),
    ("KIND_ENDPOINT", KIND_ENDPOINT),
];
