//! User-facing text of the CLI crate.

/// The text of a command that is not ready yet.
pub const NOT_IMPLEMENTED: &str = "This command is not implemented yet.";

/// The text when a profile ID is not in the rules pack.
pub const UNKNOWN_PROFILE: &str = "This profile does not exist:";

/// The text when the signature of a pack is correct.
pub const RULES_SIGNATURE_OK: &str = "The signature is correct.";

/// The warning when the tool uses a pack without a valid signature.
pub const RULES_UNSIGNED_WARNING: &str = "Warning: this pack has no valid signature. The tool accepts it because you gave the flag --allow-unsigned-rules.";

/// The hint when the signature check fails.
pub const RULES_UNSIGNED_HINT: &str =
    "To accept a pack without a valid signature, use the flag --allow-unsigned-rules.";

/// The text before the directory of an installed pack.
pub const RULES_INSTALLED: &str = "Installed the pack in:";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("NOT_IMPLEMENTED", NOT_IMPLEMENTED),
    ("UNKNOWN_PROFILE", UNKNOWN_PROFILE),
    ("RULES_SIGNATURE_OK", RULES_SIGNATURE_OK),
    ("RULES_UNSIGNED_WARNING", RULES_UNSIGNED_WARNING),
    ("RULES_UNSIGNED_HINT", RULES_UNSIGNED_HINT),
    ("RULES_INSTALLED", RULES_INSTALLED),
];
