//! User-facing text of this crate.

/// The warning when a test trust list replaces the trust list of the program.
pub const TEST_TRUST_WARNING: &str =
    "Warning: a test trust list replaces the trust list of the program. Use this only in tests.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[("TEST_TRUST_WARNING", TEST_TRUST_WARNING)];
