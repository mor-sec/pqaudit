//! The complexity of a fix. This file holds a stub. Task 15 replaces it.

use pqaudit_rules::pack::{ChangeType, RuleDef};

use crate::assets::AssetContext;
use crate::engagement::{ScoringConfig, Size};
use crate::Finding;

/// The complexity of the fix for a finding.
#[derive(Debug, Clone, PartialEq)]
pub struct Complexity {
    /// The kind of work that the fix needs.
    pub change_type: ChangeType,
    /// The size of the fix.
    pub size: Size,
    /// The approximate migration time in years.
    pub migration_years: f64,
    /// The reasons for the size.
    pub reasons: Vec<String>,
}

/// Stub: give the change type of the rule, size S, and no migration time.
pub fn assess_complexity(
    _f: &Finding,
    rule: &RuleDef,
    _ctx: &AssetContext,
    _cfg: &ScoringConfig,
) -> Complexity {
    Complexity {
        change_type: rule.change_type,
        size: Size::S,
        migration_years: 0.0,
        reasons: Vec::new(),
    }
}
