//! The priority score. This file holds a stub. Task 15 replaces it.

use chrono::NaiveDate;

use crate::assets::AssetContext;
use crate::complexity::Complexity;
use crate::deadlines::DeadlineRef;
use crate::engagement::{Band, Bands, ScoringConfig};
use crate::Finding;

/// The score of one factor.
#[derive(Debug, Clone, PartialEq)]
pub struct FactorScore {
    /// The name of the factor.
    pub name: &'static str,
    /// The value of the factor, from 0 to 1.
    pub value: f64,
    /// The weight of the factor.
    pub weight: f64,
    /// The part of the total that the factor gives.
    pub contribution: f64,
    /// A note about the value.
    pub note: String,
}

/// The score of a finding with all its factors.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreBreakdown {
    /// The factors.
    pub factors: Vec<FactorScore>,
    /// The total, from 0 to 100.
    pub total: f64,
}

/// Stub: give a neutral score with no factors.
pub fn score(
    _f: &Finding,
    _ctx: &AssetContext,
    _deadline: Option<&DeadlineRef>,
    _complexity: &Complexity,
    _cfg: &ScoringConfig,
    _crqc_year: i32,
    _today: NaiveDate,
) -> ScoreBreakdown {
    ScoreBreakdown {
        factors: Vec::new(),
        total: 0.0,
    }
}

/// Find the band of a total score.
pub fn band(total: f64, bands: &Bands) -> Band {
    if total >= bands.critical {
        Band::Critical
    } else if total >= bands.high {
        Band::High
    } else if total >= bands.medium {
        Band::Medium
    } else {
        Band::Low
    }
}
