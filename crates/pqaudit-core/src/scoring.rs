//! The priority score: a weighted sum of six factors (spec section 10.2).

use chrono::{Datelike, NaiveDate};
use pqaudit_rules::pack::ThreatType;

use crate::assets::{AssetContext, Ctx};
use crate::complexity::Complexity;
use crate::deadlines::DeadlineRef;
use crate::engagement::{Band, Bands, Exposure, ScoringConfig};
use crate::messages;
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

/// The lifespan in years that the tool uses for data with no set lifespan.
const UNASSESSED_LIFESPAN_YEARS: f64 = 25.0;

/// The value of a factor that has no good information. This is the cautious value.
const CAUTIOUS: f64 = 1.0;

/// The days in a year, for the conversion of days to years.
const DAYS_PER_YEAR: f64 = 365.25;

/// The name of a threat type, as the rules pack writes it.
pub fn threat_name(threat: ThreatType) -> &'static str {
    match threat {
        ThreatType::Hndl => "hndl",
        ThreatType::ForgeryLongLived => "forgery-long-lived",
        ThreatType::ForgeryShortLived => "forgery-short-lived",
        ThreatType::ClassicalWeakNow => "classical-weak-now",
    }
}

/// The name of an exposure, as the assets file writes it.
pub fn exposure_name(exposure: Exposure) -> &'static str {
    match exposure {
        Exposure::Internet => "internet",
        Exposure::Partner => "partner",
        Exposure::Internal => "internal",
        Exposure::Isolated => "isolated",
    }
}

fn threat_value(threat: ThreatType) -> f64 {
    match threat {
        ThreatType::Hndl | ThreatType::ClassicalWeakNow => 1.0,
        ThreatType::ForgeryLongLived => 0.8,
        ThreatType::ForgeryShortLived => 0.3,
    }
}

fn exposure_value(exposure: Exposure) -> f64 {
    match exposure {
        Exposure::Internet => 1.0,
        Exposure::Partner => 0.7,
        Exposure::Internal => 0.4,
        Exposure::Isolated => 0.2,
    }
}

/// Format a number of years for a note.
fn years(value: f64) -> String {
    format!("{value:.1}")
}

/// Work out the priority score of a finding.
///
/// Each factor has a value from 0 to 1. The contribution of a factor is
/// `100 * weight * value / sum of weights`. The total is the sum of the contributions.
/// A context field with no value gets the cautious value.
pub fn score(
    f: &Finding,
    ctx: &AssetContext,
    deadline: Option<&DeadlineRef>,
    complexity: &Complexity,
    cfg: &ScoringConfig,
    crqc_year: i32,
    today: NaiveDate,
) -> ScoreBreakdown {
    let weights = &cfg.weights;
    let values = [
        (
            "threat",
            weights.threat,
            threat_value(f.threat_type),
            messages::NOTE_THREAT.replace("{threat}", threat_name(f.threat_type)),
        ),
        {
            let (value, note) = match ctx.exposure {
                Ctx::Assessed(exposure) => (
                    exposure_value(exposure),
                    messages::NOTE_EXPOSURE.replace("{exposure}", exposure_name(exposure)),
                ),
                Ctx::Unassessed => (CAUTIOUS, messages::NOTE_EXPOSURE_UNASSESSED.to_string()),
            };
            ("exposure", weights.exposure, value, note)
        },
        {
            let (value, note) = sensitivity(ctx, cfg);
            ("sensitivity", weights.sensitivity, value, note)
        },
        {
            let (value, note) = mosca(f, ctx, complexity, crqc_year, today);
            ("mosca", weights.mosca, value, note)
        },
        {
            let (value, note) = deadline_factor(deadline, today);
            ("deadline", weights.deadline, value, note)
        },
        {
            let count = f.occurrences.len();
            let value = ((count as f64 + 1.0).log10() / 2.0).min(1.0);
            let note = messages::NOTE_SCALE.replace("{count}", &count.to_string());
            ("scale", weights.scale, value, note)
        },
    ];
    let weight_sum: f64 = values.iter().map(|(_, weight, _, _)| weight).sum();
    let factors: Vec<FactorScore> = values
        .into_iter()
        .map(|(name, weight, value, note)| FactorScore {
            name,
            value,
            weight,
            contribution: if weight_sum > 0.0 {
                100.0 * weight * value / weight_sum
            } else {
                0.0
            },
            note,
        })
        .collect();
    let total = factors.iter().map(|factor| factor.contribution).sum();
    ScoreBreakdown { factors, total }
}

fn sensitivity(ctx: &AssetContext, cfg: &ScoringConfig) -> (f64, String) {
    match &ctx.classification {
        Ctx::Unassessed => (CAUTIOUS, messages::NOTE_SENSITIVITY_UNASSESSED.to_string()),
        Ctx::Assessed(class) => match cfg.classification.get(class) {
            Some(value) => (*value, messages::NOTE_SENSITIVITY.replace("{class}", class)),
            None => (
                CAUTIOUS,
                messages::NOTE_SENSITIVITY_UNKNOWN.replace("{class}", class),
            ),
        },
    }
}

fn mosca(
    f: &Finding,
    ctx: &AssetContext,
    complexity: &Complexity,
    crqc_year: i32,
    today: NaiveDate,
) -> (f64, String) {
    let mut notes = Vec::new();
    let mut lifespan = match ctx.data_lifespan_years {
        Ctx::Assessed(years) => f64::from(years),
        Ctx::Unassessed => {
            notes.push(
                messages::NOTE_LIFESPAN_UNASSESSED
                    .replace("{years}", &UNASSESSED_LIFESPAN_YEARS.to_string()),
            );
            UNASSESSED_LIFESPAN_YEARS
        }
    };
    if f.threat_type == ThreatType::ForgeryLongLived {
        if let Some(cert) = &f.cert {
            let valid = (cert.not_after.date_naive() - today).num_days() as f64 / DAYS_PER_YEAR;
            if valid > lifespan {
                lifespan = valid;
                notes.push(messages::NOTE_LIFESPAN_CERT.replace("{years}", &years(valid)));
            }
        }
    }
    let until = f64::from(crqc_year - today.year());
    let margin = lifespan + complexity.migration_years - until;
    let value = if margin >= 0.0 {
        1.0
    } else {
        (1.0 + margin / 10.0).max(0.0)
    };
    notes.push(
        messages::NOTE_MOSCA
            .replace("{lifespan}", &years(lifespan))
            .replace("{migration}", &complexity.migration_years.to_string())
            .replace("{until}", &until.to_string())
            .replace("{margin}", &years(margin)),
    );
    (value, notes.join(" "))
}

fn deadline_factor(deadline: Option<&DeadlineRef>, today: NaiveDate) -> (f64, String) {
    let Some(deadline) = deadline else {
        return (0.0, messages::NOTE_DEADLINE_NONE.to_string());
    };
    let date = deadline.date.to_string();
    let years_left = (deadline.date - today).num_days() as f64 / DAYS_PER_YEAR;
    if years_left <= 0.0 {
        (1.0, messages::NOTE_DEADLINE_PASSED.replace("{date}", &date))
    } else {
        (
            (1.0 - years_left / 10.0).clamp(0.0, 1.0),
            messages::NOTE_DEADLINE
                .replace("{date}", &date)
                .replace("{years}", &years(years_left)),
        )
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
