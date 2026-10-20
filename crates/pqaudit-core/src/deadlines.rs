//! Select the deadline of a finding from the deadline profiles.

use chrono::NaiveDate;
use pqaudit_rules::pack::{DeadlineProfile, Milestone, MilestoneKind, ThreatType, TierScope};
use serde::Serialize;

use crate::assets::Ctx;
use crate::Tier;

/// The deadline that applies to a finding, with its profile and source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadlineRef {
    /// The date of the deadline.
    pub date: NaiveDate,
    /// The ID of the profile that gives the deadline.
    pub profile_id: String,
    /// What the source says.
    pub description: String,
    /// The title of the source.
    pub source_title: String,
    /// The URL of the source.
    pub source_url: String,
}

/// Return true if the milestone applies to the finding.
///
/// A milestone with no tier has no tier limit. It applies to every tier. A tier `high` applies to the tier `high`
/// and to an unassessed tier. This is the cautious choice.
fn applies(
    milestone: &Milestone,
    threat: ThreatType,
    tier: Ctx<Tier>,
    sector: Option<&str>,
) -> bool {
    let rule = &milestone.applies_to;
    let tier_ok = match rule.tier {
        Some(TierScope::All) => true,
        Some(TierScope::High) => matches!(tier, Ctx::Assessed(Tier::High) | Ctx::Unassessed),
        None => true,
    };
    let threat_ok = rule.threat_types.is_empty() || rule.threat_types.contains(&threat);
    let sector_ok = rule
        .sector
        .as_deref()
        .is_none_or(|wanted| sector.is_some_and(|have| have.eq_ignore_ascii_case(wanted)));
    tier_ok && threat_ok && sector_ok
}

/// Select the deadline of a finding. Use migration milestones only.
///
/// The earliest date wins. If two dates are the same, the first profile wins.
pub fn resolve(
    threat: ThreatType,
    tier: Ctx<Tier>,
    sector: Option<&str>,
    profiles: &[&DeadlineProfile],
) -> Option<DeadlineRef> {
    let mut best: Option<DeadlineRef> = None;
    for profile in profiles {
        for milestone in &profile.milestones {
            if milestone.kind != MilestoneKind::Migration
                || !applies(milestone, threat, tier, sector)
            {
                continue;
            }
            if best
                .as_ref()
                .is_none_or(|current| milestone.date < current.date)
            {
                best = Some(DeadlineRef {
                    date: milestone.date,
                    profile_id: profile.id.clone(),
                    description: milestone.description.clone(),
                    source_title: milestone.source_title.clone(),
                    source_url: milestone.source_url.clone(),
                });
            }
        }
    }
    best
}

/// List the planning milestones of the profiles, with the profile ID, in date order.
///
/// The reports show these for the engagement. They never attach to a finding.
pub fn planning(profiles: &[&DeadlineProfile]) -> Vec<(String, Milestone)> {
    let mut list: Vec<(String, Milestone)> = profiles
        .iter()
        .flat_map(|profile| {
            profile
                .milestones
                .iter()
                .filter(|milestone| milestone.kind == MilestoneKind::Planning)
                .map(|milestone| (profile.id.clone(), milestone.clone()))
        })
        .collect();
    list.sort_by_key(|(_, milestone)| milestone.date);
    list
}
