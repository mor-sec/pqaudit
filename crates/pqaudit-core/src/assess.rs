//! Join scan results with the customer context: assets, deadlines, and overrides.

use std::collections::HashSet;
use std::fmt;

use chrono::NaiveDate;
use pqaudit_rules::pack::{DeadlineProfile, Milestone, RuleDef, RulesPack, TestType};
use serde::Serialize;

use crate::assets::{compile_paths, AssetContext, AssetIndex};
use crate::complexity::{assess_complexity, testing_scope, Complexity};
use crate::deadlines::{self, DeadlineRef};
use crate::engagement::{Assumptions, Band, Engagement, Override};
use crate::merge::{keyed_fingerprint, RedactKey};
use crate::messages;
use crate::scoring::{self, ScoreBreakdown};
use crate::{Finding, Fingerprint, InventoryItem, PackRef, ResultsFile, ResultsHeader, ScanError};

/// A short description of the engagement, for the reports.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EngagementSummary {
    /// The name of the client.
    pub client: String,
    /// The name of the assessor.
    pub assessor: String,
    /// The date of the assessment.
    pub assessment_date: NaiveDate,
    /// The IDs of the selected deadline profiles, in the selection order.
    pub profiles: Vec<String>,
    /// The sector overlay.
    pub sector: Option<String>,
}

/// A finding with its customer context, deadline, score, and override.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AssessedFinding {
    /// The finding.
    pub finding: Finding,
    /// The rule that matched.
    pub rule: RuleDef,
    /// The name of the asset that matches, if there is one.
    pub asset: Option<String>,
    /// The customer context.
    pub context: AssetContext,
    /// The deadline that applies.
    pub deadline: Option<DeadlineRef>,
    /// The score with all its factors.
    pub score: ScoreBreakdown,
    /// The suggested band.
    pub band: Band,
    /// The override of the customer, if there is one.
    pub override_: Option<Override>,
    /// The band after the override.
    pub effective_band: Band,
    /// The complexity of the fix.
    pub complexity: Complexity,
    /// The types of test that the fix needs.
    pub testing: Vec<TestType>,
}

/// The result of an assessment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Assessment {
    /// The engagement.
    pub engagement: EngagementSummary,
    /// The header of the results file.
    pub header: ResultsHeader,
    /// The assessed findings, in the order of the results file.
    pub findings: Vec<AssessedFinding>,
    /// The inventory of the results file.
    pub inventory: Vec<InventoryItem>,
    /// The scan errors of the results file.
    pub errors: Vec<ScanError>,
    /// The planning milestones of the selected profiles.
    pub planning_milestones: Vec<(String, Milestone)>,
    /// The overrides that match no finding.
    ///
    /// This list is empty for a redacted results file when the tool has no redaction key.
    /// Then the fingerprints are plain, and a plain fingerprint can confirm a guess.
    pub orphaned_overrides: Vec<Override>,
    /// The number of overrides that match no finding. It includes the overrides that the list does not show.
    pub orphaned_override_count: usize,
    /// True for a redacted results file with overrides, when the tool has no redaction key.
    /// Then a plain override fingerprint cannot match a finding.
    pub overrides_need_key: bool,
    /// The number of findings with at least one unassessed context field.
    pub unassessed_count: usize,
    /// The assumptions of the engagement.
    pub assumptions: Assumptions,
    /// The rules pack of the results.
    pub pack: PackRef,
}

/// An error during the assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssessError {
    /// The engagement selects a deadline profile that the rules pack does not have.
    UnknownProfile(String),
    /// A finding names a rule that the rules pack does not have.
    UnknownRule(String),
    /// The rules pack is not the pack that made the results.
    PackMismatch {
        /// The pack of the results, as `id version hash`.
        results: String,
        /// The pack that the tool got, as `id version hash`.
        pack: String,
    },
    /// Two overrides have the same fingerprint.
    DuplicateOverride(String),
    /// An asset has a path glob that is not valid.
    InvalidGlob {
        /// The name of the asset.
        asset: String,
        /// The pattern.
        pattern: String,
    },
}

impl fmt::Display for AssessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::UnknownProfile(id) => messages::UNKNOWN_PROFILE.replace("{profile}", id),
            Self::UnknownRule(id) => messages::UNKNOWN_RULE.replace("{rule}", id),
            Self::PackMismatch { results, pack } => messages::PACK_MISMATCH
                .replace("{results}", results)
                .replace("{pack}", pack),
            Self::DuplicateOverride(fingerprint) => {
                messages::DUPLICATE_OVERRIDE.replace("{fingerprint}", fingerprint)
            }
            Self::InvalidGlob { asset, pattern } => messages::INVALID_GLOB
                .replace("{asset}", asset)
                .replace("{pattern}", pattern),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for AssessError {}

/// Assess the findings of a results file without a redaction key.
///
/// Refer to `assess_with_key`.
pub fn assess(
    results: &ResultsFile,
    eng: &Engagement,
    pack: &RulesPack,
    today: NaiveDate,
) -> Result<Assessment, AssessError> {
    assess_with_key(results, eng, pack, today, None)
}

/// An override and the fingerprints that it matches.
struct OverrideMatch {
    /// The override as the reports show it.
    shown: Override,
    /// The fingerprint in the overrides file.
    plain: String,
    /// The keyed form of the fingerprint, for redacted results.
    keyed: Option<String>,
}

impl OverrideMatch {
    fn matches(&self, fingerprint: &str) -> bool {
        self.plain == fingerprint || self.keyed.as_deref() == Some(fingerprint)
    }
}

/// Assess the findings of a results file.
///
/// The asset of a finding is the first asset in the assets file that matches any occurrence.
/// The date of the assessment is `assessment_date` from the engagement. If it is not set,
/// the tool uses `today`. The caller gives the local date as `today`.
///
/// Redacted results have keyed fingerprints. With the redaction key, an override with a plain
/// fingerprint matches the keyed form. An override in the keyed form also matches. Then the
/// assessment shows only keyed fingerprints. Without the key, only an exact match applies.
pub fn assess_with_key(
    results: &ResultsFile,
    eng: &Engagement,
    pack: &RulesPack,
    today: NaiveDate,
    key: Option<&RedactKey>,
) -> Result<Assessment, AssessError> {
    let today = eng.config.assessment_date.unwrap_or(today);
    let config = &eng.config;
    let sector = config.deadlines.sector.as_deref();

    let used = &results.header.rules_pack;
    if used.id != pack.id
        || used.version != pack.version.to_string()
        || used.content_hash != pack.content_hash
    {
        let name = |id: &str, version: &str, hash: &str| format!("{id} {version} {hash}");
        return Err(AssessError::PackMismatch {
            results: name(&used.id, &used.version, &used.content_hash),
            pack: name(&pack.id, &pack.version.to_string(), &pack.content_hash),
        });
    }
    let mut seen_overrides = HashSet::new();
    for item in &eng.overrides.r#override {
        if !seen_overrides.insert(item.fingerprint.as_str()) {
            return Err(AssessError::DuplicateOverride(item.fingerprint.clone()));
        }
    }

    let profiles: Vec<&DeadlineProfile> = config
        .deadlines
        .profiles
        .iter()
        .map(|id| {
            pack.profile(id)
                .ok_or_else(|| AssessError::UnknownProfile(id.clone()))
        })
        .collect::<Result<_, _>>()?;
    for asset in &eng.assets.asset {
        compile_paths(asset).map_err(|pattern| AssessError::InvalidGlob {
            asset: asset.name.clone(),
            pattern,
        })?;
    }
    let index = AssetIndex::new(&eng.assets.asset);
    let redaction_key = key.filter(|_| results.header.redacted);
    let overrides: Vec<OverrideMatch> = eng
        .overrides
        .r#override
        .iter()
        .map(|o| {
            let plain = o.fingerprint.clone();
            let keyed =
                redaction_key.map(|key| keyed_fingerprint(&Fingerprint(plain.clone()), key).0);
            let mut shown = o.clone();
            if let Some(keyed) = &keyed {
                // A plain fingerprint must not reach a redacted report.
                let exact = results.findings.iter().any(|f| f.fingerprint.0 == plain);
                if !exact {
                    shown.fingerprint = keyed.clone();
                }
            }
            OverrideMatch {
                shown,
                plain,
                keyed,
            }
        })
        .collect();

    let mut findings = Vec::with_capacity(results.findings.len());
    for finding in &results.findings {
        let rule = pack
            .rule(&finding.rule_id)
            .ok_or_else(|| AssessError::UnknownRule(finding.rule_id.clone()))?;
        // The asset that comes first in the assets file wins. The order of occurrences is not stable.
        let asset = finding
            .occurrences
            .iter()
            .filter_map(|occurrence| index.position(&occurrence.location))
            .min()
            .map(|place| &eng.assets.asset[place]);
        let context = asset.map_or_else(AssetContext::unassessed, AssetContext::from_asset);
        let deadline = deadlines::resolve(
            finding.threat_type,
            context.priority_tier,
            sector,
            &profiles,
        );
        let complexity = assess_complexity(finding, rule, &context, &eng.scoring);
        let score = scoring::score(
            finding,
            &context,
            deadline.as_ref(),
            &complexity,
            &eng.scoring,
            config.assumptions.crqc_year,
            today,
        );
        let band = scoring::band(score.total, &eng.scoring.bands);
        let override_ = overrides
            .iter()
            .find(|candidate| candidate.matches(&finding.fingerprint.0))
            .map(|candidate| candidate.shown.clone());
        let effective_band = override_.as_ref().map_or(band, |o| o.priority);
        let testing = testing_scope(rule, &context, &eng.scoring);
        findings.push(AssessedFinding {
            finding: finding.clone(),
            rule: rule.clone(),
            asset: asset.map(|a| a.name.clone()),
            context,
            deadline,
            score,
            band,
            override_,
            effective_band,
            complexity,
            testing,
        });
    }

    let known: HashSet<&str> = results
        .findings
        .iter()
        .map(|finding| finding.fingerprint.0.as_str())
        .collect();
    let orphaned_overrides: Vec<Override> = overrides
        .iter()
        .filter(|o| !known.iter().any(|fingerprint| o.matches(fingerprint)))
        .map(|o| o.shown.clone())
        .collect();
    let orphaned_override_count = orphaned_overrides.len();
    // Without the key, the tool cannot make a keyed form. A plain fingerprint must not reach a redacted report.
    let orphaned_overrides = if results.header.redacted && key.is_none() {
        Vec::new()
    } else {
        orphaned_overrides
    };
    let overrides_need_key =
        results.header.redacted && key.is_none() && !eng.overrides.r#override.is_empty();
    let unassessed_count = findings
        .iter()
        .filter(|f| f.context.has_unassessed())
        .count();

    Ok(Assessment {
        engagement: EngagementSummary {
            client: if results.header.redacted {
                // The clear name must not reach any report. The header has the redacted name.
                results.header.engagement.clone()
            } else {
                config.client.clone()
            },
            assessor: config.assessor.clone(),
            assessment_date: today,
            profiles: config.deadlines.profiles.clone(),
            sector: config.deadlines.sector.clone(),
        },
        header: results.header.clone(),
        findings,
        inventory: results.inventory.clone(),
        errors: results.errors.clone(),
        planning_milestones: deadlines::planning(&profiles),
        orphaned_overrides,
        orphaned_override_count,
        overrides_need_key,
        unassessed_count,
        assumptions: config.assumptions.clone(),
        pack: results.header.rules_pack.clone(),
    })
}
