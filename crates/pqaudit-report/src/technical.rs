//! The technical report (spec section 12.2).
//!
//! The code builds a view of the assessment in which each value is text.
//! Two templates show the view, one for HTML and one for Markdown.
//! The template engine escapes each value for the output format.

use minijinja::syntax::SyntaxConfig;
use minijinja::{escape_formatter, AutoEscape, Environment, Output, State, Value};
use pqaudit_core::assess::{AssessedFinding, Assessment};
use pqaudit_core::assets::Ctx;
use pqaudit_core::complexity::{change_type_name, size_name, test_type_name};
use pqaudit_core::engagement::{Band, Override};
use pqaudit_core::scoring::{exposure_name, threat_name};
use pqaudit_core::{InventoryItem, Location, Occurrence, PackOriginRef, ThreatType};
use serde::Serialize;

use crate::messages;
use crate::{Format, ReportError};

const HTML_TEMPLATE: &str = include_str!("templates/technical.html");
const MD_TEMPLATE: &str = include_str!("templates/technical.md.j2");

/// The name that selects the Markdown escape rules.
const MD_ESCAPE: &str = "markdown";

/// Make the technical report.
pub fn render(a: &Assessment, format: Format) -> Result<String, ReportError> {
    match format {
        Format::Json => serde_json::to_string_pretty(a).map_err(|error| {
            ReportError(messages::JSON_FAILED.replace("{reason}", &error.to_string()))
        }),
        Format::Html => render_template("technical.html", HTML_TEMPLATE, a),
        Format::Md => render_template("technical.md.j2", MD_TEMPLATE, a),
    }
}

fn render_template(name: &str, source: &str, a: &Assessment) -> Result<String, ReportError> {
    let fail = |error: minijinja::Error| {
        ReportError(messages::TEMPLATE_FAILED.replace("{reason}", &format!("{error:#}")))
    };
    let mut env = Environment::new();
    env.set_syntax(
        SyntaxConfig::builder()
            .trim_blocks(true)
            .lstrip_blocks(true)
            .keep_trailing_newline(true)
            .build()
            .map_err(fail)?,
    );
    env.set_auto_escape_callback(|name| {
        if name.ends_with(".html") {
            AutoEscape::Html
        } else {
            AutoEscape::Custom(MD_ESCAPE.into())
        }
    });
    env.set_formatter(format_value);
    env.add_template(name, source).map_err(fail)?;
    let view = View::new(a);
    env.get_template(name)
        .and_then(|template| template.render(minijinja::value::Serde(&view)))
        .map_err(fail)
}

/// Write a value with the escape rules of the output format.
fn format_value(
    out: &mut Output,
    state: &mut State,
    value: &Value,
) -> Result<(), minijinja::Error> {
    match state.auto_escape() {
        AutoEscape::Custom(name) if name == MD_ESCAPE && !value.is_safe() => {
            out.write_str(&escape_markdown(&value.to_string()))?;
            Ok(())
        }
        _ => escape_formatter(out, state, value),
    }
}

/// Escape text for one line of Markdown, also inside a table cell.
///
/// A line break or other control character becomes a space.
/// A character with a meaning in Markdown or HTML gets a backslash.
pub fn escape_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '~' | '&' | '!' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => out.push(' '),
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

#[derive(Serialize)]
struct View {
    client: String,
    assessor: String,
    date: String,
    tool_version: String,
    pack_id: String,
    pack_version: String,
    pack_hash: String,
    pack_origin: String,
    pack_unsigned: bool,
    engagement: String,
    redacted: bool,
    runs: Vec<RunView>,
    scope_hash: String,
    audit_log_hash: String,
    error_count: usize,
    errors: Vec<ErrorView>,
    finding_count: usize,
    inventory_count: usize,
    unassessed_count: usize,
    crqc_year: i32,
    profiles: String,
    sector: String,
    milestones: Vec<MilestoneView>,
    summary: Vec<SummaryRow>,
    findings: Vec<FindingView>,
    fix_now: Vec<BriefView>,
    ready: Vec<ReadyView>,
    vendor_questions: Vec<BriefView>,
    overrides: Vec<OverrideView>,
    orphans: Vec<OrphanView>,
    overrides_need_key: bool,
    register: Vec<RegisterRow>,
}

#[derive(Serialize)]
struct RunView {
    scanner: String,
    host: String,
    started: String,
    scope_hash: String,
    audit_log_hash: String,
}

#[derive(Serialize)]
struct ErrorView {
    location: String,
    reason: String,
}

#[derive(Serialize)]
struct MilestoneView {
    profile: String,
    date: String,
    description: String,
    source_title: String,
    source_url: String,
    link: bool,
    as_of: String,
}

#[derive(Serialize)]
struct SummaryRow {
    band: &'static str,
    count: usize,
}

#[derive(Serialize)]
struct Pair {
    name: &'static str,
    value: String,
}

#[derive(Serialize)]
struct FactorView {
    name: &'static str,
    value: String,
    weight: String,
    contribution: String,
    note: String,
}

#[derive(Serialize)]
struct OccurrenceView {
    location: String,
    evidence: String,
}

#[derive(Serialize)]
struct DeadlineView {
    date: String,
    profile: String,
    description: String,
    source_title: String,
    source_url: String,
    link: bool,
}

#[derive(Serialize)]
struct FindingView {
    id: String,
    fingerprint: String,
    title: String,
    rule_id: String,
    description: String,
    remediation: String,
    threat: &'static str,
    band: &'static str,
    effective_band: &'static str,
    total: String,
    asset: String,
    context: Vec<Pair>,
    has_unassessed: bool,
    occurrences: Vec<OccurrenceView>,
    deadline: Option<DeadlineView>,
    cwe: String,
    attack: String,
    factors: Vec<FactorView>,
    override_text: Option<String>,
    change_type: &'static str,
    size: &'static str,
    migration_years: String,
    reasons: Vec<String>,
    tests: String,
}

/// A short entry for the lists of fixes and vendor questions.
#[derive(Serialize)]
struct BriefView {
    id: String,
    title: String,
    asset: String,
    location: String,
    remediation: String,
}

#[derive(Serialize)]
struct ReadyView {
    kind: &'static str,
    fingerprint: String,
    algorithm: String,
    location: String,
}

#[derive(Serialize)]
struct OverrideView {
    id: String,
    fingerprint: String,
    title: String,
    original: &'static str,
    new: &'static str,
    reason: String,
    by: String,
    date: String,
}

#[derive(Serialize)]
struct OrphanView {
    fingerprint: String,
    priority: &'static str,
    reason: String,
    by: String,
    date: String,
}

#[derive(Serialize)]
struct RegisterRow {
    fingerprint: String,
    title: String,
    exposure: String,
    threat: String,
    classical_weakness: &'static str,
    classification: String,
    lifespan: String,
    scale: String,
    suggested: &'static str,
    effective: &'static str,
}

/// The name of a band.
fn band_name(band: Band) -> &'static str {
    match band {
        Band::Critical => "critical",
        Band::High => "high",
        Band::Medium => "medium",
        Band::Low => "low",
    }
}

/// The position of a band in the list, from the most urgent band.
fn band_rank(band: Band) -> u8 {
    match band {
        Band::Critical => 0,
        Band::High => 1,
        Band::Medium => 2,
        Band::Low => 3,
    }
}

fn location_text(location: &Location) -> String {
    match location {
        Location::File {
            path,
            line: Some(line),
        } => format!("{path}:{line}"),
        Location::File { path, line: None } => path.clone(),
        Location::Endpoint { host, ip, port, .. } => format!("{host} ({ip}):{port}"),
    }
}

fn locations_text(occurrences: &[Occurrence]) -> String {
    occurrences
        .iter()
        .map(|occurrence| location_text(&occurrence.location))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Show a context value, or the word for an unassessed value.
fn show<T>(value: &Ctx<T>, text: impl Fn(&T) -> String) -> String {
    value
        .as_assessed()
        .map_or_else(|| messages::UNASSESSED.to_string(), text)
}

/// Return true if the tool can show the URL as a link.
fn is_web_url(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://")
}

fn two(value: f64) -> String {
    format!("{value:.2}")
}

fn factor<'a>(
    item: &'a AssessedFinding,
    name: &str,
) -> Option<&'a pqaudit_core::scoring::FactorScore> {
    item.score.factors.iter().find(|f| f.name == name)
}

/// Show a context value with the value of its factor, for the risk register.
fn with_factor(item: &AssessedFinding, name: &str, text: String) -> String {
    match factor(item, name) {
        Some(f) => format!("{text} ({})", two(f.value)),
        None => text,
    }
}

fn override_text(over: &Override) -> String {
    messages::OVERRIDE_TEXT
        .replace("{band}", band_name(over.priority))
        .replace("{by}", &over.by)
        .replace("{date}", &over.date.to_string())
        .replace("{reason}", &over.reason)
}

fn finding_view(item: &AssessedFinding) -> FindingView {
    let finding = &item.finding;
    let ctx = &item.context;
    let tests: Vec<&str> = item.testing.iter().map(|t| test_type_name(*t)).collect();
    FindingView {
        id: finding.id.clone(),
        fingerprint: finding.fingerprint.0.clone(),
        title: item.rule.title.clone(),
        rule_id: item.rule.id.clone(),
        description: item.rule.description.trim().to_string(),
        remediation: item.rule.remediation.trim().to_string(),
        threat: threat_name(finding.threat_type),
        band: band_name(item.band),
        effective_band: band_name(item.effective_band),
        total: format!("{:.1}", item.score.total),
        asset: item
            .asset
            .clone()
            .unwrap_or_else(|| messages::NO_ASSET.to_string()),
        context: vec![
            Pair {
                name: "classification",
                value: show(&ctx.classification, Clone::clone),
            },
            Pair {
                name: "data_lifespan_years",
                value: show(&ctx.data_lifespan_years, ToString::to_string),
            },
            Pair {
                name: "exposure",
                value: show(&ctx.exposure, |v| exposure_name(*v).to_string()),
            },
            Pair {
                name: "priority_tier",
                value: show(&ctx.priority_tier, |v| format!("{v:?}").to_lowercase()),
            },
            Pair {
                name: "vendor",
                value: show(&ctx.vendor, ToString::to_string),
            },
            Pair {
                name: "hardware_constrained",
                value: show(&ctx.hardware_constrained, ToString::to_string),
            },
        ],
        has_unassessed: ctx.has_unassessed(),
        occurrences: finding
            .occurrences
            .iter()
            .map(|o| OccurrenceView {
                location: location_text(&o.location),
                evidence: o.evidence.clone(),
            })
            .collect(),
        deadline: item.deadline.as_ref().map(|d| DeadlineView {
            date: d.date.to_string(),
            profile: d.profile_id.clone(),
            description: d.description.clone(),
            source_title: d.source_title.clone(),
            source_url: d.source_url.clone(),
            link: is_web_url(&d.source_url),
        }),
        cwe: item.rule.cwe.join(", "),
        attack: item.rule.attack.join(", "),
        factors: item
            .score
            .factors
            .iter()
            .map(|f| FactorView {
                name: f.name,
                value: two(f.value),
                weight: two(f.weight),
                contribution: two(f.contribution),
                note: f.note.clone(),
            })
            .collect(),
        override_text: item.override_.as_ref().map(override_text),
        change_type: change_type_name(item.complexity.change_type),
        size: size_name(item.complexity.size),
        migration_years: item.complexity.migration_years.to_string(),
        reasons: item.complexity.reasons.clone(),
        tests: tests.join(", "),
    }
}

fn brief_view(item: &AssessedFinding) -> BriefView {
    BriefView {
        id: item.finding.id.clone(),
        title: item.rule.title.clone(),
        asset: item
            .asset
            .clone()
            .unwrap_or_else(|| messages::NO_ASSET.to_string()),
        location: locations_text(&item.finding.occurrences),
        remediation: item.rule.remediation.trim().to_string(),
    }
}

fn ready_view(item: &InventoryItem) -> ReadyView {
    ReadyView {
        kind: match item.kind {
            pqaudit_core::InventoryKind::Certificate => messages::KIND_CERTIFICATE,
            pqaudit_core::InventoryKind::Key => messages::KIND_KEY,
            pqaudit_core::InventoryKind::Endpoint => messages::KIND_ENDPOINT,
        },
        fingerprint: item.fingerprint.0.clone(),
        algorithm: item
            .algorithm
            .as_ref()
            .map_or_else(String::new, |algorithm| algorithm.name.clone()),
        location: locations_text(&item.occurrences),
    }
}

fn register_row(item: &AssessedFinding) -> RegisterRow {
    let ctx = &item.context;
    let occurrences = item.finding.occurrences.len();
    RegisterRow {
        fingerprint: item.finding.fingerprint.0.clone(),
        title: item.rule.title.clone(),
        exposure: with_factor(
            item,
            "exposure",
            show(&ctx.exposure, |v| exposure_name(*v).to_string()),
        ),
        threat: with_factor(
            item,
            "threat",
            threat_name(item.finding.threat_type).to_string(),
        ),
        classical_weakness: if item.finding.threat_type == ThreatType::ClassicalWeakNow {
            messages::YES
        } else {
            messages::NO
        },
        classification: with_factor(item, "sensitivity", show(&ctx.classification, Clone::clone)),
        lifespan: with_factor(
            item,
            "mosca",
            show(&ctx.data_lifespan_years, |years| {
                messages::YEARS.replace("{years}", &years.to_string())
            }),
        ),
        scale: with_factor(
            item,
            "scale",
            messages::PLACES.replace("{places}", &occurrences.to_string()),
        ),
        suggested: band_name(item.band),
        effective: band_name(item.effective_band),
    }
}

/// The text that tells where the rules pack came from.
pub fn origin_text(origin: &PackOriginRef) -> String {
    match origin {
        PackOriginRef::Embedded => messages::PACK_ORIGIN_EMBEDDED.to_string(),
        PackOriginRef::Installed {
            signed_by,
            rotation_chain,
            ..
        } => messages::PACK_ORIGIN_INSTALLED
            .replace("{signer}", signed_by)
            .replace("{chain}", &rotation_chain.join(" > ")),
        PackOriginRef::Unsigned { .. } => messages::PACK_ORIGIN_UNSIGNED.to_string(),
    }
}

impl View {
    fn new(a: &Assessment) -> Self {
        let mut ordered: Vec<&AssessedFinding> = a.findings.iter().collect();
        ordered.sort_by(|x, y| {
            band_rank(x.effective_band)
                .cmp(&band_rank(y.effective_band))
                .then(y.score.total.total_cmp(&x.score.total))
                .then_with(|| x.finding.id.cmp(&y.finding.id))
        });
        let header = &a.header;
        let dash = || messages::NONE.to_string();
        let summary = [Band::Critical, Band::High, Band::Medium, Band::Low]
            .into_iter()
            .map(|band| SummaryRow {
                band: band_name(band),
                count: a
                    .findings
                    .iter()
                    .filter(|f| f.effective_band == band)
                    .count(),
            })
            .collect();
        let overrides = ordered
            .iter()
            .filter_map(|item| {
                item.override_.as_ref().map(|over| OverrideView {
                    id: item.finding.id.clone(),
                    fingerprint: item.finding.fingerprint.0.clone(),
                    title: item.rule.title.clone(),
                    original: band_name(item.band),
                    new: band_name(over.priority),
                    reason: over.reason.clone(),
                    by: over.by.clone(),
                    date: over.date.to_string(),
                })
            })
            .collect();
        // Redacted results must not show the client name in clear.
        let client = if header.redacted {
            header.engagement.clone()
        } else {
            a.engagement.client.clone()
        };
        Self {
            client,
            assessor: a.engagement.assessor.clone(),
            date: a.engagement.assessment_date.to_string(),
            tool_version: header.tool_version.clone(),
            pack_id: a.pack.id.clone(),
            pack_version: a.pack.version.clone(),
            pack_hash: a.pack.content_hash.clone(),
            pack_origin: origin_text(&a.pack.origin),
            pack_unsigned: matches!(a.pack.origin, PackOriginRef::Unsigned { .. }),
            engagement: header.engagement.clone(),
            redacted: header.redacted,
            runs: header
                .runs
                .iter()
                .map(|run| RunView {
                    scanner: format!("{:?}", run.scanner).to_lowercase(),
                    host: run.host.clone(),
                    started: run.started.to_string(),
                    scope_hash: run.scope_hash.clone().unwrap_or_else(dash),
                    audit_log_hash: run.audit_log_hash.clone().unwrap_or_else(dash),
                })
                .collect(),
            scope_hash: header.scope_hash.clone().unwrap_or_else(dash),
            audit_log_hash: header.audit_log_hash.clone().unwrap_or_else(dash),
            error_count: a.errors.len(),
            errors: a
                .errors
                .iter()
                .map(|e| ErrorView {
                    location: e.location.clone(),
                    reason: e.reason.clone(),
                })
                .collect(),
            finding_count: a.findings.len(),
            inventory_count: a.inventory.len(),
            unassessed_count: a.unassessed_count,
            crqc_year: a.assumptions.crqc_year,
            profiles: a.engagement.profiles.join(", "),
            sector: a.engagement.sector.clone().unwrap_or_else(dash),
            milestones: a
                .planning_milestones
                .iter()
                .map(|(profile, m)| MilestoneView {
                    profile: profile.clone(),
                    date: m.date.to_string(),
                    description: m.description.clone(),
                    source_title: m.source_title.clone(),
                    source_url: m.source_url.clone(),
                    link: is_web_url(&m.source_url),
                    as_of: m.as_of.to_string(),
                })
                .collect(),
            summary,
            findings: ordered.iter().map(|f| finding_view(f)).collect(),
            fix_now: ordered
                .iter()
                .filter(|f| f.finding.threat_type == ThreatType::ClassicalWeakNow)
                .map(|f| brief_view(f))
                .collect(),
            ready: a
                .inventory
                .iter()
                .filter(|item| item.pq_ready)
                .map(ready_view)
                .collect(),
            vendor_questions: ordered
                .iter()
                .filter(|f| f.context.vendor == Ctx::Assessed(true))
                .map(|f| brief_view(f))
                .collect(),
            overrides,
            orphans: a
                .orphaned_overrides
                .iter()
                .map(|o| OrphanView {
                    fingerprint: o.fingerprint.clone(),
                    priority: band_name(o.priority),
                    reason: o.reason.clone(),
                    by: o.by.clone(),
                    date: o.date.to_string(),
                })
                .collect(),
            overrides_need_key: a.overrides_need_key,
            register: ordered.iter().map(|f| register_row(f)).collect(),
        }
    }
}
