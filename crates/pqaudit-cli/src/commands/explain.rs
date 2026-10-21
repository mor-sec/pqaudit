//! The `explain` command: show how the tool scored one finding.

use std::path::Path;

use pqaudit_core::assess::AssessedFinding;
use pqaudit_core::assets::Ctx;
use pqaudit_core::complexity::{change_type_name, size_name, test_type_name};
use pqaudit_core::engagement::Band;
use pqaudit_core::scoring::{exposure_name, threat_name};
use pqaudit_core::Location;

use crate::cli::Cli;
use crate::commands::assessment;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// Run `explain`.
pub fn run(cli: &Cli, finding_id: &str, results: Option<&Path>) -> ExitCode {
    let assessment = match assessment::load(cli, results) {
        Ok(assessment) => assessment,
        Err(code) => return code,
    };
    let Some(found) = assessment
        .findings
        .iter()
        .find(|item| item.finding.id == finding_id)
    else {
        output::error(&messages::EXPLAIN_UNKNOWN_ID.replace("{id}", &output::value(finding_id)));
        return ExitCode::Error;
    };
    // The function render cleans each value from the results file and the engagement files.
    // The line breaks that stay are the line breaks of the tool and of the rules pack.
    print!("{}", output::shown(&render(found)));
    ExitCode::Success
}

fn band_name(band: Band) -> &'static str {
    match band {
        Band::Critical => "critical",
        Band::High => "high",
        Band::Medium => "medium",
        Band::Low => "low",
    }
}

/// The location as one clean line. A path or a host name can hold a line break.
fn location_text(location: &Location) -> String {
    let text = match location {
        Location::File {
            path,
            line: Some(line),
        } => format!("{path}:{line}"),
        Location::File { path, line: None } => path.clone(),
        Location::Endpoint { host, ip, port, .. } => format!("{host} ({ip}):{port}"),
    };
    output::value(&text)
}

/// Show a context value, or the text for an unassessed value.
fn show<T>(value: &Ctx<T>, text: impl Fn(&T) -> String) -> String {
    value
        .as_assessed()
        .map_or_else(|| messages::EXPLAIN_UNASSESSED.to_string(), text)
}

fn context_line(name: &str, value: String) -> String {
    messages::EXPLAIN_CONTEXT_LINE
        .replace("{name}", name)
        .replace("{value}", &output::value(&value))
}

/// Build the text of the explanation.
fn render(item: &AssessedFinding) -> String {
    let finding = &item.finding;
    let rule = &item.rule;
    let ctx = &item.context;
    let mut lines = vec![
        messages::EXPLAIN_TITLE
            .replace("{id}", &output::value(&finding.id))
            .replace("{title}", &output::value(&rule.title)),
        messages::EXPLAIN_RULE.replace("{rule}", &output::value(&rule.id)),
        messages::EXPLAIN_DESCRIPTION.replace("{text}", rule.description.trim()),
        messages::EXPLAIN_THREAT.replace("{threat}", threat_name(finding.threat_type)),
        messages::EXPLAIN_OCCURRENCES.replace("{count}", &finding.occurrences.len().to_string()),
    ];
    for occurrence in &finding.occurrences {
        lines.push(
            messages::EXPLAIN_OCCURRENCE
                .replace("{location}", &location_text(&occurrence.location))
                .replace("{evidence}", &output::value(&occurrence.evidence)),
        );
    }

    lines.push(messages::EXPLAIN_CONTEXT.to_string());
    lines.push(messages::EXPLAIN_ASSET.replace(
        "{asset}",
        &output::value(item.asset.as_deref().unwrap_or(messages::EXPLAIN_NO_ASSET)),
    ));
    lines.push(context_line(
        "classification",
        show(&ctx.classification, Clone::clone),
    ));
    lines.push(context_line(
        "data_lifespan_years",
        show(&ctx.data_lifespan_years, ToString::to_string),
    ));
    lines.push(context_line(
        "exposure",
        show(&ctx.exposure, |value| exposure_name(*value).to_string()),
    ));
    lines.push(context_line(
        "priority_tier",
        show(&ctx.priority_tier, |value| {
            format!("{value:?}").to_lowercase()
        }),
    ));
    lines.push(context_line(
        "vendor",
        show(&ctx.vendor, ToString::to_string),
    ));
    lines.push(context_line(
        "hardware_constrained",
        show(&ctx.hardware_constrained, ToString::to_string),
    ));
    if ctx.has_unassessed() {
        lines.push(messages::EXPLAIN_UNASSESSED_FLAG.to_string());
    }

    match &item.deadline {
        Some(deadline) => {
            lines.push(
                messages::EXPLAIN_DEADLINE
                    .replace("{date}", &deadline.date.to_string())
                    .replace("{profile}", &output::value(&deadline.profile_id)),
            );
            lines.push(
                messages::EXPLAIN_DEADLINE_SOURCE
                    .replace("{title}", &output::value(&deadline.source_title))
                    .replace("{url}", &output::value(&deadline.source_url))
                    .replace("{description}", &output::value(&deadline.description)),
            );
        }
        None => lines.push(messages::EXPLAIN_DEADLINE_NONE.to_string()),
    }
    if !rule.cwe.is_empty() {
        lines.push(messages::EXPLAIN_CWE.replace("{ids}", &output::value(&rule.cwe.join(", "))));
    }
    if !rule.attack.is_empty() {
        lines.push(
            messages::EXPLAIN_ATTACK.replace("{ids}", &output::value(&rule.attack.join(", "))),
        );
    }

    lines.push(messages::EXPLAIN_SCORE.to_string());
    for factor in &item.score.factors {
        lines.push(
            messages::EXPLAIN_FACTOR
                .replace("{name}", factor.name)
                .replace("{value}", &format!("{:.2}", factor.value))
                .replace("{weight}", &format!("{:.2}", factor.weight))
                .replace("{contribution}", &format!("{:.2}", factor.contribution))
                .replace("{note}", &output::value(&factor.note)),
        );
    }
    lines.push(
        messages::EXPLAIN_TOTAL
            .replace("{total}", &format!("{:.1}", item.score.total))
            .replace("{band}", band_name(item.band)),
    );
    lines.push(match &item.override_ {
        Some(over) => messages::EXPLAIN_OVERRIDE
            .replace("{band}", band_name(over.priority))
            .replace("{reason}", &output::value(&over.reason))
            .replace("{by}", &output::value(&over.by))
            .replace("{date}", &over.date.to_string()),
        None => messages::EXPLAIN_NO_OVERRIDE.to_string(),
    });

    let complexity = &item.complexity;
    lines.push(
        messages::EXPLAIN_COMPLEXITY
            .replace("{size}", size_name(complexity.size))
            .replace("{change}", change_type_name(complexity.change_type))
            .replace("{years}", &complexity.migration_years.to_string()),
    );
    for reason in &complexity.reasons {
        lines.push(messages::EXPLAIN_REASON.replace("{reason}", &output::value(reason)));
    }
    let tests: Vec<&str> = item.testing.iter().map(|t| test_type_name(*t)).collect();
    lines.push(messages::EXPLAIN_TESTS.replace("{tests}", &tests.join(", ")));
    lines.push(messages::EXPLAIN_REMEDIATION.replace("{text}", rule.remediation.trim()));

    let mut text = lines.join("\n");
    text.push('\n');
    text
}
