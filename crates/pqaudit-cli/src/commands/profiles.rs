//! The `profiles` command: show the deadline profiles of the rules pack.

use std::io::Write;

use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::pack::{AppliesTo, DeadlineProfile, MilestoneKind, ThreatType, TierScope};

use crate::cli::ProfilesCommand;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// Run one `profiles` command.
pub fn run(command: &ProfilesCommand) -> ExitCode {
    let pack = default_pack();
    let mut out = String::new();
    match command {
        ProfilesCommand::List => {
            for profile in &pack.profiles {
                out.push_str(&format!(
                    "{}  {}  {}\n",
                    profile.id,
                    profile.name,
                    profile.milestones.len()
                ));
            }
        }
        ProfilesCommand::Show { id } => match pack.profile(id) {
            Some(profile) => out.push_str(&show(profile)),
            None => {
                eprintln!("{} {}", messages::UNKNOWN_PROFILE, output::value(id));
                return ExitCode::Error;
            }
        },
    }
    // If the reader closes the output stream, there is nothing more to do.
    let _ = std::io::stdout().write_all(out.as_bytes());
    ExitCode::Success
}

fn show(profile: &DeadlineProfile) -> String {
    let mut out = format!("{}  {}\n", profile.id, profile.name);
    for m in &profile.milestones {
        let kind = match m.kind {
            MilestoneKind::Planning => "planning",
            MilestoneKind::Migration => "migration",
        };
        out.push_str(&format!(
            "\n{}  {kind}\n  applies to: {}\n  {}\n  source: {} ({})\n  as of {}\n",
            m.date,
            applies_to(&m.applies_to),
            m.description
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            m.source_title,
            m.source_url,
            m.as_of
        ));
    }
    out
}

fn applies_to(scope: &AppliesTo) -> String {
    let tier = match scope.tier {
        Some(TierScope::High) => "tier high",
        Some(TierScope::All) | None => "tier all",
    };
    let mut parts = vec![tier.to_string()];
    if !scope.threat_types.is_empty() {
        let names: Vec<&str> = scope
            .threat_types
            .iter()
            .map(|t| match t {
                ThreatType::Hndl => "hndl",
                ThreatType::ForgeryLongLived => "forgery_long_lived",
                ThreatType::ForgeryShortLived => "forgery_short_lived",
                ThreatType::ClassicalWeakNow => "classical_weak_now",
            })
            .collect();
        parts.push(format!("threats {}", names.join(", ")));
    }
    if let Some(sector) = &scope.sector {
        parts.push(format!("sector {sector}"));
    }
    parts.join("; ")
}
