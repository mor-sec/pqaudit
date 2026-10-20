//! The `scan net` command. This version has the dry-run only.

use pqaudit_core::Protocol;
use pqaudit_scan_net::scope::{build_plan, ScopeFile, SystemResolver, TargetPlan};

use crate::cli::Cli;
use crate::exit::ExitCode;
use crate::messages;

/// Run `scan net`.
pub fn run(cli: &Cli, dry_run: bool) -> ExitCode {
    let (scope, _bytes) = match ScopeFile::load(&cli.engagement) {
        Ok(loaded) => loaded,
        Err(error) => return fail(&error),
    };
    let plan = match build_plan(&scope, &SystemResolver) {
        Ok(plan) => plan,
        Err(error) => return fail(&error),
    };
    if !dry_run {
        eprintln!("{}", messages::NOT_IMPLEMENTED);
        return ExitCode::Error;
    }
    show_plan(&plan);
    if plan.is_refused() {
        eprintln!("{}", messages::NET_REFUSED_STOP);
        ExitCode::Refused
    } else {
        ExitCode::Success
    }
}

/// Show the error. A limit error is a refusal. Other errors are failures.
fn fail(error: &pqaudit_scan_net::scope::ScopeError) -> ExitCode {
    eprintln!(
        "{}",
        messages::SCOPE_LOAD.replace("{reason}", &error.to_string())
    );
    if error.is_refusal() {
        ExitCode::Refused
    } else {
        ExitCode::Error
    }
}

/// Show each planned target and each refusal.
fn show_plan(plan: &TargetPlan) {
    for target in &plan.targets {
        let template = if target.host.is_some() {
            messages::NET_TARGET_NAMED
        } else {
            messages::NET_TARGET_IP
        };
        let protocol = match target.protocol {
            Protocol::Tls => "tls",
            Protocol::Ssh => "ssh",
        };
        println!(
            "{}",
            template
                .replace("{host}", target.host.as_deref().unwrap_or_default())
                .replace("{ip}", &target.ip.to_string())
                .replace("{port}", &target.port.to_string())
                .replace("{protocol}", protocol)
                .replace("{connections}", &target.connections.to_string())
        );
    }
    for refusal in &plan.refused {
        println!(
            "{}",
            messages::NET_REFUSED
                .replace("{target}", &refusal.target)
                .replace("{reason}", &refusal.reason.to_string())
        );
    }
    if plan.targets.is_empty() && !plan.is_refused() {
        println!("{}", messages::NET_NO_TARGETS);
    }
    println!(
        "{}",
        messages::NET_SUMMARY
            .replace("{targets}", &plan.targets.len().to_string())
            .replace("{refused}", &plan.refused.len().to_string())
    );
}
