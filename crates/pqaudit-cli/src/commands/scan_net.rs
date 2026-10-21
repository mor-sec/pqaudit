//! The `scan net` command: show the plan, or probe the targets of the scope file.
//!
//! The command checks the plan and the allowed hours before it opens a socket.

use std::path::Path;

use chrono::{Local, Utc};
use pqaudit_core::engagement::Engagement;
use pqaudit_core::SCHEMA_VERSION;
use pqaudit_core::{PackRef, Protocol, ResultsFile, ResultsHeader, RunInfo, ScannerKind};
use pqaudit_scan_net::audit::{hash_file, AuditLog};
use pqaudit_scan_net::runtime::{check_hours, run_until, NetOutput};
use pqaudit_scan_net::scope::{build_plan, scope_hash, ScopeFile, SystemResolver, TargetPlan};
use pqaudit_scan_net::tls::RealProbes;
use uuid::Uuid;

use pqaudit_scan_files::local_host_name;

use super::scan_files::{engagement_name, write_results};
use crate::cli::Cli;
use crate::commands::pack::load_active;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// The name of the audit log in the engagement directory.
const AUDIT_LOG_FILE: &str = "audit.log";
/// The most scan errors that the command shows on the screen.
const MAX_SHOWN_ERRORS: usize = 50;

/// Run `scan net`.
pub fn run(cli: &Cli, dry_run: bool, output: Option<&Path>) -> ExitCode {
    let (scope, bytes) = match ScopeFile::load(&cli.engagement) {
        Ok(loaded) => loaded,
        Err(error) => return fail(&error),
    };
    let plan = match build_plan(&scope, &SystemResolver) {
        Ok(plan) => plan,
        Err(error) => return fail(&error),
    };
    output::debug(
        &messages::NET_SUMMARY
            .replace("{targets}", &plan.targets.len().to_string())
            .replace("{refused}", &plan.refused.len().to_string()),
    );
    if dry_run || plan.is_refused() {
        show_plan(&plan);
    }
    if plan.is_refused() {
        eprintln!("{}", messages::NET_REFUSED_STOP);
        return ExitCode::Refused;
    }
    if dry_run {
        return ExitCode::Success;
    }
    // The time window comes before any connection and before any file write.
    if let Err(error) = check_hours(scope.allowed_hours.as_ref(), Local::now().time()) {
        return fail(&error);
    }
    if plan.targets.is_empty() {
        eprintln!("{}", messages::NET_NOTHING_TO_SCAN);
        return ExitCode::Error;
    }
    scan(cli, &scope, &plan, &bytes, output)
}

/// Probe the targets of a plan that passed the safety checks.
fn scan(
    cli: &Cli,
    scope: &ScopeFile,
    plan: &TargetPlan,
    scope_bytes: &[u8],
    output_path: Option<&Path>,
) -> ExitCode {
    let started = Utc::now();
    let engagement = match Engagement::load(&cli.engagement) {
        Ok(engagement) => engagement,
        Err(error) => return fail_text(messages::ENGAGEMENT_LOAD, &error.to_string()),
    };
    let active = match load_active(cli) {
        Ok(active) => active,
        Err(code) => return code,
    };
    let audit_path = engagement.dir.join(AUDIT_LOG_FILE);
    let audit = match AuditLog::open(&audit_path) {
        Ok(audit) => audit,
        Err(error) => {
            return fail_text(
                &messages::AUDIT_OPEN.replace("{path}", &audit_path.display().to_string()),
                &error.to_string(),
            )
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return fail_text(messages::NET_RUNTIME, &error.to_string()),
    };

    let run_id = Uuid::new_v4();
    let probes = RealProbes::new(scope.legacy_tls_check);
    // Ctrl-C stops the run. The tool keeps the results of the finished targets.
    // Each open connection writes its final audit line when the run drops.
    let output = runtime.block_on(run_until(
        plan,
        &probes,
        &audit,
        run_id,
        &active.pack,
        async {
            // If the handler cannot start, the scan must not stop. Wait for ever then.
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
        },
    ));
    let finished = Utc::now();

    let audit_hash = match audit.sync().and_then(|()| hash_file(&audit_path)) {
        Ok(hash) => hash,
        Err(error) => {
            return fail_text(
                &messages::AUDIT_HASH.replace("{path}", &audit_path.display().to_string()),
                &error.to_string(),
            )
        }
    };
    let host = local_host_name();
    let scope_hash = scope_hash(scope_bytes);
    let results = ResultsFile {
        header: ResultsHeader {
            schema_version: SCHEMA_VERSION,
            engagement: engagement_name(&engagement),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_pack: PackRef {
                id: active.pack.id.clone(),
                version: active.pack.version.to_string(),
                content_hash: active.pack.content_hash.clone(),
                origin: (&active.origin).into(),
            },
            scanner: ScannerKind::Net,
            host: host.clone(),
            operator: engagement.config.assessor.clone(),
            started,
            finished,
            scope_hash: Some(scope_hash.clone()),
            audit_log_hash: Some(audit_hash.clone()),
            runs: vec![RunInfo {
                run_id,
                scanner: ScannerKind::Net,
                host,
                started,
                scope_hash: Some(scope_hash),
                audit_log_hash: Some(audit_hash),
            }],
            redacted: false,
        },
        findings: output.findings.clone(),
        inventory: output.inventory.clone(),
        errors: output.errors.clone(),
    };
    let path = match output_path {
        Some(path) => path.to_path_buf(),
        None => engagement
            .dir
            .join("results")
            .join(format!("net-{}.pqr", started.format("%Y%m%dT%H%M%S"))),
    };
    if let Err(error) = write_results(&results, &path) {
        return fail_text(
            &messages::RESULTS_WRITE.replace("{path}", &path.display().to_string()),
            &error.to_string(),
        );
    }
    report(
        cli,
        &output,
        &path,
        &audit_path,
        plan.targets.len(),
        audit.is_broken(),
    )
}

/// Show the summary and choose the exit code.
fn report(
    cli: &Cli,
    output: &NetOutput,
    results_path: &Path,
    audit_path: &Path,
    targets: usize,
    audit_broken: bool,
) -> ExitCode {
    for error in output.errors.iter().take(MAX_SHOWN_ERRORS) {
        output::error(
            &messages::SCAN_ERROR_LINE
                .replace("{location}", &error.location)
                .replace("{reason}", &error.reason),
        );
    }
    if output.errors.len() > MAX_SHOWN_ERRORS {
        eprintln!(
            "{}",
            messages::SCAN_ERRORS_HIDDEN.replace(
                "{count}",
                &(output.errors.len() - MAX_SHOWN_ERRORS).to_string()
            )
        );
    }
    output::summary(
        cli,
        &messages::NET_SCAN_SUMMARY
            .replace("{targets}", &targets.to_string())
            .replace("{findings}", &output.findings.len().to_string())
            .replace("{inventory}", &output.inventory.len().to_string())
            .replace("{errors}", &output.errors.len().to_string()),
    );
    output::summary(
        cli,
        &format!(
            "{} {}",
            messages::SCAN_RESULTS,
            output::shown_path(results_path)
        ),
    );
    output::summary(
        cli,
        &format!(
            "{} {}",
            messages::NET_AUDIT_LOG,
            output::shown_path(audit_path)
        ),
    );
    if audit_broken {
        eprintln!("{}", messages::AUDIT_FAILED);
        ExitCode::Error
    } else if output.errors.is_empty() {
        ExitCode::Success
    } else {
        ExitCode::Partial
    }
}

fn fail_text(text: &str, reason: &str) -> ExitCode {
    output::error(&text.replace("{reason}", reason));
    ExitCode::Error
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
        output::line(
            &template
                .replace("{host}", target.host.as_deref().unwrap_or_default())
                .replace("{ip}", &target.ip.to_string())
                .replace("{port}", &target.port.to_string())
                .replace("{protocol}", protocol)
                .replace("{connections}", &target.connections.to_string()),
        );
    }
    for refusal in &plan.refused {
        output::line(
            &messages::NET_REFUSED
                .replace("{target}", &refusal.target)
                .replace("{reason}", &refusal.reason.to_string()),
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
