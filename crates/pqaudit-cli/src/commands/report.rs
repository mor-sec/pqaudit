//! The `report` command: make a report from a results file.

use std::fs;
use std::path::{Path, PathBuf};

use pqaudit_report::{technical, Format};

use crate::cli::{Audience, Cli, ReportFormat};
use crate::commands::assessment;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// The arguments of `report`.
pub struct ReportArgs<'a> {
    /// The audience of the report.
    pub audience: Audience,
    /// The format of the report.
    pub format: ReportFormat,
    /// The results file, if the user gave one.
    pub results: Option<&'a Path>,
    /// The output file, if the user gave one.
    pub output: Option<&'a Path>,
}

/// Run `report`.
pub fn run(cli: &Cli, args: ReportArgs<'_>) -> ExitCode {
    if args.audience != Audience::Technical || args.format == ReportFormat::Pdf {
        output::error(messages::LATER_RELEASE);
        return ExitCode::Error;
    }
    let (format, extension) = match args.format {
        ReportFormat::Html => (Format::Html, "html"),
        ReportFormat::Md => (Format::Md, "md"),
        ReportFormat::Json => (Format::Json, "json"),
        ReportFormat::Pdf => {
            output::error(messages::LATER_RELEASE);
            return ExitCode::Error;
        }
    };
    let assessment = match assessment::load(cli, args.results) {
        Ok(assessment) => assessment,
        Err(code) => return code,
    };
    let text = match technical::render(&assessment, format) {
        Ok(text) => text,
        Err(error) => {
            output::error(&error.to_string());
            return ExitCode::Error;
        }
    };
    let path: PathBuf = args.output.map(Path::to_path_buf).unwrap_or_else(|| {
        cli.engagement
            .join("reports")
            .join(format!("technical.{extension}"))
    });
    let written = match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => fs::create_dir_all(dir),
        None => Ok(()),
    }
    .and_then(|()| fs::write(&path, text));
    if let Err(error) = written {
        output::error(
            &messages::REPORT_WRITE
                .replace("{path}", &path.display().to_string())
                .replace("{reason}", &error.to_string()),
        );
        return ExitCode::Error;
    }
    output::summary(
        cli,
        &messages::REPORT_WRITTEN.replace("{path}", &path.display().to_string()),
    );
    ExitCode::Success
}
