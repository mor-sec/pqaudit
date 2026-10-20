//! The `cbom` command: make a CycloneDX cryptography bill of materials.

use std::fs;
use std::path::{Path, PathBuf};

use pqaudit_report::cbom;

use crate::cli::Cli;
use crate::commands::assessment;
use crate::exit::ExitCode;
use crate::messages;

/// Run `cbom`.
pub fn run(cli: &Cli, results: Option<&Path>, output: Option<&Path>) -> ExitCode {
    let (assessment, active) = match assessment::load_with_pack(cli, results) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let value = cbom::render(&assessment, &active.pack);
    let path: PathBuf = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cli.engagement.join("reports").join("cbom.cdx.json"));
    let written = serde_json::to_string_pretty(&value)
        .map_err(std::io::Error::other)
        .and_then(|text| {
            if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
                fs::create_dir_all(dir)?;
            }
            fs::write(&path, text)
        });
    if let Err(error) = written {
        eprintln!(
            "{}",
            messages::CBOM_WRITE
                .replace("{path}", &path.display().to_string())
                .replace("{reason}", &error.to_string())
        );
        return ExitCode::Error;
    }
    println!(
        "{}",
        messages::CBOM_WRITTEN.replace("{path}", &path.display().to_string())
    );
    ExitCode::Success
}
