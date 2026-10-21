//! Load the active rules pack and tell the user about its origin.

use pqaudit_core::PackOriginRef;
use pqaudit_report::technical::origin_text;
use pqaudit_rules::install::{active_pack, ActivePack, PackOrigin};

use crate::cli::Cli;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// Load the active rules pack.
///
/// The function writes a warning for each installed pack that it skipped.
/// It also writes a warning when the active pack has no valid signature.
/// On an error, it prints an error message and returns the exit code.
pub fn load_active(cli: &Cli) -> Result<ActivePack, ExitCode> {
    let active = active_pack(cli.allow_unsigned_rules).map_err(|error| {
        output::error(&messages::PACK_LOAD.replace("{reason}", &output::value(&error.to_string())));
        ExitCode::Error
    })?;
    for skipped in &active.skipped {
        output::warn(
            &messages::PACK_SKIPPED
                .replace("{version}", &output::value(&skipped.version))
                .replace("{path}", &output::shown_path(&skipped.path))
                .replace("{reason}", &output::value(&skipped.reason)),
        );
    }
    if matches!(active.origin, PackOrigin::Unsigned { .. }) {
        output::warn(messages::RULES_UNSIGNED_WARNING);
    }
    output::debug(
        &messages::LOG_PACK_ORIGIN
            .replace("{id}", &active.pack.id)
            .replace("{version}", &active.pack.version.to_string())
            .replace(
                "{origin}",
                &origin_text(&PackOriginRef::from(&active.origin)),
            ),
    );
    Ok(active)
}
