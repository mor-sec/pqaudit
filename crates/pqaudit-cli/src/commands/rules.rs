//! The `rules` command: show, check, and install rules packs.

use std::path::{Path, PathBuf};

use pqaudit_rules::install::{InstallError, InstalledState, PackOrigin, RulesStore};
use pqaudit_rules::pack::RulesPack;

use crate::cli::RulesCommand;
use crate::exit::ExitCode;
use crate::messages;

/// Run one `rules` command.
pub fn run(command: &RulesCommand, allow_unsigned: bool) -> ExitCode {
    let store = match RulesStore::for_user() {
        Ok(store) => store,
        Err(error) => return fail(&error),
    };
    match command {
        RulesCommand::List => list(&store, allow_unsigned),
        RulesCommand::Verify { archive, sig } => {
            verify(&store, archive, sig.as_deref(), allow_unsigned)
        }
        RulesCommand::Update { from, sig } => update(&store, from, sig.as_deref(), allow_unsigned),
    }
}

fn fail(error: &InstallError) -> ExitCode {
    eprintln!("{error}");
    ExitCode::Error
}

/// Return the signature path: the given path, or `<archive>.sig.json`.
fn sig_path(archive: &Path, sig: Option<&Path>) -> PathBuf {
    match sig {
        Some(sig) => sig.to_path_buf(),
        None => {
            let mut name = archive.as_os_str().to_os_string();
            name.push(".sig.json");
            PathBuf::from(name)
        }
    }
}

fn describe(pack: &RulesPack) -> String {
    format!("{} {}", pack.id, pack.version)
}

fn list(store: &RulesStore, allow_unsigned: bool) -> ExitCode {
    let active = match store.active_pack(allow_unsigned) {
        Ok(active) => active,
        Err(error) => return fail(&error),
    };
    let origin = match &active.origin {
        PackOrigin::Embedded => String::from("embedded"),
        PackOrigin::Installed { signed_by, .. } => format!("installed, signed by {signed_by}"),
        PackOrigin::Unsigned { .. } => String::from("installed, unsigned"),
    };
    println!(
        "active  {}  {origin}  {}",
        describe(&active.pack),
        active.pack.content_hash
    );
    for installed in store.list_installed() {
        match installed.state {
            InstalledState::Verified { pack, signed_by } => println!(
                "installed  {}  signed by {signed_by}  {}",
                describe(&pack),
                pack.content_hash
            ),
            InstalledState::Unverified { pack, reason } => println!(
                "installed  {}  unsigned: {reason}  {}",
                describe(&pack),
                pack.content_hash
            ),
            InstalledState::Invalid { reason } => {
                println!("installed  {}  invalid: {reason}", installed.version);
            }
        }
    }
    ExitCode::Success
}

fn verify(
    store: &RulesStore,
    archive: &Path,
    sig: Option<&Path>,
    allow_unsigned: bool,
) -> ExitCode {
    match store.verify(archive, &sig_path(archive, sig)) {
        Ok(verified) => {
            println!("{}", messages::RULES_SIGNATURE_OK);
            println!("pack: {}", describe(&verified.pack));
            println!("signed by: {}", verified.signed_by);
            println!("key chain:");
            for key in &verified.rotation_chain {
                println!("  {key}");
            }
            ExitCode::Success
        }
        Err(error) if allow_unsigned => match store.load_unsigned(archive) {
            Ok(pack) => {
                eprintln!("{error}");
                eprintln!("{}", messages::RULES_UNSIGNED_WARNING);
                println!("pack: {}", describe(&pack));
                ExitCode::Success
            }
            Err(_) => fail(&error),
        },
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{}", messages::RULES_UNSIGNED_HINT);
            ExitCode::Error
        }
    }
}

fn update(store: &RulesStore, from: &Path, sig: Option<&Path>, allow_unsigned: bool) -> ExitCode {
    match store.install(from, &sig_path(from, sig)) {
        Ok(dir) => {
            println!("{} {}", messages::RULES_INSTALLED, dir.display());
            ExitCode::Success
        }
        Err(error) if allow_unsigned => match store.install_unsigned(from) {
            Ok(dir) => {
                eprintln!("{error}");
                eprintln!("{}", messages::RULES_UNSIGNED_WARNING);
                println!("{} {}", messages::RULES_INSTALLED, dir.display());
                ExitCode::Success
            }
            Err(_) => fail(&error),
        },
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{}", messages::RULES_UNSIGNED_HINT);
            ExitCode::Error
        }
    }
}
