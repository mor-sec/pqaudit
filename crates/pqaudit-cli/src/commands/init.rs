//! The `init` command: make an engagement directory with the template files.

use std::fs;
use std::path::Path;

use crate::exit::ExitCode;
use crate::messages;

/// The template files. Each entry is a file name and its text.
const TEMPLATES: [(&str, &str); 5] = [
    (
        "engagement.toml",
        include_str!("../templates/engagement.toml"),
    ),
    ("scope.toml", include_str!("../templates/scope.toml")),
    ("assets.toml", include_str!("../templates/assets.toml")),
    (
        "overrides.toml",
        include_str!("../templates/overrides.toml"),
    ),
    ("scoring.toml", include_str!("../templates/scoring.toml")),
];

/// Make `<parent>/<name>/` with the templates, `results/`, and `reports/`.
pub fn run(name: &str, parent: &Path) -> ExitCode {
    let dir = parent.join(name);
    match make(&dir) {
        Ok(()) => {
            println!("{} {}", messages::INIT_CREATED, dir.display());
            println!("{}", messages::INIT_NEXT);
            ExitCode::Success
        }
        Err(Failure::NotEmpty) => {
            eprintln!(
                "{}",
                messages::INIT_NOT_EMPTY.replace("{dir}", &dir.display().to_string())
            );
            ExitCode::Error
        }
        Err(Failure::Io(error)) => {
            eprintln!(
                "{}",
                messages::INIT_IO
                    .replace("{dir}", &dir.display().to_string())
                    .replace("{reason}", &error.to_string())
            );
            ExitCode::Error
        }
    }
}

enum Failure {
    NotEmpty,
    Io(std::io::Error),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Failure::Io(error)
    }
}

fn make(dir: &Path) -> Result<(), Failure> {
    if dir.exists() {
        // A path that is not a directory also fails here, with an I/O error.
        if fs::read_dir(dir)?.next().is_some() {
            return Err(Failure::NotEmpty);
        }
    } else {
        fs::create_dir_all(dir)?;
    }
    for (name, text) in TEMPLATES {
        fs::write(dir.join(name), text)?;
    }
    fs::create_dir(dir.join("results"))?;
    fs::create_dir(dir.join("reports"))?;
    Ok(())
}
