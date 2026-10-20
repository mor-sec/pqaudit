//! The pqaudit binary.

fn main() -> std::process::ExitCode {
    pqaudit_cli::run(std::env::args_os()).into()
}
