//! The `check-offline-deps` task: the offline scanner must not depend on network crates.

use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The crate names that the offline scanner must not use.
const FORBIDDEN: [&str; 8] = [
    "tokio", "rustls", "hyper", "reqwest", "socket2", "mio", "ureq", "curl",
];

/// Run `cargo tree` for the offline scanner and check the crate names.
pub fn run() -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
    let output = Command::new(cargo)
        .args([
            "tree",
            "-p",
            "pqaudit-scan-files",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let text = String::from_utf8(output.stdout)?;
    let found = forbidden_crates(&text);
    if found.is_empty() {
        println!("The offline scanner has no network crates.");
        Ok(())
    } else {
        Err(format!(
            "pqaudit-scan-files depends on network crates: {}",
            found.join(", ")
        )
        .into())
    }
}

/// Return the forbidden crate names in the output of `cargo tree --prefix none`.
pub fn forbidden_crates(tree: &str) -> Vec<String> {
    let mut found: Vec<String> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| FORBIDDEN.iter().any(|bad| name.contains(bad)))
        .map(str::to_string)
        .collect();
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::forbidden_crates;

    #[test]
    fn finds_network_crates_by_name() {
        let tree = "pqaudit-scan-files v0.1.0\nserde v1.0.0\ntokio-util v0.7.0\nmio v1.0.0 (*)\n";
        assert_eq!(forbidden_crates(tree), vec!["mio", "tokio-util"]);
    }

    #[test]
    fn accepts_a_clean_tree() {
        assert!(forbidden_crates("pqaudit-scan-files v0.1.0\nwalkdir v2.5.0\n").is_empty());
    }
}
