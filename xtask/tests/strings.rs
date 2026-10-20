//! Tests for the `strings` command of xtask.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Make an empty directory that is unique for this test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xtask-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Run `xtask strings` and return its output directory.
fn run_strings(root: &Path, out: &Path, extra: &[&str]) {
    let status = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("strings")
        .arg("--root")
        .arg(root)
        .arg("--out")
        .arg(out)
        .args(extra)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn strings_extracts_help_and_messages() {
    let out = scratch("help");
    run_strings(&workspace_root(), &out, &["--commits", "HEAD..HEAD"]);
    let help = fs::read_to_string(out.join("cli-help.md")).unwrap();
    assert!(help.contains("Use this directory as the engagement directory."));
    assert!(help.contains("Scan files on disk."), "subcommand help");
    let messages = fs::read_to_string(out.join("messages.md")).unwrap();
    assert!(messages.contains(pqaudit_cli::messages::NOT_IMPLEMENTED));
}

#[test]
fn strings_extracts_comments() {
    let root = scratch("comments");
    let src = root.join("crates/demo/src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        "/// Read the file.\nfn a() {}\n\nfn b() {\n    // Stop here.\n\n    // SAFETY: Mark.\n\n    // rustfmt::skip\n}\n",
    )
    .unwrap();
    let git = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&root)
        .status()
        .unwrap();
    assert!(git.success());
    let out = scratch("comments-out");
    run_strings(&root, &out, &[]);
    let comments = fs::read_to_string(out.join("comments.md")).unwrap();
    assert!(comments.contains("lib.rs:1"), "{comments}");
    assert!(comments.contains("Read the file."));
    assert!(comments.contains("lib.rs:5"), "{comments}");
    assert!(comments.contains("Stop here."));
    assert!(comments.contains("Mark."), "label is removed, text stays");
    assert!(!comments.contains("SAFETY"));
    assert!(!comments.contains("rustfmt"));
    assert_eq!(comments.matches("\n## ").count(), 3, "{comments}");
}

#[test]
fn strings_extracts_commits() {
    let repo = scratch("commits");
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .current_dir(&repo)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q"]);
    fs::write(repo.join("a.txt"), "a").unwrap();
    git(&["add", "a.txt"]);
    git(&["commit", "-q", "-m", "Add the file"]);
    let out = scratch("commits-out");
    run_strings(&repo, &out, &[]);
    let commits = fs::read_to_string(out.join("commits.md")).unwrap();
    assert!(commits.contains("Add the file"), "{commits}");
}
