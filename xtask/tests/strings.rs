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
    assert!(messages.contains(pqaudit_cli::messages::LATER_RELEASE));
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

#[test]
fn strings_extracts_rules_text() {
    let root = scratch("rules");
    fs::create_dir_all(root.join("rules/rules")).unwrap();
    fs::write(
        root.join("rules/rules/tls.yaml"),
        "rules:\n  - id: TLS-1\n    title: Old protocol\n    description: >-\n      The server accepts\n      an old protocol.\n    remediation: Turn it off.\n    milestones:\n      - description: Plan the change.\n  - id: TLS-2\n    other: Not text.\n    title: Weak cipher\n",
    )
    .unwrap();
    fs::write(root.join("rules/pack.toml"), "title = \"Ignored\"\n").unwrap();
    let git = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&root)
        .status()
        .unwrap();
    assert!(git.success());
    let out = scratch("rules-out");
    run_strings(&root, &out, &[]);
    let text = fs::read_to_string(out.join("rules-text.md")).unwrap();
    for expected in [
        "Old protocol.",
        "The server accepts an old protocol.",
        "Turn it off.",
        "Plan the change.",
        "Weak cipher.",
    ] {
        assert!(text.contains(expected), "{expected} missing in {text}");
    }
    assert!(!text.contains("Not text"));
    assert!(!text.contains("Ignored"));
}

#[test]
fn strings_skips_missing_rules_folder() {
    let root = scratch("norules");
    let out = scratch("norules-out");
    let git = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&root)
        .status()
        .unwrap();
    assert!(git.success());
    run_strings(&root, &out, &[]);
    let text = fs::read_to_string(out.join("rules-text.md")).unwrap();
    assert!(!text.contains("##"));
}

#[test]
fn strings_extracts_template_comments() {
    let root = scratch("templates");
    let dir = root.join("crates/pqaudit-cli/src/templates");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("a.toml"),
        "# Name the client.\n# Use the full name.\n\nclient = \"A # B\" # Trailing note.\n# other = 1\n# [table]\n#\n# Last note.\n",
    )
    .unwrap();
    let out = scratch("templates-out");
    run_strings(&root, &out, &[]);
    let text = fs::read_to_string(out.join("templates.md")).unwrap();
    assert!(text.contains("a.toml:1"), "{text}");
    assert!(
        text.contains("Name the client. Use the full name."),
        "{text}"
    );
    assert!(text.contains("Trailing note."), "{text}");
    assert!(text.contains("Last note."), "{text}");
    assert!(!text.contains("other = 1"), "{text}");
    assert!(!text.contains("[table]"), "{text}");
    assert!(!text.contains("A # B"), "{text}");
    assert_eq!(text.matches("\n## ").count(), 3, "{text}");
}

/// Return the text of the guide section whose heading is `heading`. The section ends at the next heading.
fn guide_section<'a>(guide: &'a str, heading: &str) -> Option<&'a str> {
    let start = guide.lines().position(|line| line == heading)?;
    let mut offset = 0;
    let mut begin = None;
    for (number, line) in guide.split_inclusive('\n').enumerate() {
        if number == start + 1 {
            begin = Some(offset);
        }
        if number > start && line.starts_with('#') {
            return begin.map(|b| &guide[b..offset]);
        }
        offset += line.len();
    }
    begin.map(|b| &guide[b..])
}

/// True if the text holds the whole flag. A longer flag with the same start does not count.
fn has_flag(text: &str, flag: &str) -> bool {
    text.match_indices(flag).any(|(at, _)| {
        !text[at + flag.len()..]
            .chars()
            .next()
            .is_some_and(|next| next.is_ascii_alphanumeric() || next == '-')
    })
}

#[test]
fn docs_mention_every_flag() {
    let out = scratch("docs-flags");
    let root = workspace_root();
    run_strings(&root, &out, &["--commits", "HEAD..HEAD"]);
    let help = fs::read_to_string(out.join("cli-help.md")).unwrap();
    let guide = fs::read_to_string(root.join("docs/user-guide.md")).unwrap();
    let global = guide_section(&guide, "### Global flags").expect("a section Global flags");
    let mut flags_seen = 0;
    for line in help.lines() {
        // A command has a heading like "## `pqaudit scan files`".
        if let Some(path) = line
            .strip_prefix("## `pqaudit")
            .and_then(|rest| rest.strip_suffix('`'))
        {
            let path = path.trim();
            if !path.is_empty() {
                assert!(
                    guide.contains(path),
                    "docs/user-guide.md lacks the command {path}"
                );
            }
        }
        // A flag has a heading like "### `pqaudit scan files --follow-symlinks`".
        let Some(rest) = line
            .strip_prefix("### `pqaudit")
            .and_then(|rest| rest.strip_suffix('`'))
        else {
            continue;
        };
        let words: Vec<&str> = rest.split_whitespace().collect();
        let Some(flag) = words.last().filter(|word| word.starts_with("--")) else {
            continue;
        };
        flags_seen += 1;
        let path = &words[..words.len() - 1];
        if path.is_empty() {
            assert!(
                has_flag(global, flag),
                "the section Global flags lacks {flag}"
            );
            continue;
        }
        // The flag can be a global flag. Then the section Global flags names it.
        if has_flag(global, flag) {
            continue;
        }
        // Use the section of the longest part of the command path that has a section.
        let section = (1..=path.len()).rev().find_map(|length| {
            guide_section(&guide, &format!("### pqaudit {}", path[..length].join(" ")))
        });
        let section = section.unwrap_or_else(|| panic!("no section for {path:?}"));
        assert!(
            has_flag(section, flag),
            "the section of {} lacks {flag}",
            path.join(" ")
        );
    }
    assert!(
        flags_seen >= 40,
        "the test found too few flags: {flags_seen}"
    );
}
