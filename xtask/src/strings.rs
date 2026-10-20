//! Extract the project text, so that the STE lint can check it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::CommandFactory;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Write the six text files to `out`.
pub fn run(root: &Path, out: &Path, commits: Option<&str>) -> Result<()> {
    fs::create_dir_all(out)?;
    fs::write(out.join("cli-help.md"), cli_help())?;
    fs::write(out.join("messages.md"), messages())?;
    fs::write(out.join("rules-text.md"), rules_text(&root.join("rules"))?)?;
    fs::write(out.join("comments.md"), comments(root)?)?;
    fs::write(out.join("templates.md"), templates(root)?)?;
    fs::write(out.join("commits.md"), commit_messages(root, commits)?)?;
    Ok(())
}

/// Collapse white space, so that one text is one Markdown paragraph.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Clap removes the last full stop of a short help text. Put it back.
fn end_sentence(text: &str) -> String {
    let text = one_line(text);
    if text.ends_with(['.', '!', '?', ':']) {
        text
    } else {
        format!("{text}.")
    }
}

fn cli_help() -> String {
    let mut out = String::from("# Command-line help\n\n");
    let mut root = pqaudit_cli::cli::Cli::command();
    root.build();
    help_of(&root, "pqaudit", &mut out);
    out
}

/// Add the help text of one command and of its subcommands.
fn help_of(command: &clap::Command, path: &str, out: &mut String) {
    let about = command
        .get_long_about()
        .or_else(|| command.get_about())
        .map(ToString::to_string);
    let _ = writeln!(out, "## `{path}`\n");
    if let Some(about) = about {
        let _ = writeln!(out, "{}\n", end_sentence(&about));
    }
    for arg in command.get_arguments() {
        if matches!(arg.get_id().as_str(), "help" | "version") {
            continue;
        }
        let help = arg.get_long_help().or_else(|| arg.get_help());
        if let Some(help) = help {
            let _ = writeln!(out, "### `{path} {}`\n", arg_name(arg));
            let _ = writeln!(out, "{}\n", end_sentence(&help.to_string()));
        }
        for value in arg.get_possible_values() {
            if let Some(help) = value.get_help() {
                let _ = writeln!(out, "{}\n", end_sentence(&help.to_string()));
            }
        }
    }
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        help_of(sub, &format!("{path} {}", sub.get_name()), out);
    }
}

fn arg_name(arg: &clap::Arg) -> String {
    match arg.get_long() {
        Some(long) => format!("--{long}"),
        None => arg.get_id().to_string(),
    }
}

fn messages() -> String {
    let all: [(&str, &[(&str, &str)]); 6] = [
        ("pqaudit-cli", pqaudit_cli::messages::ALL),
        ("pqaudit-core", pqaudit_core::messages::ALL),
        ("pqaudit-rules", pqaudit_rules::messages::ALL),
        ("pqaudit-scan-files", pqaudit_scan_files::messages::ALL),
        ("pqaudit-scan-net", pqaudit_scan_net::messages::ALL),
        ("pqaudit-report", pqaudit_report::messages::ALL),
    ];
    let mut out = String::from("# Messages\n\n");
    for (krate, list) in all {
        for (id, text) in list {
            let _ = writeln!(out, "## `{krate} {id}`\n\n{}\n", one_line(text));
        }
    }
    out
}

/// Read the text fields of the rules pack. The folder may not exist yet.
fn rules_text(dir: &Path) -> Result<String> {
    let mut out = String::from("# Rules text\n\n");
    if !dir.is_dir() {
        return Ok(out);
    }
    let mut files = Vec::new();
    collect_files(dir, "yaml", &mut files)?;
    collect_files(dir, "yml", &mut files)?;
    files.sort();
    for file in files {
        let value: serde_yaml::Value = serde_yaml::from_str(&fs::read_to_string(&file)?)
            .map_err(|error| format!("{}: {error}", file.display()))?;
        let name = file
            .strip_prefix(dir.parent().unwrap_or(dir))
            .unwrap_or(&file);
        let mut found = Vec::new();
        yaml_text_fields(&value, String::new(), &mut found);
        for (path, text) in found {
            let _ = writeln!(
                out,
                "## `{} {path}`\n\n{}\n",
                name.display(),
                end_sentence(&text)
            );
        }
    }
    Ok(out)
}

/// Find the fields `title`, `description`, and `remediation` at any depth.
fn yaml_text_fields(value: &serde_yaml::Value, path: String, found: &mut Vec<(String, String)>) {
    const KEYS: [&str; 3] = ["title", "description", "remediation"];
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                let Some(key) = key.as_str() else { continue };
                let path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                match child.as_str() {
                    Some(text) if KEYS.contains(&key) => found.push((path, text.to_string())),
                    _ => yaml_text_fields(child, path, found),
                }
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for (index, child) in items.iter().enumerate() {
                yaml_text_fields(child, format!("{path}[{index}]"), found);
            }
        }
        _ => {}
    }
}

fn collect_files(dir: &Path, extension: &str, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            if entry.file_name() != "target" && entry.file_name() != ".git" {
                collect_files(&path, extension, files)?;
            }
        } else if path.extension().is_some_and(|e| e == extension) {
            files.push(path);
        }
    }
    Ok(())
}

fn comments(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    for top in ["crates", "xtask"] {
        let dir = root.join(top);
        if dir.is_dir() {
            collect_files(&dir, "rs", &mut files)?;
        }
    }
    let mut out = String::from("# Code comments\n\n");
    for file in files {
        let text = fs::read_to_string(&file)?;
        let name = file.strip_prefix(root).unwrap_or(&file);
        for (line, paragraph) in comment_paragraphs(&text) {
            let _ = writeln!(out, "## `{}:{line}`\n\n{paragraph}\n", name.display());
        }
    }
    Ok(out)
}

/// Return the comment text of one that is on a line with code, if any.
fn trailing_comment(line: &str) -> Option<&str> {
    let mut quotes = 0;
    let mut previous = ' ';
    for (index, c) in line.char_indices() {
        if c == '"' && previous != '\\' {
            quotes += 1;
        }
        if quotes % 2 == 0 && c == '/' && line[index..].starts_with("//") && previous == ' ' {
            return Some(&line[index..]);
        }
        previous = c;
    }
    None
}

/// Return the text of a comment line, or `None` for other lines.
fn comment_text(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let comment = if trimmed.starts_with("//") {
        trimmed
    } else {
        trailing_comment(line)?
    };
    let body = comment
        .strip_prefix("///")
        .or_else(|| comment.strip_prefix("//!"))
        .or_else(|| comment.strip_prefix("//"))?;
    Some(body.strip_prefix(' ').unwrap_or(body).trim_end())
}

/// A comment that only tells a tool what to do, not a person.
fn is_directive(text: &str) -> bool {
    let first = text.split_whitespace().next().unwrap_or("");
    first.contains("::") || text.starts_with("rustfmt:") || text.starts_with("cargo:")
}

/// Join adjacent comment lines. Return the first line number and the text.
fn comment_paragraphs(source: &str) -> Vec<(usize, String)> {
    let mut result = Vec::new();
    let mut current: Option<(usize, String)> = None;
    let mut in_code = false;
    let mut flush = |current: &mut Option<(usize, String)>| {
        if let Some(done) = current.take() {
            if !done.1.is_empty() {
                result.push(done);
            }
        }
    };
    for (index, line) in source.lines().enumerate() {
        let Some(text) = comment_text(line) else {
            flush(&mut current);
            in_code = false;
            continue;
        };
        if text.trim_start().starts_with("```") {
            flush(&mut current);
            in_code = !in_code;
            continue;
        }
        if in_code || text.is_empty() || is_directive(text) {
            flush(&mut current);
            continue;
        }
        let text = text.strip_prefix("SAFETY:").map_or(text, str::trim_start);
        if line.trim_start().starts_with("//") {
            match &mut current {
                Some((_, paragraph)) => {
                    paragraph.push(' ');
                    paragraph.push_str(text);
                }
                None => current = Some((index + 1, text.to_string())),
            }
        } else {
            // A comment after code is a paragraph of its own.
            flush(&mut current);
            current = Some((index + 1, text.to_string()));
            flush(&mut current);
        }
    }
    flush(&mut current);
    result
}

/// Return the comment text of a TOML line, or `None` if the line has no prose comment.
///
/// A comment that holds a commented-out key or table is example code. It is not prose.
fn toml_comment(line: &str) -> Option<&str> {
    let mut in_string = false;
    let mut previous = ' ';
    for (index, c) in line.char_indices() {
        if c == '"' && previous != '\\' {
            in_string = !in_string;
        }
        if c == '#' && !in_string {
            let body = line[index + 1..].trim();
            return Some(body.strip_prefix(' ').unwrap_or(body));
        }
        previous = c;
    }
    None
}

/// A comment that is an example key (`name = value`) or an example table (`[name]`).
fn is_toml_example(text: &str) -> bool {
    let is_key = text.split_once('=').is_some_and(|(key, _)| {
        !key.trim().is_empty()
            && key
                .trim()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    });
    is_key || (text.starts_with('[') && text.ends_with(']'))
}

/// Join adjacent comment lines of a TOML file. Return the first line number and the text.
fn toml_paragraphs(source: &str) -> Vec<(usize, String)> {
    let mut result: Vec<(usize, String)> = Vec::new();
    let mut open = false;
    for (index, line) in source.lines().enumerate() {
        let text = toml_comment(line).filter(|t| !t.is_empty() && !is_toml_example(t));
        let Some(text) = text else {
            open = false;
            continue;
        };
        let whole_line = line.trim_start().starts_with('#');
        match result.last_mut() {
            Some((_, paragraph)) if open && whole_line => {
                paragraph.push(' ');
                paragraph.push_str(text);
            }
            _ => result.push((index + 1, text.to_string())),
        }
        open = whole_line;
    }
    result
}

/// Read the comments of the template files of the CLI.
fn templates(root: &Path) -> Result<String> {
    let dir = root.join("crates/pqaudit-cli/src/templates");
    let mut out = String::from("# Template comments\n\n");
    if !dir.is_dir() {
        return Ok(out);
    }
    let mut files = Vec::new();
    collect_files(&dir, "toml", &mut files)?;
    files.sort();
    for file in files {
        let name = file.strip_prefix(root).unwrap_or(&file);
        for (line, paragraph) in toml_paragraphs(&fs::read_to_string(&file)?) {
            let _ = writeln!(out, "## `{}:{line}`\n\n{paragraph}\n", name.display());
        }
    }
    Ok(out)
}

fn git(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    Ok(Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?)
}

fn commit_messages(root: &Path, range: Option<&str>) -> Result<String> {
    let mut out = String::from("# Commit messages\n\n");
    if !git(root, &["rev-parse", "--verify", "-q", "HEAD"])?
        .status
        .success()
    {
        return Ok(out);
    }
    let range = match range {
        Some(range) => range.to_string(),
        None if git(root, &["rev-parse", "--verify", "-q", "origin/main"])?
            .status
            .success() =>
        {
            "origin/main..HEAD".to_string()
        }
        None => "HEAD".to_string(),
    };
    let log = git(root, &["log", "--format=%h%x01%B%x00", &range])?;
    if !log.status.success() {
        return Err(format!(
            "git log {range} failed: {}",
            String::from_utf8_lossy(&log.stderr).trim()
        )
        .into());
    }
    let text = String::from_utf8_lossy(&log.stdout);
    for entry in text.split('\0').filter(|e| !e.trim().is_empty()) {
        let (sha, message) = entry.trim().split_once('\u{1}').unwrap_or(("", entry));
        let _ = writeln!(out, "## {sha}\n");
        for paragraph in message.split("\n\n") {
            let paragraph = one_line(paragraph);
            if paragraph.is_empty() || paragraph.starts_with("Co-Authored-By:") {
                continue;
            }
            let _ = writeln!(out, "{paragraph}\n");
        }
    }
    Ok(out)
}
