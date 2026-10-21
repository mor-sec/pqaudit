//! The `sign-release` task: check the Sigstore bundles, write the checksum files, and sign them.

use std::fs;
use std::path::Path;
use std::process::Command;

use sha2::Sha256;
use sha3::{Digest, Sha3_256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// True when a file name belongs to the signing output, not to the release payload.
fn is_signing_file(name: &str) -> bool {
    name.ends_with(".sigstore.json")
        || name.ends_with(".sig.json")
        || name.ends_with(".ed25519.sig")
        || name.ends_with(".mldsa65.sig")
        || name == "SHA256SUMS"
        || name == "SHA3-256SUMS"
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The exact certificate identity of the release workflow run for `tag` in `repo` (`owner/name`).
fn identity(repo: &str, tag: &str) -> String {
    format!("https://github.com/{repo}/.github/workflows/release.yml@refs/tags/{tag}")
}

/// True for a rules pack archive. Its version is the pack version, not the release tag.
fn is_pack_archive(name: &str) -> bool {
    name.starts_with("rules-") && name.ends_with(".tar.zst")
}

/// Check the Sigstore bundles of all files in `dir`. Compute the checksum files from those files.
/// Write them if they are missing. Fail if a checksum file is there and is different.
/// Sign both checksum files with the keys in `keys`.
///
/// The task runs `cosign verify-blob` from the PATH with the exact identity of the workflow run for `tag`.
/// The bundle must also come from a run on `commit`, the full commit SHA of the tag.
/// It fails if a bundle is missing or wrong, or if a file name does not hold the tag.
pub fn run(keys: &Path, dir: &Path, repo: &str, tag: &str, commit: &str) -> Result<()> {
    let full_sha = commit.len() == 40
        && commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !full_sha {
        return Err(format!(
            "The commit {commit} is not a full commit SHA. Give 40 lower case hex digits."
        )
        .into());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type()?.is_file() && !is_signing_file(&name) {
            names.push(name);
        }
    }
    names.sort();
    if names.is_empty() {
        return Err("The release directory has no files.".into());
    }
    for name in &names {
        if !name.contains(tag) && !is_pack_archive(name) {
            return Err(format!("The name of {name} does not contain the tag {tag}.").into());
        }
    }
    for name in &names {
        let bundle = dir.join(format!("{name}.sigstore.json"));
        if !bundle.is_file() {
            return Err(format!("The Sigstore bundle of {name} is missing.").into());
        }
        let status = Command::new("cosign")
            .arg("verify-blob")
            .arg(dir.join(name))
            .arg("--bundle")
            .arg(&bundle)
            .arg("--certificate-identity")
            .arg(identity(repo, tag))
            .arg("--certificate-oidc-issuer")
            .arg(OIDC_ISSUER)
            .arg("--certificate-github-workflow-sha")
            .arg(commit)
            .status()
            .map_err(|error| format!("Cannot run cosign: {error}"))?;
        if !status.success() {
            return Err(format!("The Sigstore check of {name} failed.").into());
        }
    }

    let mut sha256 = String::new();
    let mut sha3 = String::new();
    for name in &names {
        let data = fs::read(dir.join(name))?;
        sha256 += &format!("{}  {name}\n", hex(&Sha256::digest(&data)));
        sha3 += &format!("{}  {name}\n", hex(&Sha3_256::digest(&data)));
    }
    // Check both files before the task signs one. Never sign a file that the task did not compute.
    let sums = [("SHA256SUMS", sha256), ("SHA3-256SUMS", sha3)];
    for (file, text) in &sums {
        let path = dir.join(file);
        if path.exists() && fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            return Err(format!(
                "{file} is in the release directory and does not match the verified files. Remove it and run the task again."
            )
            .into());
        }
    }
    for (file, text) in &sums {
        let path = dir.join(file);
        if !path.exists() {
            fs::write(&path, text)?;
        }
        crate::sign::run(keys, &path)?;
    }
    Ok(())
}
