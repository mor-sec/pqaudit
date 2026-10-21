//! Tests for the `self-cbom` and `sign-release` tasks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Read the schema files that the CycloneDX schema names with a URI.
struct LocalSchemas;

impl jsonschema::Retrieve for LocalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let name = uri.path().as_str().rsplit('/').next().unwrap_or_default();
        Ok(serde_json::from_str(&fs::read_to_string(
            schema_dir().join(name),
        )?)?)
    }
}

fn schema_dir() -> PathBuf {
    workspace_root().join("crates/pqaudit-report/tests/schema")
}

fn validator() -> jsonschema::Validator {
    let text = fs::read_to_string(schema_dir().join("bom-1.6.schema.json")).unwrap();
    let schema: Value = serde_json::from_str(&text).unwrap();
    jsonschema::options()
        .with_retriever(LocalSchemas)
        .build(&schema)
        .unwrap()
}

const DECLARATION: &str = r#"
[[use]]
purpose = "tls-probe"
algorithms = ["X25519MLKEM768", "X25519", "RSA"]
crates = ["aws-lc-rs"]

[[use]]
purpose = "rules-pack-verify"
algorithms = ["Ed25519", "ML-DSA-65"]
crates = ["ed25519-dalek", "ml-dsa"]

[[use]]
purpose = "fingerprints"
algorithms = ["SHA-256"]
crates = ["sha2"]
"#;

fn sbom(names: &[&str]) -> String {
    let components: Vec<Value> = names
        .iter()
        .map(|name| serde_json::json!({"type": "library", "name": name, "version": "1.2.3"}))
        .collect();
    serde_json::json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components})
        .to_string()
}

/// Put a fake `cargo` first in a new directory. It logs its arguments.
/// The file `cargo-mode` in `dir` sets what it does: `empty` (default), `error`, or `output`.
#[cfg(unix)]
fn fake_cargo(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("cargo-bin");
    fs::create_dir_all(&bin).unwrap();
    let script = bin.join("cargo");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> {0}/cargo.log\ncase \"$(cat {0}/cargo-mode 2>/dev/null)\" in\n  error) echo boom >&2; exit 101;;\n  output) echo 'ring v0.17.14'; exit 0;;\nesac\nexit 0\n",
            dir.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[cfg(not(unix))]
fn fake_cargo(dir: &Path) -> PathBuf {
    dir.to_path_buf()
}

fn self_cbom(dir: &Path, names: &[&str], declaration: &str) -> Output {
    fs::write(dir.join("sbom.json"), sbom(names)).unwrap();
    fs::write(dir.join("self-crypto.toml"), declaration).unwrap();
    let path = format!(
        "{}{}{}",
        fake_cargo(dir).display(),
        if cfg!(windows) { ";" } else { ":" },
        std::env::var("PATH").unwrap()
    );
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .env("PATH", path)
        .env_remove("CARGO")
        .arg("self-cbom")
        .arg("--root")
        .arg(workspace_root())
        .arg("--sbom")
        .arg(dir.join("sbom.json"))
        .arg("--declaration")
        .arg(dir.join("self-crypto.toml"))
        .arg("--out")
        .arg(dir.join("cbom.json"))
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .unwrap()
}

const ALL: [&str; 4] = ["aws-lc-rs", "ed25519-dalek", "ml-dsa", "sha2"];

#[test]
fn undeclared_crypto_crate_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut names = ALL.to_vec();
    names.push("rustls");
    let output = self_cbom(dir.path(), &names, DECLARATION);
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("rustls"), "{message}");
    assert!(!dir.path().join("cbom.json").exists());
}

#[test]
fn declared_but_absent_crate_fails() {
    let dir = tempfile::tempdir().unwrap();
    let output = self_cbom(
        dir.path(),
        &["aws-lc-rs", "ed25519-dalek", "sha2"],
        DECLARATION,
    );
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("ml-dsa"), "{message}");
}

#[test]
fn valid_declaration_writes_cbom() {
    let dir = tempfile::tempdir().unwrap();
    let mut names = ALL.to_vec();
    names.push("serde");
    let output = self_cbom(dir.path(), &names, DECLARATION);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = fs::read_to_string(dir.path().join("cbom.json")).unwrap();
    let cbom: Value = serde_json::from_str(&text).unwrap();
    let errors: Vec<String> = validator()
        .iter_errors(&cbom)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(cbom["metadata"]["timestamp"], "2023-11-14T22:13:20Z");
    assert!(text.contains("alg:ML-DSA-65"));
    assert!(text.contains("pkg:cargo/aws-lc-rs@1.2.3"));
    assert!(text.contains("tls-probe"));
    // The same input gives the same CBOM.
    let again = self_cbom(dir.path(), &names, DECLARATION);
    assert!(again.status.success());
    assert_eq!(
        text,
        fs::read_to_string(dir.path().join("cbom.json")).unwrap()
    );
}

#[cfg(unix)]
mod sign_release {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TAG: &str = "v0.1.0";

    fn identity(tag: &str) -> String {
        format!("https://github.com/mor-sec/pqaudit/.github/workflows/release.yml@refs/tags/{tag}")
    }

    fn run_with_tag(keys: &Path, release: &Path, bin: &Path, tag: &str) -> Output {
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["sign-release", "--repo", "mor-sec/pqaudit", "--tag", tag])
            .args(["--commit", "0123456789abcdef0123456789abcdef01234567"])
            .arg("--keys")
            .arg(keys)
            .arg("--dir")
            .arg(release)
            .env("PATH", path)
            .output()
            .unwrap()
    }

    fn run(keys: &Path, release: &Path, bin: &Path) -> Output {
        run_with_tag(keys, release, bin, TAG)
    }

    /// A fake `cosign` in a new directory. It logs its arguments.
    /// It passes only if the identity argument equals the text in the bundle file.
    fn fake_cosign(dir: &Path) -> PathBuf {
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let script = bin.join("cosign");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> {}/cosign.log\n[ \"$3\" = --bundle ] && [ \"$5\" = --certificate-identity ] && [ \"$(cat \"$4\")\" = \"$6\" ]\n",
                dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        bin
    }

    /// Add a release file and a bundle that names the workflow run of `tag`.
    fn add_file(release: &Path, name: &str, tag: &str) {
        fs::write(release.join(name), b"x").unwrap();
        fs::write(release.join(format!("{name}.sigstore.json")), identity(tag)).unwrap();
    }

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let status = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["keygen", "--out"])
            .arg(&keys)
            .status()
            .unwrap();
        assert!(status.success());
        let release = dir.path().join("release");
        fs::create_dir_all(&release).unwrap();
        fs::write(release.join("pqaudit-v0.1.0-linux"), b"binary").unwrap();
        fs::write(
            release.join("pqaudit-v0.1.0-linux.sigstore.json"),
            identity(TAG),
        )
        .unwrap();
        (dir, keys, release)
    }

    #[test]
    fn writes_and_signs_the_checksum_files() {
        let (dir, keys, release) = setup();
        let bin = fake_cosign(dir.path());
        let output = run(&keys, &release, &bin);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let sums = fs::read_to_string(release.join("SHA256SUMS")).unwrap();
        assert_eq!(
            sums,
            format!("{}  pqaudit-v0.1.0-linux\n", sha256_of(b"binary"))
        );
        assert!(release.join("SHA3-256SUMS").is_file());
        for file in ["SHA256SUMS", "SHA3-256SUMS"] {
            for suffix in [".sig.json", ".ed25519.sig", ".mldsa65.sig"] {
                assert!(release.join(format!("{file}{suffix}")).is_file());
            }
        }
        let log = fs::read_to_string(dir.path().join("cosign.log")).unwrap();
        assert!(log.contains("verify-blob"));
        assert!(log.contains(&format!("--certificate-identity {}", identity(TAG))));
        assert!(!log.contains("regexp"));
    }

    fn sha256_of(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(data)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn tampered_checksum_file_is_not_signed() {
        let (dir, keys, release) = setup();
        fs::write(
            release.join("SHA256SUMS"),
            format!("{}  pqaudit-v0.1.0-linux\n", "0".repeat(64)),
        )
        .unwrap();
        let output = run(&keys, &release, &fake_cosign(dir.path()));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("SHA256SUMS"));
        for name in ["SHA256SUMS", "SHA3-256SUMS"] {
            for suffix in [".sig.json", ".ed25519.sig", ".mldsa65.sig"] {
                assert!(!release.join(format!("{name}{suffix}")).exists());
            }
        }
        assert!(!release.join("SHA3-256SUMS").exists());
    }

    #[test]
    fn matching_checksum_file_is_signed() {
        let (dir, keys, release) = setup();
        let bin = fake_cosign(dir.path());
        assert!(run(&keys, &release, &bin).status.success());
        // A second run sees the files it wrote and signs again.
        assert!(run(&keys, &release, &bin).status.success());
    }

    #[test]
    fn missing_bundle_fails() {
        let (dir, keys, release) = setup();
        fs::write(release.join("extra-v0.1.0.txt"), b"x").unwrap();
        let output = run(&keys, &release, &fake_cosign(dir.path()));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("extra-v0.1.0.txt"));
        assert!(!release.join("SHA256SUMS").exists());
    }

    #[test]
    fn bundle_of_another_tag_fails() {
        // An old binary with its own valid bundle, renamed to match the new tag.
        let (dir, keys, release) = setup();
        add_file(&release, "pqaudit-v0.1.0-old", "v0.0.9");
        let output = run(&keys, &release, &fake_cosign(dir.path()));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("pqaudit-v0.1.0-old"));
        assert!(!release.join("SHA256SUMS").exists());
        assert!(!release.join("SHA256SUMS.sig.json").exists());
    }

    #[test]
    fn file_name_without_the_tag_fails() {
        let (dir, keys, release) = setup();
        add_file(&release, "pqaudit-old-binary", TAG);
        let output = run(&keys, &release, &fake_cosign(dir.path()));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("pqaudit-old-binary"));
        assert!(!release.join("SHA256SUMS").exists());
    }

    #[test]
    fn rules_archive_needs_no_tag_in_its_name() {
        let (dir, keys, release) = setup();
        add_file(&release, "rules-0.1.0.tar.zst", TAG);
        let output = run(&keys, &release, &fake_cosign(dir.path()));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn different_tag_argument_fails() {
        let (dir, keys, release) = setup();
        let output = run_with_tag(&keys, &release, &fake_cosign(dir.path()), "v0.2.0");
        assert!(!output.status.success());
    }
}

#[cfg(unix)]
mod not_linked {
    use super::*;

    const WITH_RING: &str = "\n[[not-linked]]\ncrate = \"ring\"\nreason = \"A dev-dependency.\"\n";

    fn run_mode(mode: &str) -> (tempfile::TempDir, Output) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cargo-mode"), mode).unwrap();
        let mut names = ALL.to_vec();
        names.push("ring");
        let output = self_cbom(dir.path(), &names, &format!("{DECLARATION}{WITH_RING}"));
        (dir, output)
    }

    #[test]
    fn empty_tree_output_passes() {
        let (dir, output) = run_mode("empty");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let log = fs::read_to_string(dir.path().join("cargo.log")).unwrap();
        assert!(log.contains("tree --locked"), "{log}");
        assert!(log.contains("-i ring"), "{log}");
        assert!(log.contains("--target all"), "{log}");
        assert!(log.contains("-e normal,build"), "{log}");
    }

    #[test]
    fn linked_crate_fails() {
        let (dir, output) = run_mode("output");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("ring"));
        assert!(!dir.path().join("cbom.json").exists());
    }

    #[test]
    fn cargo_error_fails() {
        let (dir, output) = run_mode("error");
        assert!(!output.status.success());
        assert!(!dir.path().join("cbom.json").exists());
    }
}

#[cfg(unix)]
#[test]
fn not_linked_crate_is_allowed_and_must_be_in_the_sbom() {
    let dir = tempfile::tempdir().unwrap();
    let declaration = format!(
        "{DECLARATION}\n[[not-linked]]\ncrate = \"ring\"\nreason = \"A dev-dependency.\"\n"
    );
    let mut names = ALL.to_vec();
    names.push("ring");
    let output = self_cbom(dir.path(), &names, &declaration);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = fs::read_to_string(dir.path().join("cbom.json")).unwrap();
    assert!(!text.contains("pkg:cargo/ring"));
    let output = self_cbom(dir.path(), &ALL, &declaration);
    assert!(String::from_utf8_lossy(&output.stderr).contains("ring"));
    assert!(!output.status.success());
}

#[cfg(unix)]
#[test]
fn repository_declaration_makes_a_valid_cbom() {
    let dir = tempfile::tempdir().unwrap();
    let text = fs::read_to_string(workspace_root().join("docs/self-crypto.toml")).unwrap();
    let table: toml::Table = text.parse().unwrap();
    let mut names: Vec<String> = Vec::new();
    for key in ["use", "not-linked"] {
        for item in table[key].as_array().unwrap() {
            if let Some(list) = item.get("crates").and_then(|v| v.as_array()) {
                names.extend(list.iter().map(|v| v.as_str().unwrap().to_string()));
            }
            if let Some(name) = item.get("crate").and_then(|v| v.as_str()) {
                names.push(name.to_string());
            }
        }
    }
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let output = self_cbom(dir.path(), &names, &text);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cbom: Value =
        serde_json::from_str(&fs::read_to_string(dir.path().join("cbom.json")).unwrap()).unwrap();
    assert!(validator().is_valid(&cbom));
}
