//! The end-to-end test of a Stage 1 engagement. It runs the commands in the order of a consultant.
//! All servers run in this process on 127.0.0.1, with two different ports.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use pqaudit_core::ResultsFile;
use serde_json::Value;

mod common;
use common::{classical_ssh_server, classical_tls_server};

#[path = "../../pqaudit-report/tests/support/validator.rs"]
mod validator_support;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../pqaudit-scan-files/tests/fixtures")
}

struct Engagement {
    dir: tempfile::TempDir,
}

impl Engagement {
    fn path(&self) -> PathBuf {
        self.dir.path().join("eng")
    }

    /// Run `pqaudit` on the engagement. `PQAUDIT_DATA_DIR` is empty, so only the embedded rules pack is in use.
    fn pqaudit(&self) -> Command {
        let mut cmd = Command::cargo_bin("pqaudit").unwrap();
        cmd.env("PQAUDIT_DATA_DIR", self.dir.path().join("data"))
            .arg("--engagement")
            .arg(self.path());
        cmd
    }
}

fn results_with_prefix(engagement: &Engagement, prefix: &str) -> Vec<PathBuf> {
    fs::read_dir(engagement.path().join("results"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(prefix)
        })
        .collect()
}

#[test]
fn full_stage1_engagement() {
    // Step 1: make the engagement.
    let engagement = Engagement {
        dir: tempfile::tempdir().unwrap(),
    };
    Command::cargo_bin("pqaudit")
        .unwrap()
        .args(["init", "acme", "--dir"])
        .arg(engagement.dir.path())
        .assert()
        .code(0);
    fs::rename(
        engagement.dir.path().join("acme"),
        engagement.dir.path().join("eng"),
    )
    .unwrap();

    // Step 2: the engagement and assets files.
    // The asset has the tier high. Any tier gets the 2030 milestone of `au`, because that milestone is for all tiers.
    fs::write(
        engagement.path().join("engagement.toml"),
        "client = \"Acme\"\nassessor = \"A. Consultant\"\nassessment_date = 2026-10-20\n\
         [deadlines]\nprofiles = [\"au\", \"uk\"]\n[assumptions]\ncrqc_year = 2035\n",
    )
    .unwrap();
    fs::write(
        engagement.path().join("assets.toml"),
        "[[asset]]\nname = \"Payments API\"\nbusiness_unit = \"Retail\"\n\
         match = { hosts = [\"127.0.0.1\"], paths = [\"**/fixtures/**\"] }\n\
         classification = \"confidential\"\ndata_lifespan_years = 10\nexposure = \"internet\"\n\
         owner = \"Platform team\"\npriority_tier = \"high\"\n",
    )
    .unwrap();

    // Step 3: the servers. The TLS server has classical key exchange only.
    let tls = classical_tls_server();
    let ssh = classical_ssh_server();
    assert_ne!(tls.port(), ssh.port());

    // Step 4: the scope. The limits are lower than the maximum values, so `override_limits` is not needed.
    fs::write(
        engagement.path().join("scope.toml"),
        format!(
            "allowed_cidrs = [\"127.0.0.0/8\"]\n\
             [limits]\nconnect_timeout_ms = 3000\nread_timeout_ms = 5000\n\
             [[target]]\nhost = \"127.0.0.1\"\nports = [{}]\nprotocol = \"tls\"\n\
             [[target]]\nhost = \"127.0.0.1\"\nports = [{}]\nprotocol = \"ssh\"\n",
            tls.port(),
            ssh.port()
        ),
    )
    .unwrap();

    // Step 5: the commands.
    engagement
        .pqaudit()
        .args(["scan", "net", "--dry-run"])
        .assert()
        .code(0);
    assert!(
        !engagement.path().join("audit.log").exists(),
        "a dry run makes no connection"
    );

    engagement.pqaudit().args(["scan", "net"]).assert().code(0);
    // One TLS port has 2 connections (hybrid and classical). The SSH port has 1.
    let log = fs::read_to_string(engagement.path().join("audit.log")).unwrap();
    let lines: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let done: Vec<&Value> = lines
        .iter()
        .filter(|line| line["outcome"] != "started")
        .collect();
    let started = lines.len() - done.len();
    assert_eq!(done.len(), 3, "{lines:?}");
    assert_eq!(started, 3, "{lines:?}");
    assert_eq!(
        done.iter().filter(|l| l["port"] == tls.port()).count(),
        2,
        "{lines:?}"
    );
    assert_eq!(
        done.iter().filter(|l| l["port"] == ssh.port()).count(),
        1,
        "{lines:?}"
    );
    // The classical server refuses the hybrid probe on purpose. That is a result, not a scan error.
    for line in &done {
        let expected = if line["probe"] == "tls-hybrid" {
            "tls-failed"
        } else {
            "ok"
        };
        assert_eq!(line["outcome"], expected, "{lines:?}");
    }

    // Exit 3 is right here. The fixtures hold files that the scanner cannot read, on purpose:
    // the GnuPG key box `pubring.kbx` and the `.key.der` files that are not certificates.
    // The scanner reports each one as an error and keeps the other results.
    engagement
        .pqaudit()
        .args(["scan", "files"])
        .arg(fixtures())
        .assert()
        .code(3);
    assert_eq!(results_with_prefix(&engagement, "net-").len(), 1);
    assert_eq!(results_with_prefix(&engagement, "files-").len(), 1);

    let mut inputs = results_with_prefix(&engagement, "net-");
    inputs.extend(results_with_prefix(&engagement, "files-"));
    engagement
        .pqaudit()
        .arg("merge")
        .args(&inputs)
        .assert()
        .code(0);
    let merged = ResultsFile::read(&engagement.path().join("results/merged.pqr")).unwrap();
    let first_id = merged.findings[0].id.clone();
    assert!(
        first_id.starts_with("F-") && first_id.len() == 10,
        "{first_id}"
    );

    engagement
        .pqaudit()
        .args(["report", "--format", "html"])
        .assert()
        .code(0);
    engagement
        .pqaudit()
        .args(["report", "--format", "json"])
        .assert()
        .code(0);
    engagement.pqaudit().arg("cbom").assert().code(0);
    engagement
        .pqaudit()
        .args(["explain", &first_id])
        .assert()
        .code(0);

    // The JSON report: `tls.no-pq-kex` has the deadline 2030-12-31 from the profile `au`.
    let reports = engagement.path().join("reports");
    let json: Value =
        serde_json::from_str(&fs::read_to_string(reports.join("technical.json")).unwrap()).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let no_pq: Vec<&Value> = findings
        .iter()
        .filter(|f| f["rule_id"] == "tls.no-pq-kex" || f["finding"]["rule_id"] == "tls.no-pq-kex")
        .collect();
    assert!(!no_pq.is_empty(), "no tls.no-pq-kex in {findings:#?}");
    for finding in no_pq {
        let deadline = &finding["deadline"];
        assert_eq!(deadline["date"], "2030-12-31", "{finding:#?}");
        assert_eq!(deadline["profile_id"], "au", "{finding:#?}");
    }

    // The CBOM is valid CycloneDX 1.6.
    let bom: Value =
        serde_json::from_str(&fs::read_to_string(reports.join("cbom.cdx.json")).unwrap()).unwrap();
    let errors: Vec<String> = validator_support::validator()
        .iter_errors(&bom)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");

    // The HTML report holds all its content.
    let html = fs::read_to_string(reports.join("technical.html")).unwrap();
    assert!(html.contains("<h1>Technical report</h1>"));
    assert!(html.contains("tls.no-pq-kex"));
    assert!(html.contains(&first_id));
    assert!(html.contains("Payments API"));
    assert!(html.contains("2030-12-31"));
    assert!(html.contains("2035"), "the CRQC year");
    assert!(html.trim_end().ends_with("</html>"));
}
