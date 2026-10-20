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
        // Every command except `init` runs through this helper. `init` runs before the engagement exists.
        let mut cmd = Command::cargo_bin("pqaudit").unwrap();
        cmd.env_remove("SOURCE_DATE_EPOCH")
            .env("PQAUDIT_DATA_DIR", self.dir.path().join("data"))
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
    // Each connection has a "started" line and a final line. They share the port and the probe.
    let probes = [
        (tls.port(), "tls-hybrid", "tls-failed"),
        (tls.port(), "tls-classical", "ok"),
        (ssh.port(), "ssh-kexinit", "ok"),
    ];
    assert_eq!(lines.len(), 2 * probes.len(), "{lines:?}");
    for (port, probe, outcome) in probes {
        let of_connection: Vec<&Value> = lines
            .iter()
            .filter(|l| l["port"] == port && l["probe"] == probe)
            .collect();
        assert_eq!(of_connection.len(), 2, "{port} {probe}: {lines:?}");
        assert_eq!(of_connection[0]["outcome"], "started", "{lines:?}");
        // The classical server refuses the hybrid probe on purpose. That is a result, not a scan error.
        assert_eq!(of_connection[1]["outcome"], outcome, "{lines:?}");
    }

    // Exit 3 is right here. The fixtures hold files that the scanner cannot read, on purpose:
    // the GnuPG key box `pubring.kbx`, the `.key.der` files that are not certificates,
    // and the key store `store-pw.p12`, which needs a password that the engagement does not give.
    // The scanner reports each one as an error and keeps the other results.
    engagement
        .pqaudit()
        .args(["scan", "files"])
        .arg(fixtures())
        .assert()
        .code(3);
    let files_results = results_with_prefix(&engagement, "files-");
    assert_eq!(files_results.len(), 1);
    let scanned = ResultsFile::read(&files_results[0]).unwrap();
    let mut errors: Vec<(String, String)> = scanned
        .errors
        .iter()
        .map(|error| {
            let name = error.location.rsplit('/').next().unwrap().to_string();
            (name, error.reason.clone())
        })
        .collect();
    errors.sort();
    let names: Vec<&str> = errors.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "pubring.kbx",
            "store-empty.key.der",
            "store-pw.key.der",
            "store-pw.p12"
        ],
        "{errors:?}"
    );
    assert!(errors[0].1.contains("Unsupported format"), "{errors:?}");
    assert!(errors[3].1.contains("Encrypted"), "{errors:?}");
    // The two `.key.der` files are raw PKCS#8 RSA keys, not certificates. The scanner reads a DER file as a
    // certificate only, so it reports them with a wrong message. This is a scanner gap that the report lists.
    // The test does not pin the message of these two errors.
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
    let first_rule = merged.findings[0].rule_id.clone();
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
    let explained = engagement
        .pqaudit()
        .args(["explain", &first_id])
        .assert()
        .code(0);
    let explained = String::from_utf8(explained.get_output().stdout.clone()).unwrap();
    assert!(
        explained.starts_with(&format!("Finding {first_id}:")),
        "{explained}"
    );
    assert!(
        explained.contains(&format!("Rule: {first_rule}\n")),
        "{explained}"
    );
    let total = explained.split("Total: ").nth(1).expect("a total line");
    let number: String = total
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    assert!(number.parse::<f64>().is_ok(), "{total}");

    // The JSON report: `tls.no-pq-kex` has the deadline 2030-12-31 from the profile `au`.
    let reports = engagement.path().join("reports");
    let json: Value =
        serde_json::from_str(&fs::read_to_string(reports.join("technical.json")).unwrap()).unwrap();
    let findings = json["findings"].as_array().unwrap();
    let no_pq: Vec<&Value> = findings
        .iter()
        .filter(|f| f["finding"]["rule_id"] == "tls.no-pq-kex")
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
    // The report is one file. It needs no other file and no network.
    assert!(html.contains("<style"));
    for banned in ["<script src", "<link", "@import", "url(http"] {
        assert!(!html.contains(banned), "found {banned}");
    }
    // A link to another site is allowed only as the href of an anchor. No source may start with `//`.
    for banned in ["src=\"//", "href=\"//"] {
        assert!(!html.contains(banned), "found {banned}");
    }
    for (at, _) in html.match_indices("http") {
        let rest = &html[at..];
        if rest.starts_with("http://") || rest.starts_with("https://") {
            let tag_start = html[..at].rfind('<').unwrap_or(0);
            let tag = &html[tag_start..at];
            assert!(
                tag.starts_with("<a ") && tag.ends_with("href=\""),
                "link outside an anchor: {}",
                rest.chars().take(40).collect::<String>()
            );
        }
    }
}
