//! Tests of the technical report.

use chrono::{NaiveDate, TimeZone, Utc};
use pqaudit_core::assess::{AssessedFinding, Assessment, EngagementSummary};
use pqaudit_core::assets::{AssetContext, Ctx};
use pqaudit_core::complexity::Complexity;
use pqaudit_core::deadlines::DeadlineRef;
use pqaudit_core::engagement::{Assumptions, Band, Exposure, Override, Size};
use pqaudit_core::scoring::{FactorScore, ScoreBreakdown};
use pqaudit_core::{
    Agility, Algorithm, ChangeType, Finding, Fingerprint, FixOwner, InventoryItem, InventoryKind,
    Location, Occurrence, PackOriginRef, PackRef, Protocol, Purpose, ResultsHeader, RunInfo,
    ScanError, ScannerKind, Source, TestType, ThreatType, Tier,
};
use pqaudit_report::technical::render;
use pqaudit_report::Format;
use pqaudit_rules::pack::{AppliesTo, Milestone, MilestoneKind, RuleDef};
use uuid::Uuid;

fn date(y: i32, m: u32, d: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

fn rule(id: &str, title: &str, threat: ThreatType) -> RuleDef {
    RuleDef {
        id: id.to_string(),
        family: "rsa".to_string(),
        aliases: vec![],
        title: title.to_string(),
        description: format!("Description of {title}."),
        remediation: format!("Replace the key of {title}."),
        threat_type: Some(threat),
        cwe: vec!["CWE-327".to_string()],
        attack: vec!["T1600".to_string()],
        change_type: ChangeType::Config,
        size_impact: vec![],
        testing: vec![TestType::Unit],
    }
}

fn finding(n: u32, threat: ThreatType, evidence: &str, run: Uuid) -> Finding {
    Finding {
        id: format!("F-0000000{n}"),
        fingerprint: Fingerprint(format!("cert:{n:032x}")),
        rule_id: format!("rule-{n}"),
        source: Source::Net,
        algorithm: Some(Algorithm {
            name: "RSA".to_string(),
            key_bits: Some(2048),
            curve: None,
        }),
        purpose: Purpose::Signature,
        threat_type: threat,
        agility: Agility::Config,
        fix_owner: FixOwner::InHouse,
        also: vec![],
        occurrences: vec![Occurrence {
            location: Location::Endpoint {
                host: format!("host{n}.example.com"),
                ip: "192.0.2.1".parse().unwrap(),
                port: 443,
                protocol: Protocol::Tls,
            },
            evidence: evidence.to_string(),
            run_id: run,
        }],
        cert: None,
        key: None,
        endpoint: None,
    }
}

fn context(vendor: Ctx<bool>, classification: Ctx<String>) -> AssetContext {
    AssetContext {
        classification,
        data_lifespan_years: Ctx::Assessed(10),
        exposure: Ctx::Assessed(Exposure::Internet),
        priority_tier: Ctx::Assessed(Tier::High),
        vendor,
        hardware_constrained: Ctx::Unassessed,
        business_unit: None,
        owner: None,
    }
}

fn assessed(
    n: u32,
    threat: ThreatType,
    band: Band,
    total: f64,
    ctx: AssetContext,
    evidence: &str,
    run: Uuid,
) -> AssessedFinding {
    let factors = [
        "threat",
        "exposure",
        "sensitivity",
        "mosca",
        "deadline",
        "scale",
    ]
    .iter()
    .map(|name| FactorScore {
        name,
        value: 0.5,
        weight: 1.0,
        contribution: 8.0,
        note: format!("Note for {name}."),
    })
    .collect();
    AssessedFinding {
        finding: finding(n, threat, evidence, run),
        rule: rule(&format!("rule-{n}"), &format!("Title {n}"), threat),
        asset: Some(format!("asset-{n}")),
        context: ctx,
        deadline: Some(DeadlineRef {
            date: date(2030, 12, 31),
            profile_id: "us".to_string(),
            description: "Move to new algorithms.".to_string(),
            source_title: "Source title".to_string(),
            source_url: "https://example.com/source".to_string(),
        }),
        score: ScoreBreakdown { factors, total },
        band,
        override_: None,
        effective_band: band,
        complexity: Complexity {
            change_type: ChangeType::Config,
            size: Size::M,
            migration_years: 1.5,
            reasons: vec!["Reason one.".to_string()],
        },
        testing: vec![TestType::Unit],
    }
}

/// The fixture has three findings, a vendor asset, and an override.
/// It also has an orphaned override and an endpoint that is ready for post-quantum use.
fn fixture() -> Assessment {
    let run = Uuid::nil();
    let started = Utc.with_ymd_and_hms(2026, 10, 1, 9, 0, 0).unwrap();
    let pack = PackRef {
        id: "pqaudit-rules".to_string(),
        version: "1.2.3".to_string(),
        content_hash: "abcdef".to_string(),
        origin: PackOriginRef::Embedded,
    };
    let header = ResultsHeader {
        schema_version: 1,
        engagement: "acme".to_string(),
        tool_version: "9.9.9".to_string(),
        rules_pack: pack.clone(),
        scanner: ScannerKind::Merged,
        host: "scanner".to_string(),
        operator: "operator".to_string(),
        started,
        finished: started,
        scope_hash: Some("scope-hash-1".to_string()),
        audit_log_hash: Some("audit-hash-1".to_string()),
        runs: vec![RunInfo {
            run_id: run,
            scanner: ScannerKind::Net,
            host: "scanner".to_string(),
            started,
            scope_hash: Some("scope-hash-1".to_string()),
            audit_log_hash: Some("audit-hash-1".to_string()),
        }],
        redacted: false,
    };
    let first = assessed(
        1,
        ThreatType::Hndl,
        Band::Critical,
        81.0,
        context(Ctx::Assessed(false), Ctx::Assessed("secret".to_string())),
        "evidence one",
        run,
    );
    let mut second = assessed(
        2,
        ThreatType::ForgeryLongLived,
        Band::High,
        60.0,
        context(Ctx::Assessed(true), Ctx::Assessed("internal".to_string())),
        "evidence two",
        run,
    );
    second.override_ = Some(Override {
        fingerprint: second.finding.fingerprint.0.clone(),
        priority: Band::Low,
        reason: "The vendor accepts the risk.".to_string(),
        by: "A. Person".to_string(),
        date: date(2026, 10, 5),
    });
    second.effective_band = Band::Low;
    let third = assessed(
        3,
        ThreatType::ClassicalWeakNow,
        Band::Medium,
        45.0,
        AssetContext::unassessed(),
        "evidence three",
        run,
    );
    let ready = InventoryItem {
        kind: InventoryKind::Endpoint,
        fingerprint: Fingerprint("endpoint:ready".to_string()),
        pq_ready: true,
        algorithm: Some(Algorithm {
            name: "X25519MLKEM768".to_string(),
            key_bits: None,
            curve: None,
        }),
        cert: None,
        key: None,
        endpoint: None,
        occurrences: vec![Occurrence {
            location: Location::Endpoint {
                host: "ready.example.com".to_string(),
                ip: "192.0.2.9".parse().unwrap(),
                port: 443,
                protocol: Protocol::Tls,
            },
            evidence: "hybrid group".to_string(),
            run_id: run,
        }],
    };
    Assessment {
        engagement: EngagementSummary {
            client: "Acme Corp".to_string(),
            assessor: "Assessor Ltd".to_string(),
            assessment_date: date(2026, 10, 20),
            profiles: vec!["us".to_string()],
            sector: None,
        },
        header,
        findings: vec![third, first, second],
        inventory: vec![ready],
        errors: vec![ScanError {
            location: "/etc/bad.pem".to_string(),
            reason: "Not a valid file.".to_string(),
        }],
        planning_milestones: vec![(
            "us".to_string(),
            Milestone {
                date: date(2027, 1, 1),
                kind: MilestoneKind::Planning,
                applies_to: AppliesTo::default(),
                description: "Make a plan.".to_string(),
                source_title: "Plan source".to_string(),
                source_url: "https://example.com/plan".to_string(),
                as_of: date(2026, 1, 1),
            },
        )],
        orphaned_overrides: vec![Override {
            fingerprint: "cert:orphan".to_string(),
            priority: Band::High,
            reason: "Orphan reason.".to_string(),
            by: "B. Person".to_string(),
            date: date(2026, 9, 1),
        }],
        overrides_need_key: false,
        unassessed_count: 1,
        assumptions: Assumptions { crqc_year: 2035 },
        pack,
    }
}

fn html() -> String {
    render(&fixture(), Format::Html).unwrap()
}

const HEADINGS: [&str; 12] = [
    "Technical report",
    "Method",
    "Scope and coverage",
    "Assumptions",
    "Summary",
    "Findings",
    "Fix now (not quantum)",
    "Ready for post-quantum cryptography",
    "Questions for vendors",
    "Overrides log",
    "Orphaned overrides",
    "Appendix: risk register",
];

fn heading_positions(text: &str, open: &str) -> Vec<usize> {
    HEADINGS
        .iter()
        .map(|name| {
            text.find(&format!("{open}{name}"))
                .unwrap_or_else(|| panic!("no heading {name}"))
        })
        .collect()
}

#[test]
fn html_is_self_contained() {
    let text = html();
    for banned in ["<script src", "<link", "@import", "url(http", "src=\"http"] {
        assert!(!text.contains(banned), "found {banned}");
    }
    assert!(text.contains("@media print"));
    assert!(text.contains("<style>"));
}

#[test]
fn sections_in_order() {
    let positions = heading_positions(&html(), ">");
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");
    let md = render(&fixture(), Format::Md).unwrap();
    let positions = heading_positions(&md, "# ");
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");
}

#[test]
fn title_block_has_names_and_versions() {
    let text = render(&fixture(), Format::Md).unwrap();
    for needle in ["Acme Corp", "Assessor Ltd", "2026-10-20", "9.9.9", "1.2.3"] {
        assert!(text.contains(needle), "no {needle}");
    }
}

#[test]
fn coverage_shows_hashes_and_error_count() {
    let text = render(&fixture(), Format::Md).unwrap();
    assert!(text.contains("scope-hash-1"));
    assert!(text.contains("audit-hash-1"));
    assert!(text.contains("Errors: 1"));
}

#[test]
fn assumptions_show_year_and_milestone_sources() {
    let text = render(&fixture(), Format::Md).unwrap();
    assert!(text.contains("2035"));
    assert!(text.contains("Plan source"));
    assert!(text.contains("https://example.com/plan"));
}

#[test]
fn findings_are_ordered_by_band_then_total() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Findings").unwrap();
    let end = text.find("# Fix now").unwrap();
    let section = &text[start..end];
    let one = section.find("F-00000001").unwrap();
    let three = section.find("F-00000003").unwrap();
    let two = section.find("F-00000002").unwrap();
    assert!(one < three && three < two, "{one} {three} {two}");
}

#[test]
fn finding_shows_details() {
    let text = render(&fixture(), Format::Md).unwrap();
    for needle in [
        "evidence one",
        "CWE-327",
        "T1600",
        "Source title",
        "hndl",
        "Reason one.",
        "Replace the key of Title 1.",
        "mosca",
    ] {
        assert!(text.contains(needle), "no {needle}");
    }
}

#[test]
fn fix_now_lists_classical_weak() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Fix now").unwrap();
    let end = text.find("# Ready for post-quantum").unwrap();
    let section = &text[start..end];
    assert!(section.contains("F-00000003"));
    assert!(!section.contains("F-00000001"));
    assert!(!section.contains("F-00000002"));
}

#[test]
fn ready_items_are_listed() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Ready for post-quantum").unwrap();
    let end = text.find("# Questions for vendors").unwrap();
    assert!(text[start..end].contains("ready.example.com"));
    assert!(text[start..end].contains("X25519MLKEM768"));
}

#[test]
fn vendor_questions_present() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Questions for vendors").unwrap();
    let end = text.find("# Overrides log").unwrap();
    let section = &text[start..end];
    assert!(section.contains("F-00000002"));
    assert!(section.contains("Replace the key of Title 2."));
    assert!(!section.contains("F-00000001"));
    assert!(!section.contains("F-00000003"));
}

#[test]
fn overrides_log_shows_reason() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Overrides log").unwrap();
    let end = text.find("# Orphaned overrides").unwrap();
    let section = &text[start..end];
    for needle in [
        "The vendor accepts the risk.",
        "A. Person",
        "2026-10-05",
        "high",
        "low",
    ] {
        assert!(section.contains(needle), "no {needle}");
    }
    let orphans = &text[end..text.find("# Appendix").unwrap()];
    assert!(orphans.contains("cert:orphan"));
    assert!(orphans.contains("Orphan reason."));
}

#[test]
fn missing_redaction_key_note_shows_with_the_orphans() {
    const NOTE: &str =
        "The results file has keyed hashes, but the engagement directory has no file redact.key.";
    assert!(!html().contains(NOTE));
    let mut a = fixture();
    a.overrides_need_key = true;
    for format in [Format::Html, Format::Md] {
        let text = render(&a, format).unwrap();
        assert!(text.contains(NOTE), "{format:?}");
    }
}

#[test]
fn risk_register_has_row_per_finding() {
    let text = render(&fixture(), Format::Md).unwrap();
    let start = text.find("# Appendix: risk register").unwrap();
    let section = &text[start..];
    let rows = section
        .lines()
        .filter(|line| line.starts_with("| cert:"))
        .count();
    assert_eq!(rows, 3);
    for column in [
        "Fingerprint",
        "Title",
        "Exposure",
        "Threat",
        "Classical weakness",
        "Classification",
        "Lifespan",
        "Scale",
        "Suggested band",
        "Effective band",
    ] {
        assert!(section.contains(column), "no column {column}");
    }
    let page = html();
    assert_eq!(page.matches("<tr class=\"register-row\"").count(), 3);
}

#[test]
fn unassessed_marked() {
    let text = render(&fixture(), Format::Md).unwrap();
    assert!(text.contains("Unassessed"));
    assert!(html().contains("Unassessed"));
}

#[test]
fn redacted_results_are_flagged_near_the_top() {
    let mut a = fixture();
    a.header.redacted = true;
    let text = render(&a, Format::Md).unwrap();
    let flag = text.find("redacted").expect("no redaction note");
    assert!(flag < text.find("# Method").unwrap());
    let plain = render(&fixture(), Format::Md).unwrap();
    assert!(!plain.contains("redacted"));
}

#[test]
fn md_and_json_render() {
    let md = render(&fixture(), Format::Md).unwrap();
    assert!(md.starts_with("# "));
    let json = render(&fixture(), Format::Json).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["engagement"]["client"], "Acme Corp");
    assert_eq!(value["findings"].as_array().unwrap().len(), 3);
}

#[test]
fn peer_text_is_escaped_in_html() {
    let mut a = fixture();
    a.findings[1].finding.occurrences[0].evidence =
        "<script>alert(1)</script><img src=x onerror=y>".to_string();
    a.errors[0].reason = "\"><b>bold</b>".to_string();
    let text = render(&a, Format::Html).unwrap();
    assert!(!text.contains("<script>alert"));
    assert!(!text.contains("<img"));
    assert!(!text.contains("<b>bold"));
    assert!(text.contains("&lt;script&gt;"));
}

#[test]
fn peer_text_cannot_break_markdown() {
    let mut a = fixture();
    a.findings[1].finding.occurrences[0].evidence =
        "a | b `code` \n# Fake heading\n| x | y |\r\n<b>bold</b>".to_string();
    a.errors[0].reason = "x | y\n## Another".to_string();
    let text = render(&a, Format::Md).unwrap();
    assert!(!text.contains("\n# Fake heading"));
    assert!(!text.contains("\n## Another"));
    assert!(!text.contains("<b>"));
    assert!(!text.contains("a | b"));
    assert!(text.contains("a \\| b"));
    // The table in the appendix keeps the same column count in every row.
    let start = text.find("# Appendix: risk register").unwrap();
    let counts: Vec<usize> = text[start..]
        .lines()
        .filter(|l| l.starts_with('|'))
        .map(|l| l.replace("\\|", "").matches('|').count())
        .collect();
    assert!(counts.windows(2).all(|w| w[0] == w[1]), "{counts:?}");
}

#[test]
fn unsafe_source_urls_are_not_links() {
    let mut a = fixture();
    a.findings[0].deadline.as_mut().unwrap().source_url = "javascript:alert(1)".to_string();
    let text = render(&a, Format::Html).unwrap();
    assert!(!text.contains("href=\"javascript"));
}

#[test]
fn rules_pack_line_shows_the_origin() {
    let embedded = render(&fixture(), Format::Md).unwrap();
    assert!(
        embedded.contains("Origin: embedded in the tool"),
        "{embedded}"
    );
    assert!(!embedded.contains("no valid signature"));

    let mut a = fixture();
    a.pack.origin = PackOriginRef::Installed {
        path: "/data/rules/1.2.3".to_string(),
        signed_by: "key-b".to_string(),
        rotation_chain: vec!["key-a".to_string(), "key-b".to_string()],
    };
    for format in [Format::Md, Format::Html] {
        let text = render(&a, format).unwrap();
        assert!(text.contains("signed by key-b"), "{text}");
        assert!(
            text.contains("key chain key-a &gt; key-b")
                || text.contains("key chain key-a \\> key-b"),
            "{text}"
        );
    }
}

#[test]
fn unsigned_rules_pack_gives_a_notice() {
    let mut a = fixture();
    a.pack.origin = PackOriginRef::Unsigned {
        path: "/data/rules/1.2.3".to_string(),
    };
    for format in [Format::Md, Format::Html] {
        let text = render(&a, format).unwrap();
        assert!(
            text.contains("Origin: installed, no valid signature"),
            "{text}"
        );
        let notice = text
            .find("The rules pack of these results has no valid signature.")
            .expect("no notice");
        assert!(notice < text.find("Method").unwrap());
    }
}

#[test]
fn redacted_results_hide_the_client_name() {
    let mut a = fixture();
    a.header.redacted = true;
    a.header.engagement = "redacted:0123456789ab".to_string();
    for format in [Format::Md, Format::Html] {
        let text = render(&a, format).unwrap();
        assert!(!text.contains("Acme Corp"), "the client name is in clear");
        assert!(
            text.contains("Client: redacted:0123456789ab")
                || text.contains("<dt>Client</dt><dd>redacted:0123456789ab</dd>")
        );
        assert!(text.contains("The client name shows as the redacted engagement name."));
    }
}
