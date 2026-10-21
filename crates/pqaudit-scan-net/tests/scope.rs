//! Tests of the scope file and the target plan.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use pqaudit_core::Protocol;
use pqaudit_scan_net::scope::{
    build_plan, scope_hash, HoursWindow, Limits, LimitsToml, RefusalReason, Resolver, ScopeError,
    ScopeFile, TargetPlan,
};

/// A resolver with fixed answers. It counts the calls for each host.
#[derive(Default)]
struct FakeResolver {
    answers: HashMap<String, Vec<IpAddr>>,
    calls: RefCell<Vec<String>>,
}

impl FakeResolver {
    fn with(host: &str, ips: &[&str]) -> Self {
        let mut resolver = FakeResolver::default();
        resolver.add(host, ips);
        resolver
    }
    fn add(&mut self, host: &str, ips: &[&str]) {
        self.answers.insert(
            host.to_string(),
            ips.iter().map(|i| i.parse().unwrap()).collect(),
        );
    }
    fn calls_for(&self, host: &str) -> usize {
        self.calls.borrow().iter().filter(|h| *h == host).count()
    }
}

impl Resolver for FakeResolver {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        self.calls.borrow_mut().push(host.to_string());
        self.answers
            .get(host)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
    }
}

fn scope(text: &str) -> ScopeFile {
    ScopeFile::parse(text, "scope.toml").unwrap()
}

fn plan(text: &str, resolver: &FakeResolver) -> TargetPlan {
    build_plan(&scope(text), resolver).unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn host_target_resolves_once() {
    let resolver = FakeResolver::with("pay.acme.example", &["10.0.0.5"]);
    let text = r#"
        allowed_cidrs = ["10.0.0.0/16"]
        [[target]]
        host = "pay.acme.example"
        ports = [443, 8443]
        protocol = "tls"
        [[target]]
        host = "pay.acme.example"
        ports = [22]
        protocol = "ssh"
    "#;
    let plan = plan(text, &resolver);
    assert_eq!(resolver.calls_for("pay.acme.example"), 1);
    assert!(!plan.is_refused());
    assert_eq!(plan.targets.len(), 3);
    assert!(plan
        .targets
        .iter()
        .all(|t| t.host.as_deref() == Some("pay.acme.example") && t.ip == ip("10.0.0.5")));
}

#[test]
fn one_bad_resolved_ip_refuses_whole_scan() {
    let resolver = FakeResolver::with("pay.acme.example", &["10.0.0.5", "203.0.113.9"]);
    let text = r#"
        allowed_cidrs = ["10.0.0.0/16"]
        [[target]]
        host = "pay.acme.example"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &resolver);
    assert!(plan.is_refused());
    assert_eq!(plan.refused.len(), 1);
    assert!(plan.refused[0].reason.to_string().contains("203.0.113.9"));
    assert!(
        plan.targets.is_empty(),
        "no address of a refused host stays"
    );
}

#[test]
fn require_ip_in_cidr_false_allows_any_address() {
    let resolver = FakeResolver::with("a.example", &["203.0.113.9"]);
    let text = r#"
        require_ip_in_cidr = false
        allowed_cidrs = ["10.0.0.0/16"]
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
    "#;
    assert!(!plan(text, &resolver).is_refused());
}

#[test]
fn no_cidr_means_no_address_check() {
    let resolver = FakeResolver::with("a.example", &["203.0.113.9"]);
    let text = r#"
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
    "#;
    assert!(!plan(text, &resolver).is_refused());
}

#[test]
fn explicit_true_without_cidr_refuses_names() {
    let resolver = FakeResolver::with("a.example", &["203.0.113.9"]);
    let text = r#"
        require_ip_in_cidr = true
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
    "#;
    assert!(plan(text, &resolver).is_refused());
}

#[test]
fn cidr_target_range_is_allowed_for_names() {
    let resolver = FakeResolver::with("a.example", &["10.0.1.3"]);
    let text = r#"
        [[target]]
        cidr = "10.0.1.0/28"
        ports = [22]
        protocol = "ssh"
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
    "#;
    assert!(!plan(text, &resolver).is_refused());
}

#[test]
fn resolution_failure_is_a_refusal() {
    let resolver = FakeResolver::default();
    let text = r#"
        [[target]]
        host = "gone.example"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &resolver);
    assert!(plan.is_refused());
    assert!(matches!(
        plan.refused[0].reason,
        RefusalReason::ResolveFailed { .. }
    ));
}

#[test]
fn zero_addresses_is_a_refusal() {
    let resolver = FakeResolver::with("empty.example", &[]);
    let text = r#"
        [[target]]
        host = "empty.example"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &resolver);
    assert!(plan.is_refused());
    assert_eq!(plan.refused[0].reason, RefusalReason::NoAddresses);
}

#[test]
fn exclude_beats_include() {
    let resolver = FakeResolver::default();
    let text = r#"
        [[target]]
        cidr = "10.0.1.0/30"
        ports = [22]
        protocol = "ssh"
        [[exclude]]
        cidr = "10.0.1.1/32"
    "#;
    let plan = plan(text, &resolver);
    let ips: Vec<IpAddr> = plan.targets.iter().map(|t| t.ip).collect();
    assert_eq!(ips, vec![ip("10.0.1.0"), ip("10.0.1.2"), ip("10.0.1.3")]);
    assert!(!plan.is_refused());
}

#[test]
fn exclude_by_host_name_skips_the_target_without_resolving() {
    let resolver = FakeResolver::with("skip.example", &["10.0.0.9"]);
    let text = r#"
        [[target]]
        host = "Skip.Example"
        ports = [443]
        protocol = "tls"
        [[exclude]]
        host = "skip.example"
    "#;
    let plan = plan(text, &resolver);
    assert!(plan.targets.is_empty());
    assert!(!plan.is_refused());
}

#[test]
fn excluded_host_address_is_removed_from_other_targets() {
    let resolver = FakeResolver::with("db.acme.example", &["10.0.1.1"]);
    let text = r#"
        [[target]]
        cidr = "10.0.1.0/30"
        ports = [22]
        protocol = "ssh"
        [[exclude]]
        host = "db.acme.example"
    "#;
    let plan = plan(text, &resolver);
    assert_eq!(plan.targets.len(), 3);
    assert!(plan.targets.iter().all(|t| t.ip != ip("10.0.1.1")));
}

#[test]
fn excluded_bad_address_still_refuses_the_host() {
    let resolver = FakeResolver::with("a.example", &["10.0.1.5", "203.0.113.9"]);
    let text = r#"
        allowed_cidrs = ["10.0.0.0/16"]
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
        [[exclude]]
        cidr = "203.0.113.9/32"
    "#;
    let plan = plan(text, &resolver);
    assert!(plan.is_refused());
    assert!(plan.refused[0].reason.to_string().contains("203.0.113.9"));
    assert!(plan.targets.is_empty());
}

#[test]
fn mapped_exclude_cidr_matches_resolved_address() {
    let resolver = FakeResolver::with("a.example", &["10.0.1.5", "10.0.1.6"]);
    let text = r#"
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
        [[exclude]]
        cidr = "::ffff:10.0.1.5/128"
    "#;
    let plan = plan(text, &resolver);
    let ips: Vec<IpAddr> = plan.targets.iter().map(|t| t.ip).collect();
    assert_eq!(ips, vec![ip("10.0.1.6")]);
}

#[test]
fn mapped_target_cidr_is_matched_by_v4_exclude() {
    let text = r#"
        [[target]]
        cidr = "::ffff:10.0.1.0/126"
        ports = [22]
        protocol = "ssh"
        [[exclude]]
        cidr = "10.0.1.1/32"
    "#;
    let plan = plan(text, &FakeResolver::default());
    let ips: Vec<IpAddr> = plan.targets.iter().map(|t| t.ip).collect();
    assert_eq!(ips, vec![ip("10.0.1.0"), ip("10.0.1.2"), ip("10.0.1.3")]);
}

#[test]
fn mapped_allowed_cidr_allows_v4_address() {
    let resolver = FakeResolver::with("a.example", &["10.0.1.5"]);
    let text = r#"
        allowed_cidrs = ["::ffff:10.0.0.0/112"]
        [[target]]
        host = "a.example"
        ports = [443]
        protocol = "tls"
    "#;
    assert!(!plan(text, &resolver).is_refused());
}

#[test]
fn wide_range_holding_the_mapped_range_is_a_parse_error() {
    for cidr in ["::/0", "::ffff:0:0/95", "::/80"] {
        for key in ["allowed_cidrs = [\"X\"]", "[[exclude]]\ncidr = \"X\""] {
            let text = key.replace('X', cidr);
            let error = ScopeFile::parse(&text, "scope.toml").unwrap_err();
            assert!(matches!(error, ScopeError::Parse { .. }), "{text}");
        }
    }
    // A plain IPv6 range stays valid.
    assert!(ScopeFile::parse("allowed_cidrs = [\"2001:db8::/32\"]", "scope.toml").is_ok());
}

#[test]
fn cidr_over_256_refused_without_override() {
    let text = r#"
        [[target]]
        cidr = "10.0.0.0/23"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &FakeResolver::default());
    assert!(plan.is_refused());
    assert!(plan.targets.is_empty());
}

#[test]
fn cidr_of_256_is_allowed_without_override() {
    let text = r#"
        [[target]]
        cidr = "10.0.0.0/24"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &FakeResolver::default());
    assert!(!plan.is_refused());
    assert_eq!(plan.targets.len(), 256);
}

#[test]
fn cidr_over_256_allowed_with_override() {
    let text = r#"
        override_limits = true
        [[target]]
        cidr = "10.0.0.0/23"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &FakeResolver::default());
    assert!(!plan.is_refused());
    assert_eq!(plan.targets.len(), 512);
}

#[test]
fn huge_cidr_is_refused_even_with_override() {
    let text = r#"
        override_limits = true
        [[target]]
        cidr = "2001:db8::/64"
        ports = [443]
        protocol = "tls"
        [[target]]
        cidr = "10.0.0.0/8"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &FakeResolver::default());
    assert_eq!(plan.refused.len(), 2);
    assert!(plan.targets.is_empty());
}

#[test]
fn limit_above_default_rejected() {
    let requested = LimitsToml {
        concurrency: Some(5),
        ..LimitsToml::default()
    };
    match Limits::effective(&requested, false) {
        Err(ScopeError::LimitAboveDefault {
            name,
            requested,
            default,
        }) => {
            assert_eq!(name, "concurrency");
            assert_eq!(requested, 5);
            assert_eq!(default, 4);
        }
        other => panic!("unexpected: {other:?}"),
    }
    let text = "[limits]\nretries = 1\n";
    assert!(build_plan(&scope(text), &FakeResolver::default()).is_err());
}

#[test]
fn limit_above_default_accepted_with_override() {
    let requested = LimitsToml {
        concurrency: Some(10),
        retries: Some(2),
        ..LimitsToml::default()
    };
    let limits = Limits::effective(&requested, true).unwrap();
    assert_eq!(limits.concurrency, 10);
    assert_eq!(limits.retries, 2);
}

#[test]
fn limit_below_default_accepted() {
    let requested = LimitsToml {
        concurrency: Some(1),
        connect_timeout_ms: Some(1000),
        min_interval_ms: Some(2000),
        ..LimitsToml::default()
    };
    let limits = Limits::effective(&requested, false).unwrap();
    assert_eq!(limits.concurrency, 1);
    assert_eq!(limits.connect_timeout, Duration::from_millis(1000));
    assert_eq!(limits.min_interval, Duration::from_millis(2000));
}

#[test]
fn interval_below_default_rejected_without_override() {
    let requested = LimitsToml {
        min_interval_ms: Some(500),
        ..LimitsToml::default()
    };
    assert!(matches!(
        Limits::effective(&requested, false),
        Err(ScopeError::LimitBelowDefault { .. })
    ));
}

#[test]
fn zero_limit_rejected() {
    let requested = LimitsToml {
        concurrency: Some(0),
        ..LimitsToml::default()
    };
    assert!(matches!(
        Limits::effective(&requested, true),
        Err(ScopeError::LimitZero { .. })
    ));
}

#[test]
fn defaults_match_the_spec() {
    let limits = Limits::effective(&LimitsToml::default(), false).unwrap();
    assert_eq!(limits.concurrency, 4);
    assert_eq!(limits.per_host, 1);
    assert_eq!(limits.min_interval, Duration::from_millis(1000));
    assert_eq!(limits.tls_handshakes, 3);
    assert_eq!(limits.connect_timeout, Duration::from_millis(5000));
    assert_eq!(limits.read_timeout, Duration::from_millis(10000));
    assert_eq!(limits.retries, 0);
}

#[test]
fn tls_connections_count_is_2_or_3() {
    let base = r#"
        [[target]]
        host = "10.0.0.5"
        ports = [443]
        protocol = "tls"
        [[target]]
        host = "10.0.0.5"
        ports = [22]
        protocol = "ssh"
    "#;
    let plain = plan(base, &FakeResolver::default());
    let tls = plain.targets.iter().find(|t| t.protocol == Protocol::Tls);
    let ssh = plain.targets.iter().find(|t| t.protocol == Protocol::Ssh);
    assert_eq!(tls.unwrap().connections, 2);
    assert_eq!(ssh.unwrap().connections, 1);

    let legacy = plan(
        &format!("legacy_tls_check = true\n{base}"),
        &FakeResolver::default(),
    );
    let tls = legacy.targets.iter().find(|t| t.protocol == Protocol::Tls);
    let ssh = legacy.targets.iter().find(|t| t.protocol == Protocol::Ssh);
    assert_eq!(tls.unwrap().connections, 3);
    assert_eq!(ssh.unwrap().connections, 1);
}

#[test]
fn tls_handshake_limit_caps_connections() {
    // The legacy check needs 3 handshakes. Without it, a TLS target needs 2.
    let text = r#"
        [limits]
        tls_handshakes = 1
        [[target]]
        host = "10.0.0.5"
        ports = [443]
        protocol = "tls"
    "#;
    assert_eq!(
        plan(text, &FakeResolver::default()).targets[0].connections,
        1
    );
}

#[test]
fn ip_target_has_no_sni() {
    let resolver = FakeResolver::default();
    let text = r#"
        [[target]]
        host = "10.0.0.5"
        ports = [443]
        protocol = "tls"
        [[target]]
        host = "2001:db8::1"
        ports = [443]
        protocol = "tls"
        [[target]]
        cidr = "10.0.1.0/31"
        ports = [443]
        protocol = "tls"
    "#;
    let plan = plan(text, &resolver);
    assert_eq!(plan.targets.len(), 4);
    assert!(plan.targets.iter().all(|t| t.host.is_none()));
    assert!(resolver.calls.borrow().is_empty(), "IP targets need no DNS");
}

#[test]
fn duplicate_targets_are_merged() {
    let text = r#"
        [[target]]
        host = "10.0.0.5"
        ports = [443, 443]
        protocol = "tls"
        [[target]]
        cidr = "10.0.0.5/32"
        ports = [443]
        protocol = "tls"
    "#;
    assert_eq!(plan(text, &FakeResolver::default()).targets.len(), 1);
}

#[test]
fn unknown_key_names_file_and_line() {
    let text = "override_limits = false\nbogus = 1\n";
    let error = ScopeFile::parse(text, "scope.toml").unwrap_err();
    let shown = error.to_string();
    assert!(shown.contains("scope.toml"), "{shown}");
    assert!(shown.contains("line 2"), "{shown}");
}

#[test]
fn unknown_key_in_target_names_line() {
    let text = "[[target]]\nhost = \"10.0.0.5\"\nports = [443]\nprotocol = \"tls\"\nport = 1\n";
    let shown = ScopeFile::parse(text, "scope.toml")
        .unwrap_err()
        .to_string();
    assert!(shown.contains("line 5"), "{shown}");
}

#[test]
fn bad_targets_are_parse_errors() {
    let cases = [
        // Neither host nor cidr.
        "[[target]]\nports = [443]\nprotocol = \"tls\"\n",
        // Both host and cidr.
        "[[target]]\nhost = \"a.example\"\ncidr = \"10.0.0.0/24\"\nports = [443]\nprotocol = \"tls\"\n",
        // No ports.
        "[[target]]\nhost = \"a.example\"\nports = []\nprotocol = \"tls\"\n",
        // Port zero.
        "[[target]]\nhost = \"a.example\"\nports = [0]\nprotocol = \"tls\"\n",
        // Unknown protocol.
        "[[target]]\nhost = \"a.example\"\nports = [443]\nprotocol = \"ftp\"\n",
        // A port in the host name.
        "[[target]]\nhost = \"a.example:443\"\nports = [443]\nprotocol = \"tls\"\n",
        // A bad CIDR.
        "[[target]]\ncidr = \"10.0.0.0/40\"\nports = [443]\nprotocol = \"tls\"\n",
        // An exclude with both keys.
        "[[exclude]]\nhost = \"a.example\"\ncidr = \"10.0.0.0/24\"\n",
        // An empty exclude.
        "[[exclude]]\n",
    ];
    for text in cases {
        let error = ScopeFile::parse(text, "scope.toml").unwrap_err();
        assert!(
            matches!(error, ScopeError::Parse { .. }),
            "{text}: {error:?}"
        );
    }
}

#[test]
fn allowed_hours_parse() {
    let day = scope("allowed_hours = \"09:00-17:00\"\n");
    let window = day.allowed_hours.unwrap();
    assert!(window.contains(9 * 60));
    assert!(window.contains(16 * 60 + 59));
    assert!(!window.contains(17 * 60));
    assert!(!window.contains(3 * 60));

    let night = scope("allowed_hours = \"22:00-06:00\"\n")
        .allowed_hours
        .unwrap();
    assert!(night.contains(23 * 60));
    assert!(night.contains(5 * 60));
    assert!(!night.contains(12 * 60));
    assert_eq!(
        night,
        HoursWindow::new(22 * 60, 6 * 60).unwrap(),
        "the window crosses midnight"
    );
}

#[test]
fn bad_allowed_hours_are_errors() {
    for value in [
        "9-17",
        "25:00-26:00",
        "09:00",
        "09:60-10:00",
        "09:00-09:00",
        "09:00-17:00-18:00",
        "",
    ] {
        let text = format!("allowed_hours = \"{value}\"\n");
        assert!(ScopeFile::parse(&text, "scope.toml").is_err(), "{value}");
    }
}

#[test]
fn scope_hash_is_sha256_hex() {
    assert_eq!(
        scope_hash(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn template_loads() {
    let template = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../pqaudit-cli/src/templates/scope.toml"
    ))
    .unwrap();
    // The template alone is valid and has no targets.
    let empty = ScopeFile::parse(&template, "scope.toml").unwrap();
    assert!(empty.target.is_empty());
    // Remove the comment mark from each example line. Example lines start with a lower case letter or a bracket.
    let uncommented: String = template
        .lines()
        .map(|line| match line.strip_prefix("# ") {
            Some(rest) if rest.starts_with(|c: char| c.is_ascii_lowercase() || c == '[') => rest,
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let full = ScopeFile::parse(&uncommented, "scope.toml")
        .unwrap_or_else(|error| panic!("{error}\n{uncommented}"));
    assert_eq!(full.target.len(), 2);
    assert_eq!(full.exclude.len(), 1);
    assert!(full.allowed_hours.is_some());
    build_plan(
        &full,
        &FakeResolver::with("pay.acme.example", &["10.0.0.5"]),
    )
    .unwrap();
}

#[test]
fn legacy_check_with_too_few_handshakes_is_a_configuration_error() {
    let text = "legacy_tls_check = true\n[limits]\ntls_handshakes = 2\n[[target]]\nhost = \"192.0.2.1\"\nports = [443]\nprotocol = \"tls\"\n";
    let error = build_plan(&scope(text), &FakeResolver::default()).unwrap_err();
    assert!(matches!(
        error,
        ScopeError::LegacyCheckNeedsHandshakes { .. }
    ));
    assert!(!error.is_refusal(), "a configuration error gives exit 1");
    let text = error.to_string();
    assert!(
        text.contains("tls_handshakes") && text.contains("legacy_tls_check"),
        "{text}"
    );
    // Three handshakes are enough.
    let ok = "legacy_tls_check = true\n[limits]\ntls_handshakes = 3\n[[target]]\nhost = \"192.0.2.1\"\nports = [443]\nprotocol = \"tls\"\n";
    assert_eq!(plan(ok, &FakeResolver::default()).targets[0].connections, 3);
}

/// Make a scope text with one TLS target for the host.
fn host_target(host: &str) -> String {
    format!("allowed_cidrs = [\"10.0.0.0/8\"]\n[[target]]\nhost = \"{host}\"\nports = [443]\nprotocol = \"tls\"\n")
}

#[test]
fn numeric_host_names_are_parse_errors() {
    for host in [
        "010.020.030.040",
        "10.1",
        "10.0.1",
        "167772161",
        "0x0a.0.0.1",
        "0X0A000001",
        "10.0.0.0x1",
        "127.1.",
        "1.2.3.4.5",
    ] {
        let error = ScopeFile::parse(&host_target(host), "scope.toml").unwrap_err();
        assert!(
            matches!(error, ScopeError::Parse { .. }),
            "{host}: {error:?}"
        );
        assert!(
            error.to_string().contains("canonical IP address"),
            "{host}: {error}"
        );
        let exclude = format!("[[exclude]]\nhost = \"{host}\"\n");
        let error = ScopeFile::parse(&exclude, "scope.toml").unwrap_err();
        assert!(
            error.to_string().contains("canonical IP address"),
            "exclude {host}: {error}"
        );
    }
}

#[test]
fn canonical_addresses_and_names_still_parse() {
    for host in [
        "10.0.0.1",
        "::1",
        "pay.example",
        "a1.example",
        "123.example",
    ] {
        ScopeFile::parse(&host_target(host), "scope.toml")
            .unwrap_or_else(|error| panic!("{host}: {error}"));
    }
}
