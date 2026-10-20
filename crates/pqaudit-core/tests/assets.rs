//! Tests for asset matching.

use pqaudit_core::assets::{match_asset, AssetContext, Ctx};
use pqaudit_core::engagement::{Asset, AssetsFile, Exposure};
use pqaudit_core::{Location, Protocol};

fn asset(name: &str, hosts: &[&str], cidrs: &[&str], paths: &[&str]) -> Asset {
    let text = format!(
        "[[asset]]\nname = {name:?}\nmatch = {{ hosts = {hosts:?}, cidrs = {cidrs:?}, paths = {paths:?} }}\n"
    );
    let file: AssetsFile = toml::from_str(&text).unwrap();
    file.asset.into_iter().next().unwrap()
}

fn endpoint(host: &str, ip: &str) -> Location {
    Location::Endpoint {
        host: host.into(),
        ip: ip.parse().unwrap(),
        port: 443,
        protocol: Protocol::Tls,
    }
}

fn file(path: &str) -> Location {
    Location::File {
        path: path.into(),
        line: None,
    }
}

#[test]
fn host_match_case_insensitive() {
    let assets = vec![asset("Pay", &["Pay.Acme.Example"], &[], &[])];
    let found = match_asset(&assets, &endpoint("PAY.acme.example", "192.0.2.1"));
    assert_eq!(found.map(|a| a.name.as_str()), Some("Pay"));
    assert!(match_asset(&assets, &endpoint("other.acme.example", "192.0.2.1")).is_none());
}

#[test]
fn cidr_match() {
    let assets = vec![asset("Net", &[], &["10.1.0.0/16", "2001:db8:1::/48"], &[])];
    assert!(match_asset(&assets, &endpoint("x", "10.1.200.3")).is_some());
    assert!(match_asset(&assets, &endpoint("x", "10.2.0.1")).is_none());
    assert!(match_asset(&assets, &endpoint("x", "2001:db8:1::5")).is_some());
    assert!(match_asset(&assets, &endpoint("x", "2001:db8:2::5")).is_none());
}

#[test]
fn path_glob_match() {
    let assets = vec![asset("Repo", &[], &[], &["repos/payments/**", "*.jks"])];
    assert!(match_asset(&assets, &file("repos/payments/src/tls/key.pem")).is_some());
    assert!(match_asset(&assets, &file("store.jks")).is_some());
    assert!(match_asset(&assets, &file("repos/billing/key.pem")).is_none());
    // Paths do not match hosts, and hosts do not match paths.
    assert!(match_asset(&assets, &endpoint("repos/payments/x", "192.0.2.1")).is_none());
}

#[test]
fn first_match_wins() {
    let assets = vec![
        asset("First", &["a.example"], &[], &[]),
        asset("Second", &["a.example"], &["192.0.2.0/24"], &[]),
    ];
    let found = match_asset(&assets, &endpoint("a.example", "192.0.2.9")).unwrap();
    assert_eq!(found.name, "First");
    let found = match_asset(&assets, &endpoint("b.example", "192.0.2.9")).unwrap();
    assert_eq!(found.name, "Second");
}

#[test]
fn no_match_is_unassessed() {
    let assets = vec![asset("Pay", &["pay.example"], &[], &[])];
    assert!(match_asset(&assets, &endpoint("other.example", "192.0.2.1")).is_none());
    assert!(match_asset(&[], &file("a.pem")).is_none());
    let context = AssetContext::unassessed();
    assert_eq!(context.classification, Ctx::Unassessed);
    assert_eq!(context.data_lifespan_years, Ctx::Unassessed);
    assert_eq!(context.exposure, Ctx::Unassessed);
    assert_eq!(context.priority_tier, Ctx::Unassessed);
    assert_eq!(context.vendor, Ctx::Unassessed);
    assert_eq!(context.hardware_constrained, Ctx::Unassessed);
    assert!(context.business_unit.is_none() && context.owner.is_none());
}

#[test]
fn missing_asset_field_stays_unassessed() {
    let text = "[[asset]]\nname = \"A\"\nexposure = \"partner\"\nvendor = false\n";
    let file: AssetsFile = toml::from_str(text).unwrap();
    let context = AssetContext::from_asset(&file.asset[0]);
    assert_eq!(context.exposure, Ctx::Assessed(Exposure::Partner));
    assert_eq!(context.vendor, Ctx::Assessed(false));
    assert_eq!(context.classification, Ctx::Unassessed);
    assert!(context.has_unassessed());
}

#[test]
fn ipv4_mapped_ipv6_matches_ipv4_cidr() {
    let assets = vec![asset("Net", &[], &["10.1.0.0/16"], &[])];
    assert!(match_asset(&assets, &endpoint("x", "::ffff:10.1.2.3")).is_some());
    assert!(match_asset(&assets, &endpoint("x", "::ffff:10.2.2.3")).is_none());
}
