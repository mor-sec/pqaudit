//! Tests of the CycloneDX CBOM.

use std::collections::HashSet;

use chrono::{NaiveDate, TimeZone, Utc};
use pqaudit_core::assess::{AssessedFinding, Assessment, EngagementSummary};
use pqaudit_core::assets::AssetContext;
use pqaudit_core::complexity::Complexity;
use pqaudit_core::engagement::{Assumptions, Band, Size};
use pqaudit_core::scoring::ScoreBreakdown;
use pqaudit_core::{
    Agility, Algorithm, CertInfo, ChangeType, EndpointInfo, Finding, Fingerprint, FixOwner,
    InventoryItem, InventoryKind, KeyInfo, KeyKind, Location, Occurrence, PackOriginRef, PackRef,
    Protocol, Purpose, ResultsHeader, ScannerKind, Source, SshObservation, TestType, ThreatType,
    TlsObservation,
};
use pqaudit_report::cbom::render;
use pqaudit_rules::embedded::default_pack;
use pqaudit_rules::pack::RuleDef;
use serde_json::{json, Value};
use uuid::Uuid;

fn rsa(bits: u32) -> Algorithm {
    Algorithm {
        name: "RSA".to_string(),
        key_bits: Some(bits),
        curve: None,
    }
}

fn plain(name: &str) -> Algorithm {
    Algorithm {
        name: name.to_string(),
        key_bits: None,
        curve: None,
    }
}

fn endpoint_at(host: &str, port: u16, protocol: Protocol) -> Occurrence {
    Occurrence {
        location: Location::Endpoint {
            host: host.to_string(),
            ip: "192.0.2.1".parse().unwrap(),
            port,
            protocol,
        },
        evidence: "evidence".to_string(),
        run_id: Uuid::nil(),
    }
}

fn file_at(path: &str, line: Option<u32>) -> Occurrence {
    Occurrence {
        location: Location::File {
            path: path.to_string(),
            line,
        },
        evidence: "evidence".to_string(),
        run_id: Uuid::nil(),
    }
}

fn cert(n: u32, key: Algorithm, signature: &str) -> CertInfo {
    CertInfo {
        sha256: format!("{n:064x}"),
        subject: format!("CN=host{n}.example.com"),
        issuer: "CN=Test CA".to_string(),
        not_before: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        not_after: Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
        is_ca: false,
        key_usage: vec![],
        ext_key_usage: vec![],
        public_key: key,
        signature_algorithm: signature.to_string(),
        chain_position: Some(0),
    }
}

fn finding(n: u32, fingerprint: &str, occurrences: Vec<Occurrence>) -> Finding {
    Finding {
        id: format!("F-0000000{n}"),
        fingerprint: Fingerprint(fingerprint.to_string()),
        rule_id: "rule".to_string(),
        source: Source::Net,
        algorithm: None,
        purpose: Purpose::Signature,
        threat_type: ThreatType::Hndl,
        agility: Agility::Config,
        fix_owner: FixOwner::InHouse,
        also: vec![],
        occurrences,
        cert: None,
        key: None,
        endpoint: None,
    }
}

fn assessed(finding: Finding) -> AssessedFinding {
    AssessedFinding {
        finding,
        rule: RuleDef {
            id: "rule".to_string(),
            family: "rsa".to_string(),
            aliases: vec![],
            title: "Title".to_string(),
            description: "Description.".to_string(),
            remediation: "Fix it.".to_string(),
            threat_type: Some(ThreatType::Hndl),
            cwe: vec![],
            attack: vec![],
            change_type: ChangeType::Config,
            size_impact: vec![],
            testing: vec![TestType::Unit],
        },
        asset: None,
        context: AssetContext::unassessed(),
        deadline: None,
        score: ScoreBreakdown {
            factors: vec![],
            total: 10.0,
        },
        band: Band::Low,
        override_: None,
        effective_band: Band::Low,
        complexity: Complexity {
            change_type: ChangeType::Config,
            size: Size::M,
            migration_years: 1.0,
            reasons: vec![],
        },
        testing: vec![TestType::Unit],
    }
}

fn cert_finding(n: u32, host: &str, key: Algorithm, signature: &str) -> AssessedFinding {
    let info = cert(n, key.clone(), signature);
    let mut f = finding(
        n,
        &format!("cert:{n:032x}"),
        vec![endpoint_at(host, 443, Protocol::Tls)],
    );
    f.algorithm = Some(key);
    f.cert = Some(info);
    assessed(f)
}

fn tls_finding() -> AssessedFinding {
    let mut f = finding(
        5,
        "endpoint:a",
        vec![endpoint_at("a.example.com", 443, Protocol::Tls)],
    );
    f.algorithm = Some(plain("X25519"));
    f.endpoint = Some(EndpointInfo {
        protocol: Protocol::Tls,
        tls: Some(TlsObservation {
            pq_hybrid_supported: Some(false),
            negotiated_version: Some("TLSv1.3".to_string()),
            negotiated_group: Some("X25519".to_string()),
            cipher_suite: Some("TLS_AES_128_GCM_SHA256".to_string()),
            legacy_versions: None,
            errors: vec![],
        }),
        ssh: None,
    });
    assessed(f)
}

fn inventory() -> Vec<InventoryItem> {
    let pq_cert = cert(7, plain("ML-DSA-65"), "ML-DSA-65");
    vec![
        InventoryItem {
            kind: InventoryKind::Certificate,
            fingerprint: Fingerprint(format!("cert:{:032x}", 7)),
            pq_ready: true,
            algorithm: Some(plain("ML-DSA-65")),
            cert: Some(pq_cert),
            key: None,
            endpoint: None,
            occurrences: vec![file_at("/etc/pki/pq.pem", Some(3))],
        },
        InventoryItem {
            kind: InventoryKind::Key,
            fingerprint: Fingerprint("key:abc".to_string()),
            pq_ready: false,
            algorithm: Some(plain("Ed25519")),
            cert: None,
            key: Some(KeyInfo {
                fingerprint_sha256: "ab".repeat(32),
                kind: KeyKind::X509Spki,
                algorithm: Some(Algorithm {
                    name: "Ed25519".to_string(),
                    key_bits: Some(256),
                    curve: None,
                }),
                comment: None,
            }),
            endpoint: None,
            occurrences: vec![file_at("/home/u/id.pub", None)],
        },
        InventoryItem {
            kind: InventoryKind::Key,
            fingerprint: Fingerprint("place:0123".to_string()),
            pq_ready: false,
            algorithm: Some(rsa(2048)),
            cert: None,
            key: Some(KeyInfo {
                fingerprint_sha256: String::new(),
                kind: KeyKind::Pkcs8Private,
                algorithm: Some(rsa(2048)),
                comment: None,
            }),
            endpoint: None,
            occurrences: vec![file_at("/etc/ssl/private/key.pem", None)],
        },
        InventoryItem {
            kind: InventoryKind::Endpoint,
            fingerprint: Fingerprint("endpoint:ssh".to_string()),
            pq_ready: true,
            algorithm: None,
            cert: None,
            key: None,
            endpoint: Some(EndpointInfo {
                protocol: Protocol::Ssh,
                tls: None,
                ssh: Some(SshObservation {
                    banner: "SSH-2.0-OpenSSH_9.9".to_string(),
                    kex: vec!["mlkem768x25519-sha256".to_string()],
                    host_key_algorithms: vec!["ssh-ed25519".to_string()],
                    ciphers: vec!["chacha20-poly1305@openssh.com".to_string()],
                    macs: vec![],
                }),
            }),
            occurrences: vec![endpoint_at("ssh.example.com", 22, Protocol::Ssh)],
        },
    ]
}

fn assessment(redacted: bool) -> Assessment {
    let started = Utc.with_ymd_and_hms(2026, 10, 1, 9, 0, 0).unwrap();
    let pack = PackRef {
        id: "pqaudit-rules".to_string(),
        version: "1.0.0".to_string(),
        content_hash: "abc".to_string(),
        origin: PackOriginRef::Embedded,
    };
    let findings = vec![
        cert_finding(1, "a.example.com", rsa(2048), "sha256WithRSAEncryption"),
        cert_finding(2, "b.example.com", rsa(2048), "sha256WithRSAEncryption"),
        tls_finding(),
    ];
    Assessment {
        engagement: EngagementSummary {
            client: "Acme Corp".to_string(),
            assessor: "Assessor".to_string(),
            assessment_date: NaiveDate::from_ymd_opt(2026, 10, 20).unwrap(),
            profiles: vec!["us".to_string()],
            sector: None,
        },
        header: ResultsHeader {
            schema_version: 1,
            engagement: "acme".to_string(),
            tool_version: "9.9.9".to_string(),
            rules_pack: pack.clone(),
            scanner: ScannerKind::Merged,
            host: "scanner".to_string(),
            operator: "operator".to_string(),
            started,
            finished: started,
            scope_hash: None,
            audit_log_hash: None,
            runs: vec![],
            redacted,
        },
        findings,
        inventory: inventory(),
        errors: vec![],
        planning_milestones: vec![],
        orphaned_overrides: vec![],
        overrides_need_key: false,
        unassessed_count: 0,
        assumptions: Assumptions { crqc_year: 2035 },
        pack,
    }
}

fn bom() -> Value {
    render(&assessment(false), default_pack())
}

fn components(bom: &Value) -> &Vec<Value> {
    bom["components"].as_array().unwrap()
}

fn of_type<'a>(bom: &'a Value, asset_type: &str) -> Vec<&'a Value> {
    components(bom)
        .iter()
        .filter(|c| c["cryptoProperties"]["assetType"] == asset_type)
        .collect()
}

fn by_ref<'a>(bom: &'a Value, bom_ref: &str) -> &'a Value {
    components(bom)
        .iter()
        .find(|c| c["bom-ref"] == bom_ref)
        .unwrap_or_else(|| panic!("no component {bom_ref}"))
}

#[path = "support/validator.rs"]
mod validator_support;
use validator_support::validator;

#[test]
fn cbom_validates_against_cyclonedx_1_6() {
    let validator = validator();
    for redacted in [false, true] {
        let value = render(&assessment(redacted), default_pack());
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{errors:#?}");
    }
    // The check must be able to fail.
    let mut broken = bom();
    broken["components"][0]["cryptoProperties"]["assetType"] = json!("not-a-type");
    assert!(!validator.is_valid(&broken));
    // The check must also read a format and a file that the schema names.
    let mut late = bom();
    late["components"][0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] =
        json!(7);
    assert!(!validator.is_valid(&late));
    let mut bad_date = bom();
    let at = components(&bad_date)
        .iter()
        .position(|c| c["cryptoProperties"]["assetType"] == "certificate")
        .unwrap();
    bad_date["components"][at]["cryptoProperties"]["certificateProperties"]["notValidAfter"] =
        json!("tomorrow");
    assert!(!validator.is_valid(&bad_date));
}

#[test]
fn hash_levels_follow_nist_categories() {
    // Collision search on SHA-256 is category 2, on SHA-384 category 4, on SHA-512 category 5.
    let pack = default_pack();
    for (name, level) in [("SHA-256", 2), ("SHA-384", 4), ("SHA-512", 5)] {
        assert_eq!(
            pack.algorithm(name).unwrap().nist_quantum_level,
            level,
            "{name}"
        );
    }
}

#[test]
fn top_level_fields() {
    let value = bom();
    assert_eq!(value["bomFormat"], "CycloneDX");
    assert_eq!(value["specVersion"], "1.6");
    assert!(value["serialNumber"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));
    let tool = &value["metadata"]["tools"]["components"][0];
    assert_eq!(tool["name"], "pqaudit");
    assert_eq!(tool["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["metadata"]["component"]["name"], "Acme Corp");
}

fn property<'a>(bom: &'a Value, name: &str) -> Option<&'a Value> {
    bom["metadata"]["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"] == name)
        .map(|p| &p["value"])
}

#[test]
fn redacted_results_set_a_property() {
    let plain = bom();
    assert!(property(&plain, "pqaudit:redacted").is_none());
    let redacted = render(&assessment(true), default_pack());
    assert_eq!(
        property(&redacted, "pqaudit:redacted"),
        Some(&json!("true"))
    );
}

#[test]
fn redacted_results_hide_the_client_name() {
    let mut a = assessment(true);
    a.header.engagement = "redacted:0123456789ab".to_string();
    let value = render(&a, default_pack());
    let text = value.to_string();
    assert!(!text.contains("Acme Corp"), "the client name is in clear");
    assert_eq!(
        value["metadata"]["component"]["name"],
        "redacted:0123456789ab"
    );
    assert!(value["metadata"]["component"]["description"]
        .as_str()
        .unwrap()
        .contains("redacted"));
}

#[test]
fn rules_pack_origin_is_a_property() {
    assert_eq!(
        property(&bom(), "pqaudit:rules-pack-origin"),
        Some(&json!("embedded"))
    );
    assert!(property(&bom(), "pqaudit:rules-pack-signer").is_none());

    let mut a = assessment(false);
    a.pack.origin = PackOriginRef::Installed {
        path: "/data/rules/1.0.0".to_string(),
        signed_by: "key-b".to_string(),
        rotation_chain: vec!["key-a".to_string(), "key-b".to_string()],
    };
    let installed = render(&a, default_pack());
    assert_eq!(
        property(&installed, "pqaudit:rules-pack-origin"),
        Some(&json!("installed"))
    );
    assert_eq!(
        property(&installed, "pqaudit:rules-pack-signer"),
        Some(&json!("key-b"))
    );

    a.pack.origin = PackOriginRef::Unsigned {
        path: "/data/rules/1.0.0".to_string(),
    };
    let unsigned = render(&a, default_pack());
    assert_eq!(
        property(&unsigned, "pqaudit:rules-pack-origin"),
        Some(&json!("unsigned"))
    );
}

#[test]
fn algorithm_components_deduped() {
    let value = bom();
    let algorithms = of_type(&value, "algorithm");
    // Two certificates and one private key use RSA with 2048 bits.
    let rsa_2048: Vec<_> = algorithms
        .iter()
        .filter(|c| {
            c["name"] == "RSA"
                && c["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "2048"
        })
        .collect();
    assert_eq!(rsa_2048.len(), 1);
    let refs: HashSet<_> = components(&value)
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), components(&value).len(), "bom-ref is unique");
    let props = &rsa_2048[0]["cryptoProperties"];
    assert_eq!(props["oid"], "1.2.840.113549.1.1.1");
    assert_eq!(props["algorithmProperties"]["primitive"], "pke");
    assert_eq!(props["algorithmProperties"]["nistQuantumSecurityLevel"], 0);
}

#[test]
fn algorithms_with_one_oid_stay_apart() {
    let mut a = assessment(false);
    let mut ecdsa = Algorithm {
        name: "ECDSA".to_string(),
        key_bits: Some(256),
        curve: Some("P-256".to_string()),
    };
    a.findings.push(cert_finding(
        8,
        "c.example.com",
        ecdsa.clone(),
        "ecdsa-with-SHA256",
    ));
    ecdsa.name = "ECDH".to_string();
    a.findings
        .push(cert_finding(9, "d.example.com", ecdsa, "ecdsa-with-SHA256"));
    let value = render(&a, default_pack());
    let curve: Vec<_> = of_type(&value, "algorithm")
        .into_iter()
        .filter(|c| c["cryptoProperties"]["oid"] == "1.2.840.10045.2.1")
        .collect();
    let names: HashSet<_> = curve.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, HashSet::from(["ECDSA", "ECDH"]));
    assert_eq!(
        curve[0]["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"],
        "P-256"
    );
    assert_eq!(
        curve[0]["cryptoProperties"]["algorithmProperties"]["curve"],
        "P-256"
    );
}

#[test]
fn cert_component_refs_algorithms() {
    let value = bom();
    let certs = of_type(&value, "certificate");
    assert_eq!(certs.len(), 3);
    let cert = by_ref(&value, &format!("cert:{:032x}", 1));
    assert_eq!(cert["type"], "cryptographic-asset");
    let props = &cert["cryptoProperties"]["certificateProperties"];
    assert_eq!(props["subjectName"], "CN=host1.example.com");
    assert_eq!(props["issuerName"], "CN=Test CA");
    assert_eq!(props["notValidBefore"], "2026-01-01T00:00:00Z");
    assert_eq!(props["notValidAfter"], "2027-01-01T00:00:00Z");
    assert_eq!(props["certificateFormat"], "X.509");
    let signature = by_ref(&value, props["signatureAlgorithmRef"].as_str().unwrap());
    assert_eq!(
        signature["cryptoProperties"]["algorithmProperties"]["primitive"],
        "signature"
    );
    let public_key = by_ref(&value, props["subjectPublicKeyRef"].as_str().unwrap());
    let key_props = &public_key["cryptoProperties"]["relatedCryptoMaterialProperties"];
    assert_eq!(key_props["type"], "public-key");
    assert_eq!(key_props["size"], 2048);
    let algorithm = by_ref(&value, key_props["algorithmRef"].as_str().unwrap());
    assert_eq!(algorithm["name"], "RSA");
    // The dependency list names the algorithms of the certificate.
    let dependency = value["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == cert["bom-ref"])
        .unwrap();
    let depends: Vec<_> = dependency["dependsOn"].as_array().unwrap().to_vec();
    assert!(depends.contains(&signature["bom-ref"]));
    assert!(depends.contains(&algorithm["bom-ref"]));
    // The location is a property.
    let location = &cert["properties"][0];
    assert_eq!(location["name"], "pqaudit:location");
    assert_eq!(location["value"], "a.example.com:443");
}

#[test]
fn every_reference_points_to_a_component() {
    let value = bom();
    let mut refs: HashSet<String> = components(&value)
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap().to_string())
        .collect();
    for service in value["services"].as_array().unwrap() {
        refs.insert(service["bom-ref"].as_str().unwrap().to_string());
    }
    for dependency in value["dependencies"].as_array().unwrap() {
        assert!(refs.contains(dependency["ref"].as_str().unwrap()));
        for target in dependency["dependsOn"].as_array().unwrap() {
            assert!(refs.contains(target.as_str().unwrap()), "{target}");
        }
    }
    let mut named = Vec::new();
    collect_refs(&value["components"], &mut named);
    assert!(!named.is_empty());
    for name in named {
        assert!(refs.contains(&name), "{name}");
    }
}

fn collect_refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if matches!(
                    key.as_str(),
                    "signatureAlgorithmRef" | "subjectPublicKeyRef" | "algorithmRef"
                ) {
                    out.push(item.as_str().unwrap().to_string());
                } else {
                    collect_refs(item, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_refs(item, out)),
        _ => {}
    }
}

#[test]
fn endpoint_service_depends_on_protocol_and_cert() {
    let value = bom();
    let services = value["services"].as_array().unwrap();
    let service = services
        .iter()
        .find(|s| s["name"] == "a.example.com:443")
        .unwrap();
    assert_eq!(service["endpoints"], json!(["https://a.example.com:443"]));
    let dependency = value["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == service["bom-ref"])
        .unwrap();
    let depends: Vec<&str> = dependency["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let protocol = depends
        .iter()
        .map(|r| by_ref(&value, r))
        .find(|c| c["cryptoProperties"]["assetType"] == "protocol")
        .expect("a protocol");
    let protocol_props = &protocol["cryptoProperties"]["protocolProperties"];
    assert_eq!(protocol_props["type"], "tls");
    assert_eq!(protocol_props["version"], "TLSv1.3");
    let suite = &protocol_props["cipherSuites"][0];
    assert_eq!(suite["name"], "TLS_AES_128_GCM_SHA256");
    let group = by_ref(&value, suite["algorithms"][0].as_str().unwrap());
    assert_eq!(group["name"], "X25519");
    assert!(depends.contains(&format!("cert:{:032x}", 1).as_str()));
    assert!(!depends.contains(&format!("cert:{:032x}", 2).as_str()));
    let ssh = services
        .iter()
        .find(|s| s["name"] == "ssh.example.com:22")
        .unwrap();
    assert_eq!(ssh["endpoints"], json!(["ssh://ssh.example.com:22"]));
    let ssh_protocol = components(&value)
        .iter()
        .find(|c| c["cryptoProperties"]["protocolProperties"]["type"] == "ssh")
        .unwrap();
    assert_eq!(
        ssh_protocol["cryptoProperties"]["protocolProperties"]["version"],
        "2.0"
    );
}

#[test]
fn pq_algorithm_has_level_3() {
    let value = bom();
    let ml_dsa = of_type(&value, "algorithm")
        .into_iter()
        .find(|c| c["name"] == "ML-DSA-65")
        .expect("ML-DSA-65 component");
    let props = &ml_dsa["cryptoProperties"]["algorithmProperties"];
    assert_eq!(props["nistQuantumSecurityLevel"], 3);
    assert_eq!(props["primitive"], "signature");
    assert_eq!(ml_dsa["cryptoProperties"]["oid"], "2.16.840.1.101.3.4.3.18");
}

#[test]
fn inventory_items_are_in_the_cbom() {
    let value = bom();
    // The place key has no public key. The fingerprint is the reference.
    let private = by_ref(&value, "place:0123");
    let props = &private["cryptoProperties"]["relatedCryptoMaterialProperties"];
    assert_eq!(props["type"], "private-key");
    assert_eq!(props["size"], 2048);
    let public = by_ref(&value, "key:abc");
    assert_eq!(
        public["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"],
        "public-key"
    );
    let location = &public["properties"][0];
    assert_eq!(location["value"], "/home/u/id.pub");
    let located = by_ref(&value, &format!("cert:{:032x}", 7));
    assert_eq!(located["properties"][0]["value"], "/etc/pki/pq.pem:3");
}

#[test]
fn no_key_bytes_in_the_text() {
    let text = serde_json::to_string(&bom()).unwrap();
    assert!(!text.contains("PRIVATE KEY"));
    assert!(!text.contains("\"value\":\"MII"));
}

fn level_of(bom: &Value, name: &str) -> Option<Value> {
    let found = of_type(bom, "algorithm")
        .into_iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no algorithm {name}"));
    found["cryptoProperties"]["algorithmProperties"]
        .get("nistQuantumSecurityLevel")
        .cloned()
}

#[test]
fn unknown_security_level_is_omitted() {
    let mut a = assessment(false);
    a.findings.push(cert_finding(
        8,
        "c.example.com",
        plain("made-up-kex"),
        "made-up-signature",
    ));
    a.findings.push(cert_finding(
        9,
        "d.example.com",
        plain("SLH-DSA"),
        "SLH-DSA",
    ));
    a.findings.push(cert_finding(
        10,
        "e.example.com",
        plain("SLH-DSA-SHA2-192s"),
        "SLH-DSA-SHA2-256f",
    ));
    let value = render(&a, default_pack());
    assert_eq!(level_of(&value, "made-up-kex"), None);
    assert_eq!(level_of(&value, "made-up-signature"), None);
    assert_eq!(level_of(&value, "SLH-DSA"), None);
    assert_eq!(level_of(&value, "SLH-DSA-SHA2-192s"), Some(json!(3)));
    assert_eq!(level_of(&value, "SLH-DSA-SHA2-256f"), Some(json!(5)));
    // A name that the pack lists as classical keeps level 0.
    assert_eq!(level_of(&value, "RSA"), Some(json!(0)));
    assert!(validator().is_valid(&value));
}

#[test]
fn cbom_is_reproducible() {
    let a = assessment(false);
    let first = serde_json::to_string(&render(&a, default_pack())).unwrap();
    let second = serde_json::to_string(&render(&a, default_pack())).unwrap();
    assert_eq!(first, second);
    let value = render(&a, default_pack());
    assert_eq!(value["metadata"]["timestamp"], "2026-10-01T09:00:00Z");
    let mut other = assessment(false);
    other.findings.push(cert_finding(
        8,
        "c.example.com",
        rsa(4096),
        "sha256WithRSAEncryption",
    ));
    let changed = render(&other, default_pack());
    assert_ne!(value["serialNumber"], changed["serialNumber"]);
}
