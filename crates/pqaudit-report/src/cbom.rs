//! The cryptography bill of materials (CBOM) in CycloneDX 1.6.
//!
//! The CBOM comes from the findings and the inventory together.
//! The results file holds only the items that are not findings in its inventory.
//! The CBOM never holds key bytes. A key component holds the algorithm and the size.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, SecondsFormat};
use pqaudit_core::assess::Assessment;
use pqaudit_core::{
    Algorithm, CertInfo, EndpointInfo, Fingerprint, KeyInfo, KeyKind, Location, Occurrence,
    Protocol,
};
use pqaudit_rules::pack::{Primitive, RulesPack};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// The name of the property that holds a place where the tool saw an item.
const LOCATION: &str = "pqaudit:location";

/// The name of the property that holds a purpose of an algorithm in the CBOM of a tool.
const PURPOSE: &str = "pqaudit:purpose";

/// The name of the property that marks redacted results.
const REDACTED: &str = "pqaudit:redacted";

/// Make the CBOM of an assessment. The result is a CycloneDX 1.6 document.
pub fn render(a: &Assessment, pack: &RulesPack) -> Value {
    let mut builder = Builder::new(pack);
    for finding in &a.findings {
        let f = &finding.finding;
        builder.add(&Subject {
            fingerprint: &f.fingerprint,
            algorithm: f.algorithm.as_ref(),
            cert: f.cert.as_ref(),
            key: f.key.as_ref(),
            endpoint: f.endpoint.as_ref(),
            occurrences: &f.occurrences,
        });
    }
    for item in &a.inventory {
        builder.add(&Subject {
            fingerprint: &item.fingerprint,
            algorithm: item.algorithm.as_ref(),
            cert: item.cert.as_ref(),
            key: item.key.as_ref(),
            endpoint: item.endpoint.as_ref(),
            occurrences: &item.occurrences,
        });
    }
    let (components, services, dependencies) = builder.finish();
    let mut metadata = json!({
        "timestamp": timestamp(a),
        "tools": {
            "components": [{
                "type": "application",
                "name": "pqaudit",
                "version": env!("CARGO_PKG_VERSION"),
            }],
        },
        "component": {
            "type": "platform",
            "bom-ref": "client",
            "name": a.engagement.client,
        },
    });
    if a.header.redacted {
        metadata["properties"] = json!([{"name": REDACTED, "value": "true"}]);
    }
    let serial = serial_number(a, &components, &services, &dependencies);
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "services": services,
        "dependencies": dependencies,
    })
}

/// A Rust crate that a tool build contains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCrate {
    /// The crate name.
    pub name: String,
    /// The crate version.
    pub version: String,
}

/// One purpose of the tool, with the algorithms and crates that serve it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUse {
    /// The purpose, for example `tls-probe`.
    pub purpose: String,
    /// The names of the algorithms.
    pub algorithms: Vec<String>,
    /// The crates that do the work.
    pub crates: Vec<ToolCrate>,
}

/// Make the CBOM of a tool from the algorithms that it declares for each purpose.
///
/// The time comes from the caller, so the same input gives the same CBOM.
/// Each crate is a library component. It depends on the algorithms of its purposes.
/// Each algorithm shows its purposes in a property.
pub fn render_tool(
    name: &str,
    version: &str,
    time: DateTime<chrono::Utc>,
    uses: &[ToolUse],
    pack: &RulesPack,
) -> Value {
    let mut builder = Builder::new(pack);
    let mut purposes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut libraries: BTreeMap<String, Value> = BTreeMap::new();
    for item in uses {
        let refs: Vec<String> = item
            .algorithms
            .iter()
            .map(|algorithm| {
                let hash = algorithm.starts_with("SHA") || algorithm.starts_with("MD5");
                builder.algorithm_ref(algorithm, None, None, if hash { "hash" } else { "unknown" })
            })
            .collect();
        for reference in &refs {
            purposes
                .entry(reference.clone())
                .or_default()
                .insert(item.purpose.clone());
        }
        for krate in &item.crates {
            let reference = format!("crate:{}@{}", krate.name, krate.version);
            libraries.insert(
                reference.clone(),
                json!({
                    "type": "library",
                    "bom-ref": reference,
                    "name": krate.name,
                    "version": krate.version,
                    "purl": format!("pkg:cargo/{}@{}", krate.name, krate.version),
                }),
            );
            builder.depend(&reference, refs.clone());
        }
    }
    let (mut components, _, dependencies) = builder.finish();
    for component in &mut components {
        let reference = component["bom-ref"].as_str().unwrap_or_default();
        if let Some(list) = purposes.get(reference) {
            let properties: Vec<Value> = list
                .iter()
                .map(|purpose| json!({"name": PURPOSE, "value": purpose}))
                .collect();
            component["properties"] = json!(properties);
        }
    }
    components.extend(libraries.into_values());
    let content = json!({"components": components, "dependencies": dependencies});
    let text = serde_json::to_string(&content).unwrap_or_default();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v5(&Uuid::NAMESPACE_OID, text.as_bytes())),
        "version": 1,
        "metadata": {
            "timestamp": time.to_rfc3339_opts(SecondsFormat::Secs, true),
            "component": {
                "type": "application",
                "bom-ref": "tool",
                "name": name,
                "version": version,
            },
        },
        "components": components,
        "dependencies": dependencies,
    })
}

/// The time of the BOM. The variable `SOURCE_DATE_EPOCH` wins if the user sets it. Else the scan end time.
///
/// The function never reads the clock, so the same input gives the same BOM.
fn timestamp(a: &Assessment) -> String {
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0));
    epoch
        .unwrap_or(a.header.finished)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The serial number: a version 5 UUID over the content of the BOM and the runs.
fn serial_number(
    a: &Assessment,
    components: &[Value],
    services: &[Value],
    dependencies: &[Value],
) -> String {
    let content = json!({
        "components": components,
        "services": services,
        "dependencies": dependencies,
        "runs": a.header.runs,
    });
    let text = serde_json::to_string(&content).unwrap_or_default();
    format!(
        "urn:uuid:{}",
        Uuid::new_v5(&Uuid::NAMESPACE_OID, text.as_bytes())
    )
}

/// One item of the findings or of the inventory.
struct Subject<'a> {
    fingerprint: &'a Fingerprint,
    algorithm: Option<&'a Algorithm>,
    cert: Option<&'a CertInfo>,
    key: Option<&'a KeyInfo>,
    endpoint: Option<&'a EndpointInfo>,
    occurrences: &'a [Occurrence],
}

/// A component with the places where the tool saw it.
struct Entry {
    component: Value,
    locations: BTreeSet<String>,
}

/// The protocol of a network endpoint, as the CBOM shows it.
#[derive(Default)]
struct ServiceEntry {
    certs: BTreeSet<String>,
    version: Option<String>,
    suites: Vec<Value>,
    algorithms: BTreeSet<String>,
}

/// The key of a service: the host in lower case, the port, and the protocol name.
type ServiceKey = (String, u16, &'static str);

struct Builder<'p> {
    pack: &'p RulesPack,
    algorithms: BTreeMap<String, Value>,
    certs: BTreeMap<String, Entry>,
    keys: BTreeMap<String, Entry>,
    services: BTreeMap<ServiceKey, ServiceEntry>,
    dependencies: BTreeMap<String, BTreeSet<String>>,
}

impl<'p> Builder<'p> {
    fn new(pack: &'p RulesPack) -> Self {
        Self {
            pack,
            algorithms: BTreeMap::new(),
            certs: BTreeMap::new(),
            keys: BTreeMap::new(),
            services: BTreeMap::new(),
            dependencies: BTreeMap::new(),
        }
    }

    fn add(&mut self, subject: &Subject<'_>) {
        let locations: Vec<String> = subject
            .occurrences
            .iter()
            .map(|occurrence| location_text(&occurrence.location))
            .collect();
        if let Some(cert) = subject.cert {
            self.add_cert(subject.fingerprint, cert, &locations);
        }
        if let Some(key) = subject.key {
            self.add_key(subject, key, &locations);
        }
        let ends: Vec<ServiceKey> = subject
            .occurrences
            .iter()
            .filter_map(|occurrence| service_key(&occurrence.location))
            .collect();
        for end in ends {
            let entry = self.services.entry(end.clone()).or_default();
            if subject.cert.is_some() {
                entry.certs.insert(subject.fingerprint.0.clone());
            }
            if let Some(info) = subject
                .endpoint
                .filter(|info| protocol_name(info.protocol) == end.2)
            {
                self.add_endpoint_info(&end, info);
            }
        }
    }

    fn add_endpoint_info(&mut self, key: &ServiceKey, info: &EndpointInfo) {
        let mut version = None;
        let mut suites = Vec::new();
        let mut refs = BTreeSet::new();
        if let Some(tls) = &info.tls {
            version.clone_from(&tls.negotiated_version);
            let mut algorithms = Vec::new();
            if let Some(group) = &tls.negotiated_group {
                let name = self.algorithm_ref(group, None, None, "key-agree");
                refs.insert(name.clone());
                algorithms.push(name);
            }
            let mut suite = Map::new();
            if let Some(name) = &tls.cipher_suite {
                suite.insert("name".to_string(), json!(name));
            }
            if !algorithms.is_empty() {
                suite.insert("algorithms".to_string(), json!(algorithms));
            }
            if !suite.is_empty() {
                suites.push(Value::Object(suite));
            }
        }
        if let Some(ssh) = &info.ssh {
            version = ssh_version(&ssh.banner);
            let groups = [
                (&ssh.kex, "key-agree"),
                (&ssh.host_key_algorithms, "signature"),
                (&ssh.ciphers, "unknown"),
                (&ssh.macs, "mac"),
            ];
            let mut algorithms = Vec::new();
            for (names, fallback) in groups {
                for name in names {
                    let name = self.algorithm_ref(name, None, None, fallback);
                    refs.insert(name.clone());
                    algorithms.push(name);
                }
            }
            if !algorithms.is_empty() {
                suites.push(json!({"algorithms": algorithms}));
            }
        }
        let entry = self.services.entry(key.clone()).or_default();
        if entry.version.is_none() {
            entry.version = version;
        }
        for suite in suites {
            if !entry.suites.contains(&suite) {
                entry.suites.push(suite);
            }
        }
        entry.algorithms.extend(refs);
    }

    fn add_cert(&mut self, fingerprint: &Fingerprint, cert: &CertInfo, locations: &[String]) {
        let reference = fingerprint.0.clone();
        if let Some(entry) = self.certs.get_mut(&reference) {
            entry.locations.extend(locations.iter().cloned());
            return;
        }
        let key = &cert.public_key;
        let key_algorithm =
            self.algorithm_ref(&key.name, key.key_bits, key.curve.as_deref(), "unknown");
        let signature = self.signature_ref(&cert.signature_algorithm);
        let key_ref = format!("{reference}#public-key");
        let mut material = Map::new();
        material.insert("type".to_string(), json!("public-key"));
        material.insert("algorithmRef".to_string(), json!(key_algorithm));
        if let Some(bits) = key.key_bits {
            material.insert("size".to_string(), json!(bits));
        }
        self.keys.insert(
            key_ref.clone(),
            Entry {
                component: crypto_component(
                    &key_ref,
                    &key_ref,
                    json!({
                        "assetType": "related-crypto-material",
                        "relatedCryptoMaterialProperties": material,
                    }),
                ),
                locations: BTreeSet::new(),
            },
        );
        self.depend(&key_ref, [key_algorithm.clone()]);
        self.depend(
            &reference,
            [signature.clone(), key_ref.clone(), key_algorithm],
        );
        let component = crypto_component(
            &reference,
            &cert.subject,
            json!({
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": cert.subject,
                    "issuerName": cert.issuer,
                    "notValidBefore": cert.not_before.to_rfc3339_opts(SecondsFormat::Secs, true),
                    "notValidAfter": cert.not_after.to_rfc3339_opts(SecondsFormat::Secs, true),
                    "signatureAlgorithmRef": signature,
                    "subjectPublicKeyRef": key_ref,
                    "certificateFormat": "X.509",
                },
            }),
        );
        self.certs.insert(
            reference,
            Entry {
                component,
                locations: locations.iter().cloned().collect(),
            },
        );
    }

    fn add_key(&mut self, subject: &Subject<'_>, key: &KeyInfo, locations: &[String]) {
        let reference = subject.fingerprint.0.clone();
        if let Some(entry) = self.keys.get_mut(&reference) {
            entry.locations.extend(locations.iter().cloned());
            return;
        }
        let private = matches!(key.kind, KeyKind::Pkcs8Private | KeyKind::EncryptedPrivate);
        let mut material = Map::new();
        material.insert(
            "type".to_string(),
            json!(if private { "private-key" } else { "public-key" }),
        );
        if let Some(algorithm) = key.algorithm.as_ref().or(subject.algorithm) {
            let algorithm_ref = self.algorithm_ref(
                &algorithm.name,
                algorithm.key_bits,
                algorithm.curve.as_deref(),
                "unknown",
            );
            material.insert("algorithmRef".to_string(), json!(algorithm_ref));
            if let Some(bits) = algorithm.key_bits {
                material.insert("size".to_string(), json!(bits));
            }
            self.depend(&reference, [algorithm_ref]);
        }
        let component = crypto_component(
            &reference,
            &reference,
            json!({
                "assetType": "related-crypto-material",
                "relatedCryptoMaterialProperties": material,
            }),
        );
        self.keys.insert(
            reference,
            Entry {
                component,
                locations: locations.iter().cloned().collect(),
            },
        );
    }

    /// Make the algorithm component, if it is new. Return its reference.
    ///
    /// The reference holds the name and the parameter set. The OID is not enough:
    /// ECDSA and ECDH share one OID.
    fn algorithm_ref(
        &mut self,
        name: &str,
        key_bits: Option<u32>,
        curve: Option<&str>,
        fallback_primitive: &str,
    ) -> String {
        let parameter = curve
            .map(str::to_string)
            .or(key_bits.map(|bits| bits.to_string()));
        let reference = match &parameter {
            Some(parameter) => format!("alg:{name}:{parameter}"),
            None => format!("alg:{name}"),
        };
        if !self.algorithms.contains_key(&reference) {
            let fact = self.pack.algorithm(name);
            let primitive = fact.map_or(fallback_primitive, |fact| primitive_name(fact.primitive));
            let mut properties = Map::new();
            properties.insert("primitive".to_string(), json!(primitive));
            if let Some(parameter) = &parameter {
                properties.insert("parameterSetIdentifier".to_string(), json!(parameter));
            }
            if let Some(curve) = curve {
                properties.insert("curve".to_string(), json!(curve));
            }
            if let Some(level) = security_level(self.pack, name) {
                properties.insert("nistQuantumSecurityLevel".to_string(), json!(level));
            }
            let mut crypto = json!({
                "assetType": "algorithm",
                "algorithmProperties": properties,
            });
            if let Some(oid) = fact.and_then(|fact| fact.oid.as_ref()) {
                crypto["oid"] = json!(oid);
            }
            self.algorithms.insert(
                reference.clone(),
                crypto_component(&reference, name, crypto),
            );
        }
        reference
    }

    /// Make the component of a certificate signature algorithm. Return its reference.
    ///
    /// The name is the name in the certificate, for example `sha256WithRSAEncryption`.
    /// The security level comes from the algorithm in the name.
    fn signature_ref(&mut self, name: &str) -> String {
        let reference = format!("alg:sig:{name}");
        if !self.algorithms.contains_key(&reference) {
            let lower = name.to_ascii_lowercase();
            let base = if self.pack.algorithm(name).is_some() {
                name
            } else if lower.contains("rsa") {
                "RSA"
            } else if lower.starts_with("ecdsa") {
                "ECDSA"
            } else if lower.starts_with("dsa") {
                "DSA"
            } else {
                name
            };
            let mut properties = Map::new();
            properties.insert("primitive".to_string(), json!("signature"));
            if let Some(level) = security_level(self.pack, base) {
                properties.insert("nistQuantumSecurityLevel".to_string(), json!(level));
            }
            let mut crypto = json!({
                "assetType": "algorithm",
                "algorithmProperties": properties,
            });
            if let Some(oid) = self.pack.algorithm(name).and_then(|fact| fact.oid.as_ref()) {
                crypto["oid"] = json!(oid);
            }
            self.algorithms.insert(
                reference.clone(),
                crypto_component(&reference, name, crypto),
            );
        }
        reference
    }

    fn depend(&mut self, from: &str, to: impl IntoIterator<Item = String>) {
        self.dependencies
            .entry(from.to_string())
            .or_default()
            .extend(to);
    }

    fn finish(mut self) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
        let mut components: Vec<Value> = self.algorithms.values().cloned().collect();
        components.extend(entries(&self.certs));
        components.extend(entries(&self.keys));
        let mut services = Vec::new();
        let list = std::mem::take(&mut self.services);
        for ((host, port, protocol), entry) in list {
            let name = format!("{host}:{port}");
            let service_ref = format!("service:{protocol}:{name}");
            let protocol_ref = format!("protocol:{protocol}:{name}");
            let mut properties = Map::new();
            properties.insert("type".to_string(), json!(protocol));
            if let Some(version) = &entry.version {
                properties.insert("version".to_string(), json!(version));
            }
            if !entry.suites.is_empty() {
                properties.insert("cipherSuites".to_string(), json!(entry.suites));
            }
            components.push(crypto_component(
                &protocol_ref,
                &format!("{protocol}://{name}"),
                json!({
                    "assetType": "protocol",
                    "protocolProperties": properties,
                }),
            ));
            let scheme = if protocol == "tls" { "https" } else { "ssh" };
            let shown = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                name.clone()
            };
            services.push(json!({
                "bom-ref": service_ref,
                "name": name,
                "endpoints": [format!("{scheme}://{shown}")],
            }));
            let mut depends = vec![protocol_ref.clone()];
            depends.extend(entry.certs.iter().cloned());
            self.dependencies
                .entry(service_ref)
                .or_default()
                .extend(depends);
            self.dependencies
                .entry(protocol_ref)
                .or_default()
                .extend(entry.algorithms);
        }
        let dependencies = self
            .dependencies
            .into_iter()
            .filter(|(_, targets)| !targets.is_empty())
            .map(|(reference, targets)| json!({"ref": reference, "dependsOn": targets}))
            .collect();
        (components, services, dependencies)
    }
}

fn service_key(location: &Location) -> Option<ServiceKey> {
    match location {
        Location::Endpoint {
            host,
            port,
            protocol,
            ..
        } => Some((host.to_lowercase(), *port, protocol_name(*protocol))),
        Location::File { .. } => None,
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tls => "tls",
        Protocol::Ssh => "ssh",
    }
}

fn primitive_name(primitive: Primitive) -> &'static str {
    match primitive {
        Primitive::Pke => "pke",
        Primitive::Kem => "kem",
        Primitive::Signature => "signature",
        Primitive::KeyAgree => "key-agree",
        Primitive::Hash => "hash",
        Primitive::Cipher => "block-cipher",
    }
}

/// The NIST quantum security level of an algorithm, if the tool knows it.
///
/// A name that the pack does not list has no level.
/// SLH-DSA has levels 1, 3, and 5, so the level comes from the size in the name.
/// The plain name `SLH-DSA` has no level.
fn security_level(pack: &RulesPack, name: &str) -> Option<u8> {
    if let Some(rest) = name.strip_prefix("SLH-DSA") {
        let size = rest.trim_end_matches(['s', 'f']).rsplit('-').next()?;
        return match size {
            "128" => Some(1),
            "192" => Some(3),
            "256" => Some(5),
            _ => None,
        };
    }
    pack.algorithm(name).map(|fact| fact.nist_quantum_level)
}

/// The protocol version in an SSH banner. The banner `SSH-2.0-name` gives `2.0`.
fn ssh_version(banner: &str) -> Option<String> {
    let rest = banner.strip_prefix("SSH-")?;
    let version = rest.split('-').next()?;
    (!version.is_empty()).then(|| version.to_string())
}

fn location_text(location: &Location) -> String {
    match location {
        Location::File { path, line: None } => path.clone(),
        Location::File {
            path,
            line: Some(line),
        } => format!("{path}:{line}"),
        Location::Endpoint { host, port, .. } => format!("{host}:{port}"),
    }
}

fn crypto_component(reference: &str, name: &str, crypto: Value) -> Value {
    json!({
        "type": "cryptographic-asset",
        "bom-ref": reference,
        "name": name,
        "cryptoProperties": crypto,
    })
}

/// The components of a map, with the location properties.
fn entries(map: &BTreeMap<String, Entry>) -> Vec<Value> {
    map.values()
        .map(|entry| {
            let mut component = entry.component.clone();
            if !entry.locations.is_empty() {
                let properties: Vec<Value> = entry
                    .locations
                    .iter()
                    .map(|place| json!({"name": LOCATION, "value": place}))
                    .collect();
                component["properties"] = json!(properties);
            }
            component
        })
        .collect()
}
