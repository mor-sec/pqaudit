//! The TLS probes: a hybrid-only handshake, a classical handshake, and the legacy check.
//!
//! The probes use rustls with the aws-lc-rs provider. The certificate verifier records the
//! chain and accepts all chains. This is safe, because the probes send no application data.

use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use pqaudit_core::x509::parse_certificate;
use pqaudit_core::{CertInfo, TlsObservation};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::SupportedKxGroup;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, ProtocolVersion, SignatureScheme, SupportedProtocolVersion,
};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::messages;
use crate::runtime::{Connected, ProbeCtx, Probes, SshObservationResult, TlsObservationWithCerts};
use crate::scope::PlannedTarget;
use crate::tls_legacy;

/// The probe name of the hybrid handshake in the audit log.
pub const PROBE_HYBRID: &str = "tls-hybrid";
/// The probe name of the classical handshake in the audit log.
pub const PROBE_CLASSICAL: &str = "tls-classical";

/// The most certificates that the tool reads from a chain.
const MAX_CHAIN: usize = 10;
/// The longest time to wait for the close of a session.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
/// The longest error text that the tool keeps from a peer or the system, in characters.
const MAX_ERROR_CHARS: usize = 200;

/// The probes that open real connections.
#[derive(Debug, Clone, Copy)]
pub struct RealProbes {
    legacy_tls_check: bool,
}

impl RealProbes {
    /// Make the probes. The flag `legacy_tls_check` comes from the scope file.
    ///
    /// The legacy check also needs 3 connections in the plan.
    pub fn new(legacy_tls_check: bool) -> Self {
        Self { legacy_tls_check }
    }
}

#[async_trait]
impl Probes for RealProbes {
    async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
        probe_tls(self.legacy_tls_check, t, ctx).await
    }

    async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
        Err(messages::SSH_NOT_AVAILABLE.to_string())
    }
}

/// A verifier that records the chain and accepts all chains.
#[derive(Debug)]
struct Recorder {
    chain: Mutex<Vec<Vec<u8>>>,
    schemes: Vec<SignatureScheme>,
}

impl Recorder {
    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.chain.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = self.chain.lock().unwrap_or_else(PoisonError::into_inner);
        chain.clear();
        chain.push(end_entity.as_ref().to_vec());
        chain.extend(
            intermediates
                .iter()
                .take(MAX_CHAIN)
                .map(|cert| cert.as_ref().to_vec()),
        );
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// One client setup: the configuration and the verifier that records the chain.
struct Setup {
    config: Arc<ClientConfig>,
    recorder: Arc<Recorder>,
}

fn setup(
    groups: Vec<&'static dyn SupportedKxGroup>,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<Setup, String> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = groups;
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let recorder = Arc::new(Recorder {
        chain: Mutex::new(Vec::new()),
        schemes,
    });
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| short(&e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(recorder.clone())
        .with_no_client_auth();
    // Each handshake must be a full handshake.
    config.resumption = Resumption::disabled();
    Ok(Setup {
        config: Arc::new(config),
        recorder,
    })
}

/// The setup for the hybrid handshake: TLS 1.3 and the hybrid groups only.
fn hybrid_setup() -> Result<Setup, String> {
    setup(
        vec![kx_group::X25519MLKEM768, kx_group::SECP256R1MLKEM768],
        &[&rustls::version::TLS13],
    )
}

/// The setup for the classical handshake: the groups of a normal client, TLS 1.3 and 1.2.
fn classical_setup() -> Result<Setup, String> {
    setup(
        vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

/// Keep the start of a text. A peer or the system can give a long text.
fn short(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

/// A failed handshake.
struct Failure {
    /// True if the tool must stop the probe of this target: no connect, or a timeout.
    fatal: bool,
    text: String,
}

/// A finished handshake.
struct Shake {
    version: String,
    group: Option<String>,
    suite: Option<String>,
    chain: Vec<Vec<u8>>,
}

fn version_text(version: ProtocolVersion) -> String {
    match version {
        ProtocolVersion::TLSv1_3 => String::from("TLS 1.3"),
        ProtocolVersion::TLSv1_2 => String::from("TLS 1.2"),
        other => format!("{other:?}"),
    }
}

fn server_name(t: &PlannedTarget) -> ServerName<'static> {
    t.host
        .as_ref()
        .and_then(|host| ServerName::try_from(host.clone()).ok())
        .unwrap_or_else(|| ServerName::IpAddress(t.ip.into()))
}

/// Do one handshake. The tool sends no data after it. It closes the session and the socket.
async fn handshake(
    ctx: &ProbeCtx<'_>,
    t: &PlannedTarget,
    label: &str,
    setup: &Setup,
) -> Result<Shake, Failure> {
    let Connected { stream, mut audit } = ctx.connect(t, label).await.map_err(|error| Failure {
        fatal: true,
        text: error.to_string(),
    })?;
    let connector = TlsConnector::from(setup.config.clone());
    let name = server_name(t);
    let attempt = timeout(ctx.limits.read_timeout, async {
        let tls = connector.connect(name, stream).await?;
        let (_, connection) = tls.get_ref();
        let shake = Shake {
            version: connection
                .protocol_version()
                .map_or_else(|| messages::UNKNOWN_VALUE.to_string(), version_text),
            group: connection
                .negotiated_key_exchange_group()
                .map(|group| format!("{:?}", group.name())),
            suite: connection
                .negotiated_cipher_suite()
                .map(|suite| format!("{:?}", suite.suite())),
            chain: Vec::new(),
        };
        Ok::<_, io::Error>((tls, shake))
    })
    .await;
    let chain = setup.recorder.take();
    match attempt {
        Ok(Ok((mut tls, mut shake))) => {
            // The handshake finished and the result is final. The close has its own time limit.
            // A slow peer must not change the result.
            let _ = timeout(CLOSE_TIMEOUT, tls.shutdown()).await;
            // Close the socket before the audit guard releases the host permit.
            drop(tls);
            audit.set_outcome("ok");
            shake.chain = chain;
            Ok(shake)
        }
        Ok(Err(error)) => {
            audit.set_outcome("tls-failed");
            Err(Failure {
                fatal: false,
                text: messages::HANDSHAKE_FAILED
                    .replace("{probe}", label)
                    .replace("{reason}", &short(&error.to_string())),
            })
        }
        Err(_) => {
            audit.set_outcome("timeout");
            Err(Failure {
                fatal: true,
                text: messages::HANDSHAKE_TIMEOUT.replace("{probe}", label),
            })
        }
    }
}

/// Read the certificates of a chain. Add the reason for each certificate that is not readable.
fn read_chain(ders: &[Vec<u8>], failures: &mut Vec<String>) -> Vec<CertInfo> {
    let mut chain = Vec::new();
    for (position, der) in ders.iter().take(MAX_CHAIN).enumerate() {
        match parse_certificate(der, position) {
            Ok(cert) => chain.push(cert),
            Err(error) => failures.push(
                messages::CHAIN_CERT_BAD
                    .replace("{position}", &position.to_string())
                    .replace("{reason}", &short(&error.reason())),
            ),
        }
    }
    if ders.len() > MAX_CHAIN {
        failures.push(messages::CHAIN_TOO_LONG.replace("{max}", &MAX_CHAIN.to_string()));
    }
    chain
}

fn adopt(obs: &mut TlsObservation, shake: &Shake) {
    obs.negotiated_version = Some(shake.version.clone());
    obs.negotiated_group.clone_from(&shake.group);
    obs.cipher_suite.clone_from(&shake.suite);
}

/// Probe a TLS target. The plan sets the number of connections.
///
/// The order is: hybrid, classical, and legacy. The count of connections cuts the list.
/// With one connection, the tool does the classical handshake only.
/// After a timeout or a failed connect, the tool makes no more connections to the target.
async fn probe_tls(
    legacy_tls_check: bool,
    t: &PlannedTarget,
    ctx: &ProbeCtx<'_>,
) -> TlsObservationWithCerts {
    let mut obs = TlsObservation {
        pq_hybrid_supported: None,
        negotiated_version: None,
        negotiated_group: None,
        cipher_suite: None,
        legacy_versions: None,
        errors: Vec::new(),
    };
    let mut failures: Vec<String> = Vec::new();
    let wanted = t.connections.min(ctx.limits.tls_handshakes);
    // The limit is for the address and port over all names. Other targets can use it first.
    let budget = ctx.claim_handshakes(t.ip, t.port, wanted);
    if budget == 0 {
        failures.push(messages::HANDSHAKE_LIMIT_USED.to_string());
        obs.errors.extend(failures.iter().cloned());
        return TlsObservationWithCerts {
            obs,
            chain: Vec::new(),
            failures,
        };
    }
    if budget < wanted {
        // The probe is not complete. This is a failure, so the scan exits with 3.
        failures.push(messages::HANDSHAKE_LIMIT_PART.to_string());
    }
    let (hybrid, classical) = match (hybrid_setup(), classical_setup()) {
        (Ok(hybrid), Ok(classical)) => (hybrid, classical),
        (Err(error), _) | (_, Err(error)) => {
            failures.push(error);
            obs.errors.extend(failures.iter().cloned());
            return TlsObservationWithCerts {
                obs,
                chain: Vec::new(),
                failures,
            };
        }
    };

    let mut chain_der: Vec<Vec<u8>> = Vec::new();
    let mut hybrid_rejected: Option<String> = None;
    let mut stop = false;
    // With one handshake, the tool does the hybrid one. It gives the verdict and the chain.
    if budget >= 1 {
        match handshake(ctx, t, PROBE_HYBRID, &hybrid).await {
            Ok(shake) => {
                obs.pq_hybrid_supported = Some(true);
                adopt(&mut obs, &shake);
                chain_der = shake.chain;
            }
            Err(failure) if failure.fatal => {
                failures.push(failure.text);
                stop = true;
            }
            Err(failure) => hybrid_rejected = Some(failure.text),
        }
    }
    if !stop && budget >= 2 {
        match handshake(ctx, t, PROBE_CLASSICAL, &classical).await {
            Ok(shake) => {
                adopt(&mut obs, &shake);
                if !shake.chain.is_empty() {
                    chain_der = shake.chain;
                }
                // The server speaks TLS. Only now is a rejection of the hybrid groups a fact.
                // This is a result, not a failure.
                if let Some(reason) = hybrid_rejected.take() {
                    obs.pq_hybrid_supported = Some(false);
                    obs.errors
                        .push(messages::HYBRID_REJECTED.replace("{reason}", &reason));
                }
            }
            Err(failure) => {
                stop = failure.fatal;
                failures.push(failure.text);
            }
        }
    }
    // With one handshake there is no classical handshake to confirm a hybrid rejection.
    if let Some(reason) = hybrid_rejected.take() {
        failures.push(messages::HYBRID_REJECTED.replace("{reason}", &reason));
    }
    if !stop && legacy_tls_check && budget >= 3 {
        match tls_legacy::probe(ctx, t).await {
            Ok(versions) => obs.legacy_versions = Some(versions),
            Err(reason) => {
                failures.push(messages::LEGACY_FAILED.replace("{reason}", &short(&reason)))
            }
        }
    }
    let chain = read_chain(&chain_der, &mut failures);
    obs.errors.extend(failures.iter().cloned());
    TlsObservationWithCerts {
        obs,
        chain,
        failures,
    }
}
