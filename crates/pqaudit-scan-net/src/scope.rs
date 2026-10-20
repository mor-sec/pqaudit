//! The scope file, the limits, and the target plan.
//!
//! The scope file is the only source of network targets. The plan lists the
//! `host:port` pairs that the tool can connect to. The tool refuses all other targets.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use ipnet::IpNet;
use pqaudit_core::Protocol;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::messages;

/// The name of the scope file.
pub const SCOPE_FILE: &str = "scope.toml";

/// The most addresses in a CIDR target. A larger target needs `override_limits`.
pub const MAX_CIDR_ADDRESSES: u128 = 256;

/// The most addresses in a CIDR target, also with `override_limits`.
pub const HARD_MAX_CIDR_ADDRESSES: u128 = 65_536;

/// The number of TLS connections for each port.
const TLS_CONNECTIONS: u8 = 2;
/// The number of TLS connections for each port when `legacy_tls_check` is true.
const TLS_CONNECTIONS_LEGACY: u8 = 3;

/// An error in the scope file or in the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The scope file does not exist.
    Missing {
        /// The name of the file.
        file: String,
    },
    /// The tool cannot read the scope file.
    Io {
        /// The name of the file.
        file: String,
        /// The reason.
        reason: String,
    },
    /// The file is not valid TOML, or has a wrong key or value.
    Parse {
        /// The name of the file.
        file: String,
        /// The line number, counted from 1.
        line: usize,
        /// The reason.
        reason: String,
    },
    /// A limit is above its default and `override_limits` is false.
    LimitAboveDefault {
        /// The name of the limit.
        name: &'static str,
        /// The requested value.
        requested: u64,
        /// The default value.
        default: u64,
    },
    /// A limit is below its default minimum and `override_limits` is false.
    LimitBelowDefault {
        /// The name of the limit.
        name: &'static str,
        /// The requested value.
        requested: u64,
        /// The default value.
        default: u64,
    },
    /// A limit is zero but must be 1 or more.
    LimitZero {
        /// The name of the limit.
        name: &'static str,
    },
}

impl ScopeError {
    /// True if the error is a refusal because of safety. The exit code is then 2.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::LimitAboveDefault { .. } | Self::LimitBelowDefault { .. }
        )
    }
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Missing { file } => messages::SCOPE_MISSING.replace("{file}", file),
            Self::Io { file, reason } => messages::SCOPE_IO
                .replace("{file}", file)
                .replace("{reason}", reason),
            Self::Parse { file, line, reason } => messages::SCOPE_PARSE
                .replace("{file}", file)
                .replace("{line}", &line.to_string())
                .replace("{reason}", reason),
            Self::LimitAboveDefault {
                name,
                requested,
                default,
            } => messages::LIMIT_ABOVE_DEFAULT
                .replace("{name}", name)
                .replace("{requested}", &requested.to_string())
                .replace("{default}", &default.to_string()),
            Self::LimitBelowDefault {
                name,
                requested,
                default,
            } => messages::LIMIT_BELOW_DEFAULT
                .replace("{name}", name)
                .replace("{requested}", &requested.to_string())
                .replace("{default}", &default.to_string()),
            Self::LimitZero { name } => messages::LIMIT_ZERO.replace("{name}", name),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for ScopeError {}

/// A daily time window in local time. The window can cross midnight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoursWindow {
    start: u16,
    end: u16,
}

impl HoursWindow {
    /// Make a window from two minutes of the day. Return `None` if a value is not valid.
    ///
    /// The start is in the window. The end is not. The two values must differ.
    pub fn new(start: u16, end: u16) -> Option<Self> {
        (start < 24 * 60 && end < 24 * 60 && start != end).then_some(Self { start, end })
    }

    /// Read the form `HH:MM-HH:MM`.
    pub fn parse(text: &str) -> Option<Self> {
        let (start, end) = text.split_once('-')?;
        Self::new(parse_time(start)?, parse_time(end)?)
    }

    /// True if the minute of the day is in the window.
    pub fn contains(&self, minute_of_day: u16) -> bool {
        if self.start < self.end {
            (self.start..self.end).contains(&minute_of_day)
        } else {
            minute_of_day >= self.start || minute_of_day < self.end
        }
    }
}

/// Read `HH:MM` as a minute of the day.
fn parse_time(text: &str) -> Option<u16> {
    let (hours, minutes) = text.split_once(':')?;
    let digits = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(hours) || !digits(minutes) {
        return None;
    }
    let (hours, minutes): (u16, u16) = (hours.parse().ok()?, minutes.parse().ok()?);
    (hours < 24 && minutes < 60).then_some(hours * 60 + minutes)
}

impl TryFrom<String> for HoursWindow {
    type Error = String;
    fn try_from(text: String) -> Result<Self, String> {
        Self::parse(&text).ok_or_else(|| messages::HOURS_INVALID.to_string())
    }
}

impl<'de> Deserialize<'de> for HoursWindow {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::try_from(text).map_err(serde::de::Error::custom)
    }
}

/// A host in the scope file: a lower case host name or an IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// A host name. The tool resolves it one time.
    Name(String),
    /// An IP address. The connection has no SNI.
    Ip(IpAddr),
}

impl Host {
    fn parse(text: &str) -> Result<Self, String> {
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(Self::Ip(ip.to_canonical()));
        }
        let name = text.strip_suffix('.').unwrap_or(text).to_ascii_lowercase();
        let valid = !name.is_empty()
            && name.len() <= 253
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            && !name.starts_with('.')
            && !name.contains("..");
        if valid {
            Ok(Self::Name(name))
        } else {
            Err(messages::HOST_INVALID.to_string())
        }
    }
}

/// What a target or an exclude names: a host or a CIDR range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// A host name or an IP address.
    Host(Host),
    /// A CIDR range.
    Cidr(IpNet),
}

impl Selector {
    fn from_keys(host: Option<String>, cidr: Option<IpNet>, kind: &str) -> Result<Self, String> {
        match (host, cidr) {
            (Some(host), None) => Host::parse(&host).map(Self::Host),
            (None, Some(cidr)) => canonical_net(cidr).map(Self::Cidr),
            _ => Err(kind.to_string()),
        }
    }
}

/// Make a canonical range. A mapped IPv6 range becomes an IPv4 range.
///
/// Addresses are canonical too, so both sides of a match use one family.
/// A range that is wider than the mapped range and that holds it is an error.
fn canonical_net(net: IpNet) -> Result<IpNet, String> {
    let net = net.trunc();
    let IpNet::V6(v6) = net else { return Ok(net) };
    let mapped_base = std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0);
    if v6.prefix_len() >= 96 {
        return Ok(match v6.network().to_ipv4_mapped() {
            Some(v4) => IpNet::V4(
                ipnet::Ipv4Net::new(v4, v6.prefix_len() - 96).expect("the prefix is at most 32"),
            ),
            None => net,
        });
    }
    if v6.contains(&mapped_base) {
        return Err(messages::MAPPED_RANGE_WIDE.to_string());
    }
    Ok(net)
}

fn canonical_nets<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IpNet>, D::Error> {
    Vec::<IpNet>::deserialize(deserializer)?
        .into_iter()
        .map(|net| canonical_net(net).map_err(serde::de::Error::custom))
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTarget {
    host: Option<String>,
    cidr: Option<IpNet>,
    ports: Vec<u16>,
    protocol: Protocol,
}

/// A `[[target]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawTarget")]
pub struct Target {
    /// The host or the CIDR range.
    pub selector: Selector,
    /// The ports. The list is not empty.
    pub ports: Vec<u16>,
    /// The protocol of all ports.
    pub protocol: Protocol,
}

impl TryFrom<RawTarget> for Target {
    type Error = String;
    fn try_from(raw: RawTarget) -> Result<Self, String> {
        let selector = Selector::from_keys(raw.host, raw.cidr, messages::TARGET_KIND)?;
        if raw.ports.is_empty() {
            return Err(messages::PORTS_EMPTY.to_string());
        }
        if raw.ports.contains(&0) {
            return Err(messages::PORT_ZERO.to_string());
        }
        Ok(Self {
            selector,
            ports: raw.ports,
            protocol: raw.protocol,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExclude {
    host: Option<String>,
    cidr: Option<IpNet>,
}

/// An `[[exclude]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawExclude")]
pub struct Exclude {
    /// The host or the CIDR range.
    pub selector: Selector,
}

impl TryFrom<RawExclude> for Exclude {
    type Error = String;
    fn try_from(raw: RawExclude) -> Result<Self, String> {
        Selector::from_keys(raw.host, raw.cidr, messages::EXCLUDE_KIND)
            .map(|selector| Exclude { selector })
    }
}

/// The `[limits]` table. A missing value means the default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsToml {
    /// The most connections at the same time in total.
    pub concurrency: Option<usize>,
    /// The most connections at the same time to one host.
    pub per_host: Option<usize>,
    /// The least time between two connections to one host, in milliseconds.
    pub min_interval_ms: Option<u64>,
    /// The most TLS handshakes for each port.
    pub tls_handshakes: Option<u8>,
    /// The connect timeout, in milliseconds.
    pub connect_timeout_ms: Option<u64>,
    /// The read timeout, in milliseconds.
    pub read_timeout_ms: Option<u64>,
    /// The number of retries.
    pub retries: Option<u8>,
}

/// The content of `scope.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScopeFile {
    /// If true, each address of a host name must be in an allowed range.
    pub require_ip_in_cidr: Option<bool>,
    /// The ranges that host names can resolve to. These are not targets.
    #[serde(deserialize_with = "canonical_nets")]
    pub allowed_cidrs: Vec<IpNet>,
    /// The hours in which the scan can start, in local time.
    pub allowed_hours: Option<HoursWindow>,
    /// If true, limits can be above their defaults.
    pub override_limits: bool,
    /// If true, a TLS port gets one more connection for old protocol versions.
    pub legacy_tls_check: bool,
    /// The limits.
    pub limits: LimitsToml,
    /// The targets.
    pub target: Vec<Target>,
    /// The exclusions. They have priority over the targets.
    pub exclude: Vec<Exclude>,
}

impl ScopeFile {
    /// Read the text of a scope file. `file` is the name that the error messages show.
    pub fn parse(text: &str, file: &str) -> Result<Self, ScopeError> {
        toml::from_str(text).map_err(|error| {
            let offset = error.span().map_or(0, |span| span.start).min(text.len());
            let line = 1 + text.as_bytes()[..offset]
                .iter()
                .filter(|b| **b == b'\n')
                .count();
            ScopeError::Parse {
                file: file.to_string(),
                line,
                reason: error.message().to_string(),
            }
        })
    }

    /// Read `scope.toml` in the engagement directory. Return the file and its bytes.
    pub fn load(dir: &Path) -> Result<(Self, Vec<u8>), ScopeError> {
        let bytes = match std::fs::read(dir.join(SCOPE_FILE)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(ScopeError::Missing {
                    file: SCOPE_FILE.to_string(),
                })
            }
            Err(error) => {
                return Err(ScopeError::Io {
                    file: SCOPE_FILE.to_string(),
                    reason: error.to_string(),
                })
            }
        };
        let text = std::str::from_utf8(&bytes).map_err(|error| ScopeError::Io {
            file: SCOPE_FILE.to_string(),
            reason: error.to_string(),
        })?;
        Ok((Self::parse(text, SCOPE_FILE)?, bytes))
    }
}

/// The SHA-256 hash of the scope file bytes, in hex.
pub fn scope_hash(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// The limits of a scan. A limit never goes above its default unless `override_limits` is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most connections at the same time in total.
    pub concurrency: usize,
    /// The most connections at the same time to one host.
    pub per_host: usize,
    /// The least time between two connections to one host.
    pub min_interval: Duration,
    /// The most TLS handshakes for each port.
    pub tls_handshakes: u8,
    /// The connect timeout.
    pub connect_timeout: Duration,
    /// The read timeout.
    pub read_timeout: Duration,
    /// The number of retries.
    pub retries: u8,
}

impl Limits {
    /// The default limits.
    pub const DEFAULT: Limits = Limits {
        concurrency: 4,
        per_host: 1,
        min_interval: Duration::from_millis(1000),
        tls_handshakes: 3,
        connect_timeout: Duration::from_millis(5000),
        read_timeout: Duration::from_millis(10_000),
        retries: 0,
    };

    /// Apply the requested values to the defaults.
    ///
    /// A value above its default is an error, unless `override_limits` is true.
    /// The minimum interval is the reverse: a value below its default is an error.
    pub fn effective(requested: &LimitsToml, override_limits: bool) -> Result<Limits, ScopeError> {
        let d = Limits::DEFAULT;
        let ms = |t: Duration| t.as_millis() as u64;
        // Take a value that must not be above its default.
        let upper = |name: &'static str, value: Option<u64>, default: u64, zero_ok: bool| {
            let Some(value) = value else {
                return Ok(default);
            };
            if value == 0 && !zero_ok {
                return Err(ScopeError::LimitZero { name });
            }
            if value > default && !override_limits {
                return Err(ScopeError::LimitAboveDefault {
                    name,
                    requested: value,
                    default,
                });
            }
            Ok(value)
        };
        let interval = match requested.min_interval_ms {
            Some(value) if value < ms(d.min_interval) && !override_limits => {
                return Err(ScopeError::LimitBelowDefault {
                    name: "min_interval_ms",
                    requested: value,
                    default: ms(d.min_interval),
                })
            }
            Some(value) => value,
            None => ms(d.min_interval),
        };
        Ok(Limits {
            concurrency: upper(
                "concurrency",
                requested.concurrency.map(|v| v as u64),
                d.concurrency as u64,
                false,
            )? as usize,
            per_host: upper(
                "per_host",
                requested.per_host.map(|v| v as u64),
                d.per_host as u64,
                false,
            )? as usize,
            min_interval: Duration::from_millis(interval),
            tls_handshakes: upper(
                "tls_handshakes",
                requested.tls_handshakes.map(u64::from),
                u64::from(d.tls_handshakes),
                false,
            )? as u8,
            connect_timeout: Duration::from_millis(upper(
                "connect_timeout_ms",
                requested.connect_timeout_ms,
                ms(d.connect_timeout),
                false,
            )?),
            read_timeout: Duration::from_millis(upper(
                "read_timeout_ms",
                requested.read_timeout_ms,
                ms(d.read_timeout),
                false,
            )?),
            retries: upper(
                "retries",
                requested.retries.map(u64::from),
                u64::from(d.retries),
                true,
            )? as u8,
        })
    }
}

/// A source of IP addresses for host names.
pub trait Resolver {
    /// Resolve a host name to IP addresses.
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The resolver of the operating system. It uses `ToSocketAddrs`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        Ok((host, 0u16)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect())
    }
}

/// A target that the tool can connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTarget {
    /// The host name for SNI. It is `None` for a target that is an IP address or a CIDR.
    pub host: Option<String>,
    /// The IP address to connect to.
    pub ip: IpAddr,
    /// The port.
    pub port: u16,
    /// The protocol.
    pub protocol: Protocol,
    /// The number of connections that the tool makes to this port.
    pub connections: u8,
}

/// The reason that the tool refuses a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalReason {
    /// The resolver gave an error.
    ResolveFailed {
        /// The text of the error.
        reason: String,
    },
    /// The host name has no addresses.
    NoAddresses,
    /// Some addresses are not in an allowed CIDR range.
    IpOutsideAllowed {
        /// The addresses that are outside.
        ips: Vec<IpAddr>,
    },
    /// The CIDR range has more than 256 addresses.
    CidrTooLarge {
        /// The limit.
        max: u128,
    },
    /// The CIDR range has more addresses than the tool ever scans.
    CidrHuge {
        /// The limit.
        max: u128,
    },
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::ResolveFailed { reason } => messages::REFUSE_RESOLVE.replace("{reason}", reason),
            Self::NoAddresses => messages::REFUSE_NO_ADDRESSES.to_string(),
            Self::IpOutsideAllowed { ips } => {
                let list: Vec<String> = ips.iter().map(ToString::to_string).collect();
                messages::REFUSE_OUTSIDE.replace("{ips}", &list.join(", "))
            }
            Self::CidrTooLarge { max } => {
                messages::REFUSE_CIDR_LARGE.replace("{max}", &max.to_string())
            }
            Self::CidrHuge { max } => messages::REFUSE_CIDR_HUGE.replace("{max}", &max.to_string()),
        };
        f.write_str(&text)
    }
}

/// A target that the tool refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The target as the scope file names it.
    pub target: String,
    /// The reason.
    pub reason: RefusalReason,
}

/// The targets of a scan, the refusals, and the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPlan {
    /// The targets that the tool can connect to.
    pub targets: Vec<PlannedTarget>,
    /// The targets that the tool refuses.
    pub refused: Vec<Refusal>,
    /// The limits of the scan.
    pub limits: Limits,
}

impl TargetPlan {
    /// True if the tool refuses a target. One refusal stops the full scan.
    pub fn is_refused(&self) -> bool {
        !self.refused.is_empty()
    }
}

/// Resolve each host name one time. The cache keeps the answers.
struct CachedResolver<'a> {
    resolver: &'a dyn Resolver,
    cache: HashMap<String, Result<Vec<IpAddr>, String>>,
}

impl CachedResolver<'_> {
    fn resolve(&mut self, host: &str) -> Result<Vec<IpAddr>, String> {
        let resolver = self.resolver;
        self.cache
            .entry(host.to_string())
            .or_insert_with(|| {
                resolver
                    .resolve(host)
                    .map(|ips| {
                        let mut seen = HashSet::new();
                        ips.into_iter()
                            .map(|ip| ip.to_canonical())
                            .filter(|ip| seen.insert(*ip))
                            .collect()
                    })
                    .map_err(|error| error.to_string())
            })
            .clone()
    }
}

/// The number of addresses in a range. A very large range gives `u128::MAX`.
fn address_count(net: &IpNet) -> u128 {
    let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
    if host_bits > 32 {
        u128::MAX
    } else {
        1u128 << host_bits
    }
}

/// List all addresses of a range. The caller checks the size first.
fn addresses(net: &IpNet) -> Vec<IpAddr> {
    match net {
        IpNet::V4(net) => {
            let start = u32::from(net.network());
            (0..address_count(&IpNet::V4(*net)) as u32)
                .map(|n| IpAddr::V4(std::net::Ipv4Addr::from(start + n)))
                .collect()
        }
        IpNet::V6(net) => {
            let start = u128::from(net.network());
            (0..address_count(&IpNet::V6(*net)))
                .map(|n| IpAddr::V6(std::net::Ipv6Addr::from(start + n)).to_canonical())
                .collect()
        }
    }
}

/// Make the target plan from the scope file.
///
/// The function resolves each host name one time. Exclusions have priority over targets.
/// If a resolved address is outside the allowed ranges, the plan refuses the full host.
pub fn build_plan(scope: &ScopeFile, resolver: &dyn Resolver) -> Result<TargetPlan, ScopeError> {
    let limits = Limits::effective(&scope.limits, scope.override_limits)?;
    let mut resolver = CachedResolver {
        resolver,
        cache: HashMap::new(),
    };
    let mut refused = Vec::new();

    // Collect the exclusions. A host name in an exclusion also gives its addresses.
    let mut excluded_nets: Vec<IpNet> = Vec::new();
    let mut excluded_names: Vec<&str> = Vec::new();
    for exclude in &scope.exclude {
        match &exclude.selector {
            Selector::Cidr(net) => excluded_nets.push(*net),
            Selector::Host(Host::Ip(ip)) => excluded_nets.push(IpNet::from(*ip)),
            Selector::Host(Host::Name(name)) => excluded_names.push(name),
        }
    }
    for name in &excluded_names {
        match resolver.resolve(name) {
            Ok(ips) => excluded_nets.extend(ips.into_iter().map(IpNet::from)),
            Err(reason) => refused.push(Refusal {
                target: format!("exclude {name}"),
                reason: RefusalReason::ResolveFailed { reason },
            }),
        }
    }
    let is_excluded = |ip: &IpAddr| excluded_nets.iter().any(|net| net.contains(ip));

    // The ranges that host names can resolve to: the allowed ranges and the CIDR targets.
    let mut allowed: Vec<IpNet> = scope.allowed_cidrs.iter().map(IpNet::trunc).collect();
    allowed.extend(scope.target.iter().filter_map(|t| match &t.selector {
        Selector::Cidr(net) => Some(*net),
        Selector::Host(_) => None,
    }));
    let require_ip_in_cidr = scope.require_ip_in_cidr.unwrap_or(!allowed.is_empty());

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for target in &scope.target {
        let (sni, ips) = match &target.selector {
            Selector::Host(Host::Ip(ip)) => (None, vec![*ip]),
            Selector::Host(Host::Name(name)) => {
                if excluded_names.contains(&name.as_str()) {
                    continue;
                }
                let ips = match resolver.resolve(name) {
                    Ok(ips) if ips.is_empty() => {
                        refused.push(Refusal {
                            target: name.clone(),
                            reason: RefusalReason::NoAddresses,
                        });
                        continue;
                    }
                    Ok(ips) => ips,
                    Err(reason) => {
                        refused.push(Refusal {
                            target: name.clone(),
                            reason: RefusalReason::ResolveFailed { reason },
                        });
                        continue;
                    }
                };
                // Check every resolved address first. Then apply the exclusions.
                let outside: Vec<IpAddr> = ips
                    .iter()
                    .filter(|ip| require_ip_in_cidr && !allowed.iter().any(|net| net.contains(*ip)))
                    .copied()
                    .collect();
                if !outside.is_empty() {
                    refused.push(Refusal {
                        target: name.clone(),
                        reason: RefusalReason::IpOutsideAllowed { ips: outside },
                    });
                    continue;
                }
                let ips = ips.into_iter().filter(|ip| !is_excluded(ip)).collect();
                (Some(name.clone()), ips)
            }
            Selector::Cidr(net) => {
                let count = address_count(net);
                let reason = if count > HARD_MAX_CIDR_ADDRESSES {
                    Some(RefusalReason::CidrHuge {
                        max: HARD_MAX_CIDR_ADDRESSES,
                    })
                } else if count > MAX_CIDR_ADDRESSES && !scope.override_limits {
                    Some(RefusalReason::CidrTooLarge {
                        max: MAX_CIDR_ADDRESSES,
                    })
                } else {
                    None
                };
                if let Some(reason) = reason {
                    refused.push(Refusal {
                        target: net.to_string(),
                        reason,
                    });
                    continue;
                }
                let ips = addresses(net)
                    .into_iter()
                    .filter(|ip| !is_excluded(ip))
                    .collect();
                (None, ips)
            }
        };
        let wanted = match target.protocol {
            Protocol::Tls if scope.legacy_tls_check => TLS_CONNECTIONS_LEGACY,
            Protocol::Tls => TLS_CONNECTIONS,
            Protocol::Ssh => 1,
        };
        let connections = match target.protocol {
            Protocol::Tls => wanted.min(limits.tls_handshakes),
            Protocol::Ssh => wanted,
        };
        for ip in ips {
            if is_excluded(&ip) {
                continue;
            }
            for &port in &target.ports {
                if seen.insert((sni.clone(), ip, port, target.protocol as u8)) {
                    targets.push(PlannedTarget {
                        host: sni.clone(),
                        ip,
                        port,
                        protocol: target.protocol,
                        connections,
                    });
                }
            }
        }
    }
    Ok(TargetPlan {
        targets,
        refused,
        limits,
    })
}
