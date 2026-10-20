//! User-facing text of this crate.

/// The error for a scope file that is not valid. The tool fills in {file}, {line}, and {reason}.
pub const SCOPE_PARSE: &str = "The file {file} is not valid at line {line}. {reason}";

/// The error for a scope file that the tool cannot read. The tool fills in {file} and {reason}.
pub const SCOPE_IO: &str = "The tool cannot read the file {file}. {reason}";

/// The error when the scope file does not exist. The tool fills in {file}.
pub const SCOPE_MISSING: &str =
    "The file {file} does not exist. Run the command init, or add the file.";

/// The error for a limit above its default. The tool fills in {name}, {requested}, and {default}.
pub const LIMIT_ABOVE_DEFAULT: &str = "The limit {name} is {requested}. The default is {default}. To set a higher value, set override_limits to true.";

/// The error for a limit below its default minimum. The tool fills in {name}, {requested}, and {default}.
pub const LIMIT_BELOW_DEFAULT: &str = "The limit {name} is {requested}. The default is {default}, and this value must not be lower. To set a lower value, set override_limits to true.";

/// The error for a limit that is zero. The tool fills in {name}.
pub const LIMIT_ZERO: &str = "The limit {name} must be 1 or more.";

/// The reason when a target has neither a host nor a CIDR, or both.
pub const TARGET_KIND: &str = "A target needs one host or one cidr key, not both.";

/// The reason when an exclude has neither a host nor a CIDR, or both.
pub const EXCLUDE_KIND: &str = "An exclude needs one host or one cidr key, not both.";

/// The reason when a target has no ports.
pub const PORTS_EMPTY: &str = "A target needs at least one port.";

/// The reason when a port is zero.
pub const PORT_ZERO: &str = "A port must be from 1 to 65535.";

/// The reason when a host name has characters that are not valid.
pub const HOST_INVALID: &str =
    "A host must be a host name or an IP address. It must not have a port, a path, or spaces.";

/// The reason when allowed_hours is not valid.
pub const HOURS_INVALID: &str =
    "The value of allowed_hours must have the form HH:MM-HH:MM. The two times must differ.";

/// The reason when an IPv6 range is wider than the IPv4-mapped range and holds it.
pub const MAPPED_RANGE_WIDE: &str =
    "This IPv6 range holds the IPv4-mapped range ::ffff:0:0/96. Use a smaller range or an IPv4 range.";

/// The reason when a host name does not resolve. The tool fills in {reason}.
pub const REFUSE_RESOLVE: &str = "The host name does not resolve. {reason}";

/// The reason when a host name has no addresses.
pub const REFUSE_NO_ADDRESSES: &str = "The host name has no addresses.";

/// The reason when addresses are outside the allowed ranges. The tool fills in {ips}.
pub const REFUSE_OUTSIDE: &str =
    "These addresses are not in an allowed CIDR range: {ips}. The tool refuses the full scan.";

/// The reason when a CIDR has too many addresses. The tool fills in {max}.
pub const REFUSE_CIDR_LARGE: &str =
    "The CIDR range has more than {max} addresses. To scan it, set override_limits to true.";

/// The reason when a CIDR is too large even with override_limits. The tool fills in {max}.
pub const REFUSE_CIDR_HUGE: &str =
    "The CIDR range has more than {max} addresses. The tool never scans a range this large.";

/// The error when the current time is outside `allowed_hours`.
pub const OUTSIDE_HOURS: &str =
    "The current time is outside the window allowed_hours. The tool makes no connection.";

/// The error when the tool cannot connect. The tool fills in {reason}.
pub const CONNECT_FAILED: &str = "The tool could not connect. {reason}";

/// The error when the connect does not finish in the connect timeout.
pub const CONNECT_TIMEOUT: &str = "The connection did not finish in the connect timeout.";

/// The error when the audit log does not work.
pub const AUDIT_BROKEN: &str =
    "The tool cannot write the audit log. The tool makes no more connections.";

/// The error when the handshake does not finish in the read timeout. The tool fills in {probe}.
pub const HANDSHAKE_TIMEOUT: &str = "The {probe} handshake did not finish in the read timeout.";

/// The error when a handshake fails. The tool fills in {probe} and {reason}.
pub const HANDSHAKE_FAILED: &str = "The {probe} handshake failed. {reason}";

/// The note that the server did not accept the hybrid groups. The tool fills in {reason}.
pub const HYBRID_REJECTED: &str = "The server did not accept the hybrid key exchange. {reason}";

/// The error for a certificate in the chain that the tool cannot read.
/// The tool fills in {position} and {reason}.
pub const CHAIN_CERT_BAD: &str = "Certificate {position} in the chain is not readable. {reason}";

/// The note that the chain has more certificates than the tool reads. The tool fills in {max}.
pub const CHAIN_TOO_LONG: &str =
    "The chain has more than {max} certificates. The tool read the first {max}.";

/// The error when the check for old protocol versions fails. The tool fills in {reason}.
pub const LEGACY_FAILED: &str = "The check for old protocol versions failed. {reason}";

/// The error when the server sends a reply that is not a TLS handshake record.
pub const LEGACY_BAD_REPLY: &str = "The server sent a reply that is not a TLS handshake.";

/// The error when the server sends too many lines, or a long line, before the SSH banner.
pub const SSH_BANNER_TOO_LONG: &str =
    "The SSH banner is too long. The server sent too many lines, or a line that is too long.";

/// The error when an SSH packet is too large. The tool fills in {max}.
pub const SSH_PACKET_TOO_LARGE: &str =
    "The server sent an SSH packet that is too large. The limit is {max} bytes.";

/// The error when an SSH packet is not valid.
pub const SSH_PACKET_INVALID: &str = "The server sent an SSH packet that the tool cannot read.";

/// The error when the first SSH packet is not a KEXINIT message.
pub const SSH_NOT_KEXINIT: &str = "The first SSH packet of the server is not a KEXINIT message.";

/// The error when the server closes the connection too early.
pub const SSH_CLOSED: &str = "The server closed the connection before the SSH exchange ended.";

/// The error when a read or write fails in the SSH exchange. The tool fills in {reason}.
pub const SSH_IO: &str = "The SSH exchange failed. {reason}";

/// The error when the SSH exchange does not finish in the read timeout.
pub const SSH_TIMEOUT: &str = "The SSH exchange did not finish in the read timeout.";

/// The evidence for an SSH server without a post-quantum key exchange.
pub const EVIDENCE_SSH_NO_PQ: &str =
    "The server offers no post-quantum key exchange. It offers {count} key exchange algorithms.";

/// The evidence for an SSH server with weak key exchange algorithms. The tool fills in {names}.
pub const EVIDENCE_SSH_WEAK_KEX: &str =
    "The server offers these weak key exchange algorithms: {names}.";

/// The evidence for an SSH server with classical host keys. The tool fills in {names}.
pub const EVIDENCE_SSH_HOSTKEY: &str =
    "All host key algorithms of the server are classical: {names}.";

/// The evidence for an SSH server with a post-quantum key exchange. The tool fills in {names}.
pub const EVIDENCE_SSH_PQ_READY: &str =
    "The server offers these post-quantum key exchange algorithms: {names}.";

/// The error when other names used the handshake limit of this address and port.
pub const HANDSHAKE_LIMIT_USED: &str =
    "Other names used all handshakes for this address and port. The tool makes no connection.";

/// The note when other names used part of the handshake limit of this address and port.
pub const HANDSHAKE_LIMIT_PART: &str =
    "Other names used part of the handshake limit for this address and port. The probe of this name is not complete.";

/// The error for a target that the tool did not finish because the user stopped the scan.
pub const TARGET_STOPPED: &str =
    "The user stopped the scan before the tool finished this target. The results for it are not complete.";

/// The error when the system cannot give random bytes.
pub const RANDOM_FAILED: &str = "The system cannot give random bytes.";

/// The error when no handshake finished and the tool has no other reason.
pub const NO_HANDSHAKE: &str = "No TLS handshake finished.";

/// The evidence for an endpoint that accepts a hybrid group.
pub const EVIDENCE_PQ_READY: &str = "The server accepted a hybrid post-quantum key exchange.";

/// The evidence for an endpoint that does not accept a hybrid group.
/// The tool fills in {group}.
pub const EVIDENCE_NO_PQ: &str =
    "The server did not accept a hybrid post-quantum key exchange. It selected the group {group}.";

/// The evidence for an endpoint that accepts old protocol versions. The tool fills in {versions}.
pub const EVIDENCE_LEGACY: &str = "The server accepted these old protocol versions: {versions}.";

/// The evidence for a certificate in the chain of an endpoint.
/// The tool fills in {position} and {subject}.
pub const EVIDENCE_CHAIN_CERT: &str = "Certificate {position} in the chain. Subject: {subject}.";

/// The text for an unknown group or version.
pub const UNKNOWN_VALUE: &str = "unknown";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("SCOPE_PARSE", SCOPE_PARSE),
    ("SCOPE_IO", SCOPE_IO),
    ("SCOPE_MISSING", SCOPE_MISSING),
    ("LIMIT_ABOVE_DEFAULT", LIMIT_ABOVE_DEFAULT),
    ("LIMIT_BELOW_DEFAULT", LIMIT_BELOW_DEFAULT),
    ("LIMIT_ZERO", LIMIT_ZERO),
    ("TARGET_KIND", TARGET_KIND),
    ("EXCLUDE_KIND", EXCLUDE_KIND),
    ("PORTS_EMPTY", PORTS_EMPTY),
    ("PORT_ZERO", PORT_ZERO),
    ("HOST_INVALID", HOST_INVALID),
    ("HOURS_INVALID", HOURS_INVALID),
    ("MAPPED_RANGE_WIDE", MAPPED_RANGE_WIDE),
    ("REFUSE_RESOLVE", REFUSE_RESOLVE),
    ("REFUSE_NO_ADDRESSES", REFUSE_NO_ADDRESSES),
    ("REFUSE_OUTSIDE", REFUSE_OUTSIDE),
    ("REFUSE_CIDR_LARGE", REFUSE_CIDR_LARGE),
    ("REFUSE_CIDR_HUGE", REFUSE_CIDR_HUGE),
    ("OUTSIDE_HOURS", OUTSIDE_HOURS),
    ("CONNECT_FAILED", CONNECT_FAILED),
    ("CONNECT_TIMEOUT", CONNECT_TIMEOUT),
    ("AUDIT_BROKEN", AUDIT_BROKEN),
    ("HANDSHAKE_TIMEOUT", HANDSHAKE_TIMEOUT),
    ("HANDSHAKE_FAILED", HANDSHAKE_FAILED),
    ("HYBRID_REJECTED", HYBRID_REJECTED),
    ("CHAIN_CERT_BAD", CHAIN_CERT_BAD),
    ("CHAIN_TOO_LONG", CHAIN_TOO_LONG),
    ("LEGACY_FAILED", LEGACY_FAILED),
    ("LEGACY_BAD_REPLY", LEGACY_BAD_REPLY),
    ("SSH_BANNER_TOO_LONG", SSH_BANNER_TOO_LONG),
    ("SSH_PACKET_TOO_LARGE", SSH_PACKET_TOO_LARGE),
    ("SSH_PACKET_INVALID", SSH_PACKET_INVALID),
    ("SSH_NOT_KEXINIT", SSH_NOT_KEXINIT),
    ("SSH_CLOSED", SSH_CLOSED),
    ("SSH_IO", SSH_IO),
    ("SSH_TIMEOUT", SSH_TIMEOUT),
    ("HANDSHAKE_LIMIT_USED", HANDSHAKE_LIMIT_USED),
    ("HANDSHAKE_LIMIT_PART", HANDSHAKE_LIMIT_PART),
    ("TARGET_STOPPED", TARGET_STOPPED),
    ("RANDOM_FAILED", RANDOM_FAILED),
    ("NO_HANDSHAKE", NO_HANDSHAKE),
    ("EVIDENCE_PQ_READY", EVIDENCE_PQ_READY),
    ("EVIDENCE_NO_PQ", EVIDENCE_NO_PQ),
    ("EVIDENCE_LEGACY", EVIDENCE_LEGACY),
    ("EVIDENCE_CHAIN_CERT", EVIDENCE_CHAIN_CERT),
    ("EVIDENCE_SSH_NO_PQ", EVIDENCE_SSH_NO_PQ),
    ("EVIDENCE_SSH_WEAK_KEX", EVIDENCE_SSH_WEAK_KEX),
    ("EVIDENCE_SSH_HOSTKEY", EVIDENCE_SSH_HOSTKEY),
    ("EVIDENCE_SSH_PQ_READY", EVIDENCE_SSH_PQ_READY),
    ("UNKNOWN_VALUE", UNKNOWN_VALUE),
];
