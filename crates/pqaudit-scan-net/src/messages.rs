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
];
