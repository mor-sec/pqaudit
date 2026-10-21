//! Address ranges in one canonical form.

use ipnet::IpNet;
use serde::Deserialize;

use crate::messages;

/// Make a canonical range. A mapped IPv6 range becomes an IPv4 range.
///
/// Addresses are canonical too, so both sides of a match use one family.
/// A range that is wider than the mapped range and that holds it is an error.
pub fn canonical_net(net: IpNet) -> Result<IpNet, String> {
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

/// Read a list of ranges and make each range canonical.
pub fn canonical_nets<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IpNet>, D::Error> {
    Vec::<IpNet>::deserialize(deserializer)?
        .into_iter()
        .map(|net| canonical_net(net).map_err(serde::de::Error::custom))
        .collect()
}
