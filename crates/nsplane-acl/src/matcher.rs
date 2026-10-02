//! Compiled source/destination matchers and the rule text parsers.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::Error;
use crate::engine::SourceAssertion;
use crate::net::{IpNet, Protocol};

// ── Source matcher ────────────────────────────────────────────────────────────

/// Compiled source matcher (host aliases already resolved to CIDRs).
#[derive(Debug, Clone)]
pub(crate) enum SrcMatcher {
    Any,
    Cidr(IpNet),
    /// A client WireGuard public key principal. Matches a request
    /// whose source assertion is `WgPeerKey{pubkey}` with the same key.
    Key([u8; 32]),
}

impl SrcMatcher {
    pub(crate) fn matches(&self, source: &SourceAssertion) -> bool {
        match self {
            Self::Any => true,
            // CIDR rules match only IP-bearing sources (terminate bindings);
            // a key/IdP assertion carries no IP and never matches a CIDR.
            Self::Cidr(net) => source.ip().is_some_and(|ip| net.contains(&ip)),
            Self::Key(want) => {
                matches!(source, SourceAssertion::WgPeerKey { pubkey } if pubkey == want)
            }
        }
    }
}

// ── Destination matcher ───────────────────────────────────────────────────────

/// Compiled destination matcher.
#[derive(Debug, Clone)]
pub(crate) struct DstMatcher {
    pub(crate) host: HostMatcher,
    pub(crate) ports: PortMatcher,
}

#[derive(Debug, Clone)]
pub(crate) enum HostMatcher {
    Any,
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub(crate) enum PortMatcher {
    Any,
    Single(u16),
    Range(u16, u16),
    List(Vec<u16>),
}

impl DstMatcher {
    pub(crate) fn matches(&self, ip: IpAddr, port: u16) -> bool {
        let host_ok = match &self.host {
            HostMatcher::Any => true,
            HostMatcher::Cidr(net) => net.contains(&ip),
        };
        if !host_ok {
            return false;
        }
        match &self.ports {
            PortMatcher::Any => true,
            PortMatcher::Single(p) => port == *p,
            PortMatcher::Range(lo, hi) => port >= *lo && port <= *hi,
            PortMatcher::List(ports) => ports.contains(&port),
        }
    }
}

// ── Parser functions ──────────────────────────────────────────────────────────

/// Parse a source string into a `SrcMatcher` with aliases resolved from `hosts`.
///
/// Accepted forms:
/// - `*` — any source
/// - `key:<64-hex>` — a client WireGuard public key principal
/// - `10.0.0.0/24` — CIDR
/// - `alias` — host alias from the `hosts` map
pub(crate) fn parse_src(s: &str, hosts: &HashMap<String, IpNet>) -> Result<SrcMatcher, Error> {
    if s == "*" {
        return Ok(SrcMatcher::Any);
    }
    if let Some(hex) = s.strip_prefix("key:") {
        let key = parse_hex32(hex).ok_or_else(|| Error::UnknownAlias(s.to_owned()))?;
        return Ok(SrcMatcher::Key(key));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(SrcMatcher::Cidr(net));
    }
    if let Some(net) = hosts.get(s) {
        return Ok(SrcMatcher::Cidr(*net));
    }
    Err(Error::UnknownAlias(s.to_owned()))
}

/// Parse exactly 64 lowercase/uppercase hex chars into a 32-byte key.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse a destination string (`host:ports`) into a `DstMatcher`.
///
/// Accepted forms:
/// - `*:*` — any host, any port
/// - `192.168.0.0/24:80` — CIDR + single port
/// - `alias:5432` — host alias + single port
/// - `alias:80,443` — host alias + port list
/// - `alias:8000-8999` — host alias + port range
/// - `alias:*` — host alias + any port
pub(crate) fn parse_dst(s: &str, hosts: &HashMap<String, IpNet>) -> Result<DstMatcher, Error> {
    let colon = s.rfind(':').ok_or_else(|| Error::InvalidDst {
        dst: s.to_owned(),
        reason: "missing ':' between host and port".to_owned(),
    })?;

    let host_part = &s[..colon];
    let port_part = &s[colon + 1..];

    let host = parse_host(host_part, hosts)?;
    let ports = parse_ports(port_part).map_err(|reason| Error::InvalidDst {
        dst: s.to_owned(),
        reason,
    })?;

    Ok(DstMatcher { host, ports })
}

fn parse_host(s: &str, hosts: &HashMap<String, IpNet>) -> Result<HostMatcher, Error> {
    if s == "*" {
        return Ok(HostMatcher::Any);
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(HostMatcher::Cidr(net));
    }
    if let Some(net) = hosts.get(s) {
        return Ok(HostMatcher::Cidr(*net));
    }
    Err(Error::UnknownAlias(s.to_owned()))
}

fn parse_ports(s: &str) -> Result<PortMatcher, String> {
    if s == "*" {
        return Ok(PortMatcher::Any);
    }
    // Port list: "80,443,8080"
    if s.contains(',') {
        let ports = s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port '{p}'"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(PortMatcher::List(ports));
    }
    // Port range: "8000-8999"
    if let Some((lo_s, hi_s)) = s.split_once('-') {
        let lo = lo_s
            .parse::<u16>()
            .map_err(|_| format!("invalid range start '{lo_s}'"))?;
        let hi = hi_s
            .parse::<u16>()
            .map_err(|_| format!("invalid range end '{hi_s}'"))?;
        if lo > hi {
            return Err(format!("range start {lo} > end {hi}"));
        }
        return Ok(PortMatcher::Range(lo, hi));
    }
    // Single port.
    let p = s
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{s}'"))?;
    Ok(PortMatcher::Single(p))
}

/// Parse a protocol string (`"tcp"` / `"udp"`) into a `Protocol`.
pub(crate) fn parse_protocol(s: &str) -> Result<Protocol, Error> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        other => Err(Error::InvalidPolicy(format!(
            "unknown protocol '{other}': expected 'tcp' or 'udp'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn hosts() -> HashMap<String, IpNet> {
        let mut m = HashMap::new();
        m.insert("web".to_owned(), "192.168.1.0/24".parse().unwrap());
        m.insert("db".to_owned(), "192.168.1.10/32".parse().unwrap());
        m
    }

    // ── SrcMatcher ────────────────────────────────────────────────────────

    /// A terminate-binding source carrying `ip` (the legacy/IP path).
    fn ip_src(ip: IpAddr) -> SourceAssertion {
        SourceAssertion::Terminate {
            binding: crate::engine::TerminateBinding {
                ip: Some(ip),
                anchor: ip.to_string(),
            },
        }
    }

    #[test]
    fn src_wildcard_matches_any_ip() {
        let m = parse_src("*", &HashMap::new()).unwrap();
        assert!(m.matches(&ip_src("1.2.3.4".parse().unwrap())));
    }

    #[test]
    fn src_cidr_matches_contained_ip() {
        let m = parse_src("10.0.0.0/24", &HashMap::new()).unwrap();
        assert!(m.matches(&ip_src(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))));
        assert!(!m.matches(&ip_src(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5)))));
    }

    #[test]
    fn src_alias_resolves_to_cidr() {
        let m = parse_src("web", &hosts()).unwrap();
        assert!(m.matches(&ip_src(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)))));
        assert!(!m.matches(&ip_src(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 5)))));
    }

    #[test]
    fn src_unknown_alias_returns_error() {
        assert!(parse_src("unknown", &HashMap::new()).is_err());
    }

    #[test]
    fn src_key_parses_and_matches_wg_peer_key() {
        let m = parse_src(&format!("key:{}", "0a".repeat(32)), &HashMap::new()).unwrap();
        assert!(m.matches(&SourceAssertion::WgPeerKey { pubkey: [0x0a; 32] }));
        assert!(!m.matches(&SourceAssertion::WgPeerKey { pubkey: [0x0b; 32] }));
        assert!(!m.matches(&ip_src("10.0.0.5".parse().unwrap())));
        // Malformed key hex → parse error.
        assert!(parse_src("key:nothex", &HashMap::new()).is_err());
    }

    // ── DstMatcher ────────────────────────────────────────────────────────

    #[test]
    fn dst_wildcard_matches_anything() {
        let m = parse_dst("*:*", &HashMap::new()).unwrap();
        assert!(m.matches("1.2.3.4".parse().unwrap(), 9999));
    }

    #[test]
    fn dst_cidr_single_port() {
        let m = parse_dst("192.168.1.0/24:80", &HashMap::new()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 80));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 5)), 80));
    }

    #[test]
    fn dst_alias_port_list() {
        let m = parse_dst("web:80,443", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 80));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 8080));
    }

    #[test]
    fn dst_alias_port_range() {
        let m = parse_dst("web:8000-8999", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8000));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8500));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8999));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 7999));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9000));
    }

    #[test]
    fn dst_alias_wildcard_port() {
        let m = parse_dst("db:*", &hosts()).unwrap();
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 1));
        assert!(m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 65535));
        assert!(!m.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 11)), 80));
    }

    #[test]
    fn dst_missing_colon_returns_error() {
        assert!(parse_dst("192.168.1.1", &HashMap::new()).is_err());
    }

    #[test]
    fn dst_invalid_port_returns_error() {
        assert!(parse_dst("*:notaport", &HashMap::new()).is_err());
    }

    #[test]
    fn dst_range_inverted_returns_error() {
        assert!(parse_dst("*:9000-8000", &HashMap::new()).is_err());
    }

    // ── parse_protocol ────────────────────────────────────────────────────

    #[test]
    fn parse_protocol_tcp() {
        assert_eq!(parse_protocol("tcp").unwrap(), Protocol::Tcp);
    }

    #[test]
    fn parse_protocol_udp() {
        assert_eq!(parse_protocol("udp").unwrap(), Protocol::Udp);
    }

    #[test]
    fn parse_protocol_unknown_returns_error() {
        assert!(parse_protocol("icmp").is_err());
    }
}
