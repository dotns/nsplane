//! The text parsers of the policy document and its compilation into typed
//! [`Rule`]s.
//!
//! A `key:<hex>` source becomes the label `key:<lowercase hex>`; a CIDR or
//! host alias source becomes `sources`, which match the flow's source
//! address whatever its labels. Each document rule becomes one typed rule per
//! kind of source and per port set of its destinations, all with the
//! document rule's index as their id.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;

use tracing::warn;

use crate::Error;
use crate::engine::AclTestFailure;
use crate::net::{IpNet, Protocol};
use crate::policy::{AclPolicy, AclRule, AclTest};
use crate::rules::{Flow, Label, LabelSet, PortSet, ProtocolMatch, Rule, RuleId, RuleSet};

/// A parsed document source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DocSource {
    Any,
    /// A 32-byte key, as its `key:<lowercase hex>` label.
    Key(Label),
    Cidr(IpNet),
}

// ── Parser functions ──────────────────────────────────────────────────────────

/// Parse a source string with aliases resolved from `hosts`.
///
/// Accepted forms:
/// - `*` — any source
/// - `key:<64-hex>` — a 32-byte key, matched as a label
/// - `10.0.0.0/24` — CIDR
/// - `alias` — host alias from the `hosts` map
pub(crate) fn parse_src(s: &str, hosts: &HashMap<String, IpNet>) -> Result<DocSource, Error> {
    if s == "*" {
        return Ok(DocSource::Any);
    }
    if let Some(hex) = s.strip_prefix("key:") {
        let key = parse_hex32(hex).ok_or_else(|| Error::UnknownAlias(s.to_owned()))?;
        let mut label = String::with_capacity(4 + 64);
        label.push_str("key:");
        for b in key {
            use std::fmt::Write as _;
            let _ = write!(label, "{b:02x}");
        }
        return Ok(DocSource::Key(Label::from(label)));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(DocSource::Cidr(net));
    }
    if let Some(net) = hosts.get(s) {
        return Ok(DocSource::Cidr(*net));
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

/// Parse a destination string (`host:ports`): the host prefix (`None` for
/// any host) and the ports.
///
/// Accepted forms:
/// - `*:*` — any host, any port
/// - `192.168.0.0/24:80` — CIDR + single port
/// - `alias:5432` — host alias + single port
/// - `alias:80,443` — host alias + port list
/// - `alias:8000-8999` — host alias + port range
/// - `alias:*` — host alias + any port
pub(crate) fn parse_dst(
    s: &str,
    hosts: &HashMap<String, IpNet>,
) -> Result<(Option<IpNet>, PortSet), Error> {
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

    Ok((host, ports))
}

fn parse_host(s: &str, hosts: &HashMap<String, IpNet>) -> Result<Option<IpNet>, Error> {
    if s == "*" {
        return Ok(None);
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(Some(net));
    }
    if let Some(net) = hosts.get(s) {
        return Ok(Some(*net));
    }
    Err(Error::UnknownAlias(s.to_owned()))
}

/// Parse a port matcher: `*`, `22`, `80,443` or `8000-8999`.
pub(crate) fn parse_ports(s: &str) -> Result<PortSet, String> {
    if s == "*" {
        return Ok(PortSet::Any);
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
        return Ok(PortSet::list(ports));
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
        return Ok(PortSet::Ranges(vec![RangeInclusive::new(lo, hi)]));
    }
    // Single port.
    let p = s
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{s}'"))?;
    Ok(PortSet::single(p))
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

/// The typed protocols of a document protocol (`None`: TCP and UDP) and
/// port set.
pub(crate) fn protocols(proto: Option<Protocol>, ports: PortSet) -> Vec<ProtocolMatch> {
    match proto {
        Some(Protocol::Tcp) => vec![ProtocolMatch::Tcp(ports)],
        Some(Protocol::Udp) => vec![ProtocolMatch::Udp(ports)],
        None => vec![ProtocolMatch::Tcp(ports.clone()), ProtocolMatch::Udp(ports)],
    }
}

// ── Document compilation ──────────────────────────────────────────────────────

fn resolve_hosts(raw: &HashMap<String, String>) -> Result<HashMap<String, IpNet>, Error> {
    raw.iter()
        .map(|(alias, cidr)| {
            let net = cidr.parse::<IpNet>().map_err(|e| Error::InvalidCidr {
                addr: cidr.clone(),
                reason: e.to_string(),
            })?;
            Ok((alias.clone(), net))
        })
        .collect()
}

/// The typed rules of `policy`'s accept rules, in order.
pub(crate) fn compile_rules(policy: &AclPolicy) -> Result<Vec<Rule>, Error> {
    let hosts = resolve_hosts(&policy.hosts)?;
    let mut rules = Vec::new();
    for (i, rule) in policy.acls.iter().enumerate() {
        compile_rule(i, rule, &hosts, &mut rules)?;
    }
    Ok(rules)
}

fn compile_rule(
    i: usize,
    rule: &AclRule,
    hosts: &HashMap<String, IpNet>,
    out: &mut Vec<Rule>,
) -> Result<(), Error> {
    let sources = rule
        .src
        .iter()
        .map(|s| parse_src(s, hosts))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::InvalidPolicy(format!("rule {i} src: {e}")))?;
    let destinations = rule
        .dst
        .iter()
        .map(|s| parse_dst(s, hosts))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Error::InvalidPolicy(format!("rule {i} dst: {e}")))?;
    let proto = rule
        .proto
        .as_deref()
        .map(parse_protocol)
        .transpose()
        .map_err(|e| Error::InvalidPolicy(format!("rule {i} proto: {e}")))?;

    // One group per kind of source: any source matches any of them.
    let mut source_groups: Vec<(Vec<Label>, Vec<IpNet>)> = Vec::new();
    if sources.contains(&DocSource::Any) {
        source_groups.push((Vec::new(), Vec::new()));
    } else {
        let mut keys = Vec::new();
        let mut cidrs = Vec::new();
        for source in sources {
            match source {
                DocSource::Key(label) => keys.push(label),
                DocSource::Cidr(net) => cidrs.push(net),
                DocSource::Any => {}
            }
        }
        if !keys.is_empty() {
            source_groups.push((keys, Vec::new()));
        }
        if !cidrs.is_empty() {
            source_groups.push((Vec::new(), cidrs));
        }
    }
    // One group per port set: `None` destinations mean any host.
    let mut destination_groups: Vec<(PortSet, Option<Vec<IpNet>>)> = Vec::new();
    for (host, ports) in destinations {
        let index = destination_groups
            .iter()
            .position(|(p, _)| *p == ports)
            .unwrap_or_else(|| {
                destination_groups.push((ports, Some(Vec::new())));
                destination_groups.len() - 1
            });
        let hosts = &mut destination_groups[index].1;
        match host {
            None => *hosts = None,
            Some(net) => {
                if let Some(nets) = hosts {
                    nets.push(net);
                }
            }
        }
    }

    let id = RuleId::from(i.to_string());
    for (labels, sources) in &source_groups {
        for (ports, hosts) in &destination_groups {
            out.push(Rule {
                id: id.clone(),
                labels: labels.clone(),
                sources: sources.clone(),
                destinations: hosts.clone().unwrap_or_default(),
                protocols: protocols(proto, ports.clone()),
            });
        }
    }
    Ok(())
}

impl RuleSet {
    /// Compile a policy document ([`AclPolicy`]) into typed rules and run its
    /// built-in tests (temporary, until the document is removed).
    ///
    /// Each rule of the document gets its index as [`RuleId`]. Returns
    /// [`Error::TestsFailed`] when a test fails.
    pub fn from_document(policy: AclPolicy) -> Result<Self, Error> {
        let rules = Self::new(compile_rules(&policy)?)?;
        let failures = test_failures(&rules, policy.tests);
        if !failures.is_empty() {
            for f in &failures {
                warn!(
                    src = %f.test.src,
                    dst = %f.test.dst,
                    expected = f.test.allow,
                    reason = %f.reason,
                    "ACL policy test failed"
                );
            }
            return Err(Error::TestsFailed {
                count: failures.len(),
            });
        }
        Ok(rules)
    }
}

/// Run the document tests against `rules`, as requests from a source
/// without labels at the test's source address.
fn test_failures(rules: &RuleSet, tests: Vec<AclTest>) -> Vec<AclTestFailure> {
    tests
        .into_iter()
        .filter_map(|test| {
            let reason = test_failure(rules, &test)?;
            Some(AclTestFailure { test, reason })
        })
        .collect()
}

/// Why `test` fails against `rules`, `None` when it passes.
fn test_failure(rules: &RuleSet, test: &AclTest) -> Option<String> {
    let Ok(src_ip) = test.src.parse::<IpAddr>() else {
        return Some(format!("cannot parse src IP '{}'", test.src));
    };
    let dst = match parse_test_dst(&test.dst) {
        Ok(dst) => dst,
        Err(reason) => return Some(reason),
    };
    let protocol = match test.proto.as_deref() {
        Some(raw) => match parse_protocol(raw) {
            Ok(proto) => proto,
            Err(reason) => return Some(format!("cannot parse test proto '{raw}': {reason}")),
        },
        None => Protocol::Tcp,
    };

    let src = SocketAddr::new(src_ip, 0);
    let flow = match protocol {
        Protocol::Tcp => Flow::tcp(src, dst),
        Protocol::Udp => Flow::udp(src, dst),
    };
    let allowed = rules.matching(&LabelSet::empty(), &flow).is_some();
    (allowed != test.allow).then(|| {
        format!(
            "expected {}, got {}",
            if test.allow { "allow" } else { "deny" },
            if allowed { "allow" } else { "deny" },
        )
    })
}

/// Parse a test destination string like `"192.168.1.10:5432"`.
fn parse_test_dst(s: &str) -> Result<SocketAddr, String> {
    let colon = s
        .rfind(':')
        .ok_or_else(|| format!("missing ':' in test dst '{s}'"))?;
    let ip_str = &s[..colon];
    let port_str = &s[colon + 1..];
    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid IP '{ip_str}' in test dst '{s}'"))?;
    let port = port_str
        .parse::<u16>()
        .map_err(|_| format!("invalid port '{port_str}' in test dst '{s}'"))?;
    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AclAction;
    use std::collections::HashMap;

    fn hosts() -> HashMap<String, IpNet> {
        let mut m = HashMap::new();
        m.insert("web".to_owned(), "192.168.1.0/24".parse().unwrap());
        m.insert("db".to_owned(), "192.168.1.10/32".parse().unwrap());
        m
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    // ── Sources ───────────────────────────────────────────────────────────

    #[test]
    fn src_forms() {
        assert_eq!(parse_src("*", &HashMap::new()).unwrap(), DocSource::Any);
        assert_eq!(
            parse_src("10.0.0.0/24", &HashMap::new()).unwrap(),
            DocSource::Cidr(net("10.0.0.0/24"))
        );
        assert_eq!(
            parse_src("web", &hosts()).unwrap(),
            DocSource::Cidr(net("192.168.1.0/24"))
        );
        assert!(parse_src("unknown", &HashMap::new()).is_err());
    }

    #[test]
    fn src_key_becomes_its_lowercase_label() {
        let upper = format!("key:{}", "0A".repeat(32));
        assert_eq!(
            parse_src(&upper, &HashMap::new()).unwrap(),
            DocSource::Key(Label::from(format!("key:{}", "0a".repeat(32))))
        );
        // Malformed key hex → parse error.
        assert!(parse_src("key:nothex", &HashMap::new()).is_err());
    }

    // ── Destinations ──────────────────────────────────────────────────────

    #[test]
    fn dst_forms() {
        assert_eq!(
            parse_dst("*:*", &HashMap::new()).unwrap(),
            (None, PortSet::Any)
        );
        assert_eq!(
            parse_dst("192.168.1.0/24:80", &HashMap::new()).unwrap(),
            (Some(net("192.168.1.0/24")), PortSet::single(80))
        );
        assert_eq!(
            parse_dst("web:80,443", &hosts()).unwrap(),
            (Some(net("192.168.1.0/24")), PortSet::list([80, 443]))
        );
        assert_eq!(
            parse_dst("web:8000-8999", &hosts()).unwrap(),
            (
                Some(net("192.168.1.0/24")),
                PortSet::Ranges(vec![RangeInclusive::new(8000, 8999)])
            )
        );
        assert_eq!(
            parse_dst("db:*", &hosts()).unwrap(),
            (Some(net("192.168.1.10/32")), PortSet::Any)
        );
    }

    #[test]
    fn dst_errors() {
        assert!(parse_dst("192.168.1.1", &HashMap::new()).is_err());
        assert!(parse_dst("*:notaport", &HashMap::new()).is_err());
        assert!(parse_dst("*:9000-8000", &HashMap::new()).is_err());
        assert!(parse_dst("nohost:80", &HashMap::new()).is_err());
    }

    // ── parse_protocol ────────────────────────────────────────────────────

    #[test]
    fn parse_protocol_values() {
        assert_eq!(parse_protocol("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(parse_protocol("UDP").unwrap(), Protocol::Udp);
        assert!(parse_protocol("icmp").is_err());
    }

    // ── Compilation ───────────────────────────────────────────────────────

    fn doc(src: &[&str], dst: &[&str], proto: Option<&str>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::from([("web".to_owned(), "192.168.1.0/24".to_owned())]),
            acls: vec![AclRule {
                action: AclAction::Accept,
                src: src.iter().map(ToString::to_string).collect(),
                dst: dst.iter().map(ToString::to_string).collect(),
                proto: proto.map(str::to_owned),
            }],
            tests: Vec::new(),
        }
    }

    #[test]
    fn a_rule_splits_by_source_kind_and_port_set() {
        let key = format!("key:{}", "01".repeat(32));
        let rules = compile_rules(&doc(
            &[&key, "10.0.0.0/8", "web"],
            &["10.1.0.0/16:80", "*:443", "10.2.0.0/16:80"],
            Some("tcp"),
        ))
        .unwrap();
        let expected = [
            (
                vec![Label::from(key.as_str())],
                vec![],
                vec![net("10.1.0.0/16"), net("10.2.0.0/16")],
                80,
            ),
            (vec![Label::from(key.as_str())], vec![], vec![], 443),
            (
                vec![],
                vec![net("10.0.0.0/8"), net("192.168.1.0/24")],
                vec![net("10.1.0.0/16"), net("10.2.0.0/16")],
                80,
            ),
            (
                vec![],
                vec![net("10.0.0.0/8"), net("192.168.1.0/24")],
                vec![],
                443,
            ),
        ];
        assert_eq!(rules.len(), expected.len());
        for (rule, (labels, sources, destinations, port)) in rules.iter().zip(expected) {
            assert_eq!(rule.id.as_str(), "0");
            assert_eq!(rule.labels, labels);
            assert_eq!(rule.sources, sources);
            assert_eq!(rule.destinations, destinations);
            assert_eq!(
                rule.protocols,
                vec![ProtocolMatch::Tcp(PortSet::single(port))]
            );
        }
    }

    #[test]
    fn wildcards_and_both_protocols() {
        let rules = compile_rules(&doc(&["10.0.0.1/32", "*"], &["*:*", "web:*"], None)).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].labels, Vec::new());
        assert_eq!(rules[0].sources, Vec::new());
        assert_eq!(rules[0].destinations, Vec::new());
        assert_eq!(
            rules[0].protocols,
            vec![
                ProtocolMatch::Tcp(PortSet::Any),
                ProtocolMatch::Udp(PortSet::Any)
            ]
        );
        // A rule with no source or no destination matches nothing.
        assert_eq!(
            compile_rules(&doc(&[], &["*:*"], None)).unwrap(),
            Vec::new()
        );
        assert_eq!(compile_rules(&doc(&["*"], &[], None)).unwrap(), Vec::new());
    }

    #[test]
    fn compile_errors() {
        assert!(matches!(
            compile_rules(&doc(&["nope"], &["*:*"], None)),
            Err(Error::InvalidPolicy(_))
        ));
        assert!(matches!(
            compile_rules(&doc(&["*"], &["*:*"], Some("icmp"))),
            Err(Error::InvalidPolicy(_))
        ));
        let mut bad_hosts = doc(&["*"], &["*:*"], None);
        bad_hosts
            .hosts
            .insert("x".to_owned(), "not-a-cidr".to_owned());
        assert!(matches!(
            compile_rules(&bad_hosts),
            Err(Error::InvalidCidr { .. })
        ));
    }
}
