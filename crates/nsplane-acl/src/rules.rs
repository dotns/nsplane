//! Typed rules: opaque labels and rule IDs, accept rules and flows.
//!
//! [`Rule`]s match flows by label, address prefix and protocol and are
//! validated into a [`RuleSet`]; [`Flow`] and [`Decision`] are the input and
//! output of [`AclEngine::evaluate`](crate::AclEngine::evaluate).

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;
use crate::namespace::{NamespaceId, ip_nets};
use crate::net::{IpNet, Protocol};
use crate::pinhole::PinholeId;

// ── Labels and rule IDs ───────────────────────────────────────────────────────

/// An opaque source label. nsplane compares labels for equality only.
///
/// The label keeps its text and a precomputed 64-bit hash, so comparing two
/// labels compares the hashes first and the texts only when the hashes are
/// equal. Labels are ordered by their text.
#[derive(Clone)]
pub struct Label {
    text: Arc<str>,
    hash: u64,
}

impl Label {
    /// A label with the given text.
    pub fn new(text: impl Into<Arc<str>>) -> Self {
        let text = text.into();
        let hash = fnv1a(text.as_bytes());
        Self { text, hash }
    }

    /// The label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The order of label sets and compiled rules: by hash, then by text.
    fn set_order(&self, other: &Self) -> Ordering {
        self.hash
            .cmp(&other.hash)
            .then_with(|| self.text.cmp(&other.text))
    }
}

/// 64-bit FNV-1a: deterministic and cheap for short texts.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.text == other.text
    }
}

impl Eq for Label {}

impl PartialOrd for Label {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> Ordering {
        self.text.cmp(&other.text)
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Label").field(&&*self.text).finish()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<&str> for Label {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for Label {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl Serialize for Label {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

/// A set of labels, sorted and without duplicates. Clone is one `Arc`
/// increment.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct LabelSet(Arc<[Label]>);

impl LabelSet {
    /// The set of `labels`, without duplicates.
    pub fn new(labels: impl IntoIterator<Item = Label>) -> Self {
        let mut labels: Vec<Label> = labels.into_iter().collect();
        labels.sort_by(Label::set_order);
        labels.dedup();
        Self(labels.into())
    }

    /// The empty set: a source that matches only rules without labels.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether `label` is in the set.
    #[must_use]
    pub fn contains(&self, label: &Label) -> bool {
        self.0
            .binary_search_by(|probe| probe.set_order(label))
            .is_ok()
    }

    /// Whether at least one of `labels` is in the set.
    #[must_use]
    pub fn intersects(&self, labels: &[Label]) -> bool {
        labels.iter().any(|label| self.contains(label))
    }

    /// The labels, in an unspecified but stable order.
    pub fn iter(&self) -> impl Iterator<Item = &Label> {
        self.0.iter()
    }

    /// The number of labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the set shares a label with `sorted`, which is sorted in the
    /// set order: one merge over both slices.
    pub(crate) fn intersects_sorted(&self, sorted: &[Label]) -> bool {
        let (mut mine, mut theirs) = (self.0.iter(), sorted.iter());
        let (mut a, mut b) = (mine.next(), theirs.next());
        while let (Some(x), Some(y)) = (a, b) {
            match x.set_order(y) {
                Ordering::Less => a = mine.next(),
                Ordering::Greater => b = theirs.next(),
                Ordering::Equal => return true,
            }
        }
        false
    }

    /// Whether a label with the text `text` is in the set.
    pub(crate) fn contains_text(&self, text: &str) -> bool {
        self.0.iter().any(|label| label.as_str() == text)
    }
}

impl fmt::Debug for LabelSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.iter()).finish()
    }
}

impl FromIterator<Label> for LabelSet {
    fn from_iter<I: IntoIterator<Item = Label>>(labels: I) -> Self {
        Self::new(labels)
    }
}

impl Serialize for LabelSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de> Deserialize<'de> for LabelSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<Label>::deserialize(deserializer).map(Self::new)
    }
}

/// An opaque rule identifier, carried into decisions and logs. Need not be
/// unique.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(Arc<str>);

impl RuleId {
    /// A rule identifier with the given text.
    pub fn new(text: impl Into<Arc<str>>) -> Self {
        Self(text.into())
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The shared text, for the filter's reply dependencies.
    pub(crate) fn shared(&self) -> Arc<str> {
        Arc::clone(&self.0)
    }
}

impl fmt::Debug for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RuleId").field(&&*self.0).finish()
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RuleId {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for RuleId {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl Borrow<str> for RuleId {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Serialize for RuleId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RuleId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from)
    }
}

// ── Typed rules ───────────────────────────────────────────────────────────────

/// An accept rule.
///
/// The rule matches a flow from a source with label set `S` when all of
/// these hold: `labels` is empty or `S` contains one of them; `sources` is
/// empty or the flow's source address lies in one of them; `destinations` is
/// empty or the flow's destination address lies in one of them; and an entry
/// of `protocols` matches the flow's transport. A prefix never contains an
/// address of the other family.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// The identifier reported when the rule accepts a flow.
    pub id: RuleId,
    /// Source labels; empty: any source.
    #[serde(default)]
    pub labels: Vec<Label>,
    /// Source address prefixes; empty: any source address.
    #[serde(default, with = "ip_nets")]
    pub sources: Vec<IpNet>,
    /// Destination address prefixes; empty: any destination address.
    #[serde(default, with = "ip_nets")]
    pub destinations: Vec<IpNet>,
    /// Protocols (with ports or ICMP types); must not be empty.
    pub protocols: Vec<ProtocolMatch>,
}

impl Rule {
    /// A rule `id` accepting `protocols` from any source to any destination.
    pub fn new(id: impl Into<RuleId>, protocols: Vec<ProtocolMatch>) -> Self {
        Self {
            id: id.into(),
            labels: Vec::new(),
            sources: Vec::new(),
            destinations: Vec::new(),
            protocols,
        }
    }

    /// Sets [`labels`](Self::labels).
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = Label>) -> Self {
        self.labels = labels.into_iter().collect();
        self
    }

    /// Sets [`sources`](Self::sources).
    #[must_use]
    pub fn with_sources(mut self, sources: impl IntoIterator<Item = IpNet>) -> Self {
        self.sources = sources.into_iter().collect();
        self
    }

    /// Sets [`destinations`](Self::destinations).
    #[must_use]
    pub fn with_destinations(mut self, destinations: impl IntoIterator<Item = IpNet>) -> Self {
        self.destinations = destinations.into_iter().collect();
        self
    }
}

/// The protocols a rule accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolMatch {
    /// Every protocol, every port and ICMP type.
    Any,
    /// TCP to these destination ports.
    Tcp(PortSet),
    /// UDP to these destination ports.
    Udp(PortSet),
    /// ICMP (IPv4) or `ICMPv6` (IPv6), by message type.
    Icmp(IcmpTypes),
    /// Another IP protocol number (not 1, 6, 17 or 58: use the variants
    /// above).
    Ip(u8),
}

/// Destination ports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortSet {
    /// Every port.
    Any,
    /// The ports in one of these inclusive ranges; must not be empty.
    Ranges(Vec<RangeInclusive<u16>>),
}

impl PortSet {
    /// One port.
    #[must_use]
    pub fn single(port: u16) -> Self {
        Self::Ranges(vec![RangeInclusive::new(port, port)])
    }

    /// A list of single ports.
    pub fn list(ports: impl IntoIterator<Item = u16>) -> Self {
        Self::Ranges(ports.into_iter().map(|port| port..=port).collect())
    }

    /// Whether `port` is in the set.
    #[must_use]
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Ranges(ranges) => ranges.iter().any(|range| range.contains(&port)),
        }
    }
}

/// ICMP message types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpTypes {
    /// Every type.
    Any,
    /// These types; must not be empty.
    Only(Vec<u8>),
}

/// The protocols of one rule, grant or outbound rule in a flat form: a
/// match is a few branches.
#[derive(Debug, Clone, Default)]
pub(crate) struct Protocols {
    any: bool,
    tcp: Option<PortSet>,
    udp: Option<PortSet>,
    icmp: Option<IcmpTypes>,
    ip: Vec<u8>,
}

impl Protocols {
    /// Validate and flatten `protocols`; `Err` holds the reason.
    pub(crate) fn compile(protocols: &[ProtocolMatch]) -> Result<Self, String> {
        if protocols.is_empty() {
            return Err("empty protocol list".to_owned());
        }
        let mut out = Self::default();
        for protocol in protocols {
            match protocol {
                ProtocolMatch::Any => out.any = true,
                ProtocolMatch::Tcp(ports) => merge_ports(&mut out.tcp, ports)?,
                ProtocolMatch::Udp(ports) => merge_ports(&mut out.udp, ports)?,
                ProtocolMatch::Icmp(types) => merge_types(&mut out.icmp, types)?,
                ProtocolMatch::Ip(number @ (1 | 6 | 17 | 58)) => {
                    return Err(format!(
                        "IP protocol {number} must use the Tcp, Udp or Icmp variant"
                    ));
                }
                ProtocolMatch::Ip(number) => out.ip.push(*number),
            }
        }
        Ok(out)
    }

    /// Whether some entry matches `transport`.
    pub(crate) fn matches(&self, transport: Transport) -> bool {
        self.any
            || match transport {
                Transport::Tcp { dst_port, .. } => self
                    .tcp
                    .as_ref()
                    .is_some_and(|ports| ports.contains(dst_port)),
                Transport::Udp { dst_port, .. } => self
                    .udp
                    .as_ref()
                    .is_some_and(|ports| ports.contains(dst_port)),
                Transport::Icmp { icmp_type } => {
                    self.icmp.as_ref().is_some_and(|types| match types {
                        IcmpTypes::Any => true,
                        IcmpTypes::Only(types) => types.contains(&icmp_type),
                    })
                }
                Transport::Ip(number) => self.ip.contains(&number),
            }
    }

    /// Whether every flow of `protocol` matches, whatever its port.
    pub(crate) const fn covers(&self, protocol: Protocol) -> bool {
        let ports = match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        };
        self.any || matches!(ports, Some(PortSet::Any))
    }
}

fn merge_ports(into: &mut Option<PortSet>, ports: &PortSet) -> Result<(), String> {
    if let PortSet::Ranges(ranges) = ports {
        if ranges.is_empty() {
            return Err("empty port range list".to_owned());
        }
        if let Some(range) = ranges.iter().find(|range| range.start() > range.end()) {
            return Err(format!(
                "port range start {} > end {}",
                range.start(),
                range.end()
            ));
        }
    }
    match (into.as_mut(), ports) {
        (Some(PortSet::Any), _) => {}
        (Some(PortSet::Ranges(mine)), PortSet::Ranges(more)) => mine.extend(more.iter().cloned()),
        (_, ports) => *into = Some(ports.clone()),
    }
    Ok(())
}

fn merge_types(into: &mut Option<IcmpTypes>, types: &IcmpTypes) -> Result<(), String> {
    if matches!(types, IcmpTypes::Only(only) if only.is_empty()) {
        return Err("empty ICMP type list".to_owned());
    }
    match (into.as_mut(), types) {
        (Some(IcmpTypes::Any), _) => {}
        (Some(IcmpTypes::Only(mine)), IcmpTypes::Only(more)) => mine.extend_from_slice(more),
        (_, types) => *into = Some(types.clone()),
    }
    Ok(())
}

/// A rule in its matching form.
#[derive(Debug)]
struct CompiledRule {
    /// Sorted in the label set order, without duplicates.
    labels: Box<[Label]>,
    sources: Box<[IpNet]>,
    destinations: Box<[IpNet]>,
    protocols: Protocols,
}

impl CompiledRule {
    fn compile(rule: &Rule) -> Result<Self, Error> {
        let protocols =
            Protocols::compile(&rule.protocols).map_err(|reason| Error::InvalidRule {
                id: rule.id.clone(),
                reason,
            })?;
        let LabelSet(labels) = LabelSet::new(rule.labels.iter().cloned());
        Ok(Self {
            labels: labels.iter().cloned().collect(),
            sources: rule.sources.iter().copied().collect(),
            destinations: rule.destinations.iter().copied().collect(),
            protocols,
        })
    }

    fn matches(&self, labels: &LabelSet, flow: &Flow) -> bool {
        (self.labels.is_empty() || labels.intersects_sorted(&self.labels))
            && (self.sources.is_empty() || self.sources.iter().any(|net| net.contains(&flow.src)))
            && (self.destinations.is_empty()
                || self.destinations.iter().any(|net| net.contains(&flow.dst)))
            && self.protocols.matches(flow.transport)
    }

    /// Whether the rule accepts every `protocol` flow from any source.
    fn accepts_everything(&self, protocol: Protocol) -> bool {
        self.labels.is_empty()
            && self.sources.is_empty()
            && self.destinations.is_empty()
            && self.protocols.covers(protocol)
    }
}

/// A validated, immutable rule list (the default rules or one namespace's
/// rules), cheap to share through an `Arc`.
///
/// Rules are a union: the verdict does not depend on their order, and the
/// reported [`RuleId`] is that of the first matching rule in list order.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    compiled: Vec<CompiledRule>,
}

impl RuleSet {
    /// Validate `rules`.
    ///
    /// Returns [`Error::InvalidRule`] for a rule with an empty protocol list,
    /// a port range whose start is greater than its end, an empty
    /// [`PortSet::Ranges`] or [`IcmpTypes::Only`], or
    /// [`ProtocolMatch::Ip`] of 1, 6, 17 or 58.
    pub fn new(rules: impl IntoIterator<Item = Rule>) -> Result<Self, Error> {
        let rules: Vec<Rule> = rules.into_iter().collect();
        let compiled = rules
            .iter()
            .map(CompiledRule::compile)
            .collect::<Result<_, _>>()?;
        Ok(Self { rules, compiled })
    }

    /// The empty rule set: every new flow is denied.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The rules, in list order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The number of rules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the set holds no rule.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The first rule matching `flow` from a source with `labels` (rules
    /// only: no namespaces, grants or pinholes). `None` for a flow whose
    /// addresses are of different families.
    #[must_use]
    pub fn matching(&self, labels: &LabelSet, flow: &Flow) -> Option<&RuleId> {
        if flow.is_mixed() {
            return None;
        }
        self.first_match(labels, flow)
    }

    /// [`matching`](Self::matching) without the family check.
    pub(crate) fn first_match(&self, labels: &LabelSet, flow: &Flow) -> Option<&RuleId> {
        self.compiled
            .iter()
            .position(|rule| rule.matches(labels, flow))
            .map(|index| &self.rules[index].id)
    }

    /// Whether every TCP and UDP flow from any source is accepted.
    pub(crate) fn accepts_everything(&self) -> bool {
        [Protocol::Tcp, Protocol::Udp].into_iter().all(|protocol| {
            self.compiled
                .iter()
                .any(|rule| rule.accepts_everything(protocol))
        })
    }
}

// ── Flows and decisions ───────────────────────────────────────────────────────

/// A flow described without a packet: its addresses and transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Flow {
    /// The source address.
    pub src: IpAddr,
    /// The destination address.
    pub dst: IpAddr,
    /// The transport protocol with its ports or ICMP type.
    pub transport: Transport,
}

/// The transport of a [`Flow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP.
    Tcp {
        /// The source port.
        src_port: u16,
        /// The destination port.
        dst_port: u16,
    },
    /// UDP.
    Udp {
        /// The source port.
        src_port: u16,
        /// The destination port.
        dst_port: u16,
    },
    /// ICMP on IPv4 (protocol 1) or `ICMPv6` on IPv6 (protocol 58).
    Icmp {
        /// The message type.
        icmp_type: u8,
    },
    /// Another IP protocol.
    Ip(u8),
}

impl Flow {
    /// A TCP flow from `src` to `dst`.
    #[must_use]
    pub const fn tcp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            src: src.ip(),
            dst: dst.ip(),
            transport: Transport::Tcp {
                src_port: src.port(),
                dst_port: dst.port(),
            },
        }
    }

    /// A UDP flow from `src` to `dst`.
    #[must_use]
    pub const fn udp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            src: src.ip(),
            dst: dst.ip(),
            transport: Transport::Udp {
                src_port: src.port(),
                dst_port: dst.port(),
            },
        }
    }

    /// An ICMP (or `ICMPv6`) flow of message type `icmp_type`.
    #[must_use]
    pub const fn icmp(src: IpAddr, dst: IpAddr, icmp_type: u8) -> Self {
        Self {
            src,
            dst,
            transport: Transport::Icmp { icmp_type },
        }
    }

    /// A flow of IP protocol `protocol`.
    #[must_use]
    pub const fn ip(src: IpAddr, dst: IpAddr, protocol: u8) -> Self {
        Self {
            src,
            dst,
            transport: Transport::Ip(protocol),
        }
    }

    /// Whether the addresses are of different families.
    pub(crate) const fn is_mixed(&self) -> bool {
        self.src.is_ipv4() != self.dst.is_ipv4()
    }

    /// The port-carrying protocol and destination port, for pinholes.
    pub(crate) const fn port(&self) -> Option<(Protocol, u16)> {
        match self.transport {
            Transport::Tcp { dst_port, .. } => Some((Protocol::Tcp, dst_port)),
            Transport::Udp { dst_port, .. } => Some((Protocol::Udp, dst_port)),
            Transport::Icmp { .. } | Transport::Ip(_) => None,
        }
    }
}

/// The decision about a new inbound flow
/// ([`AclEngine::evaluate`](crate::AclEngine::evaluate)).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// The flow is accepted.
    Accept(Matched),
    /// The flow is denied; a [`reasons`](crate::reasons) constant.
    Deny(&'static str),
}

/// What accepted a flow.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Matched {
    /// A rule of the default rule set (`namespace: None`) or of a namespace.
    Rule {
        /// The namespace whose rule matched, `None` for the default rules.
        namespace: Option<NamespaceId>,
        /// The matching rule's identifier.
        id: RuleId,
    },
    /// A directed grant, by identifier.
    Grant(RuleId),
    /// An inbound pinhole.
    Pinhole(PinholeId),
    /// [`PolicyState::NotInstalled`] with [`NotInstalled::Accept`].
    NotInstalled,
}

impl Decision {
    /// Whether the flow is accepted.
    #[must_use]
    pub const fn is_accept(&self) -> bool {
        matches!(self, Self::Accept(_))
    }

    /// The identifier of the rule or grant that accepted the flow.
    #[must_use]
    pub const fn rule_id(&self) -> Option<&RuleId> {
        match self {
            Self::Accept(Matched::Rule { id, .. } | Matched::Grant(id)) => Some(id),
            Self::Accept(_) | Self::Deny(_) => None,
        }
    }

    /// The reason of a denial.
    #[must_use]
    pub const fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Deny(reason) => Some(reason),
            Self::Accept(_) => None,
        }
    }
}

/// What applies to sources in no namespace while no rule set is installed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotInstalled {
    /// New flows are denied with [`reasons::NO_POLICY`](crate::reasons::NO_POLICY).
    #[default]
    Deny,
    /// Every flow is accepted.
    Accept,
}

/// The state of the engine's default rule set (sources in no namespace).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PolicyState {
    /// Nothing installed: the engine's [`NotInstalled`] action applies.
    #[default]
    NotInstalled,
    /// A rule set is installed (possibly empty: every new flow denied).
    Installed {
        /// The number of installed rules.
        rules: usize,
    },
    /// The caller reported a failure: fail closed.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn tcp(src: &str, dst: &str, port: u16) -> Flow {
        Flow::tcp(
            SocketAddr::new(addr(src), 4000),
            SocketAddr::new(addr(dst), port),
        )
    }

    fn udp(src: &str, dst: &str, port: u16) -> Flow {
        Flow::udp(
            SocketAddr::new(addr(src), 4000),
            SocketAddr::new(addr(dst), port),
        )
    }

    fn set(labels: &[&str]) -> LabelSet {
        labels.iter().copied().map(Label::from).collect()
    }

    fn one(rule: Rule) -> RuleSet {
        RuleSet::new([rule]).unwrap()
    }

    fn matches(rules: &RuleSet, labels: &LabelSet, flow: &Flow) -> Option<String> {
        rules
            .matching(labels, flow)
            .map(|id| id.as_str().to_owned())
    }

    #[test]
    fn labels_compare_by_text() {
        let (a, b) = (Label::from("a"), Label::from(String::from("b")));
        assert_eq!(a, Label::new("a"));
        assert_ne!(a, b);
        assert!(a < b);
        assert_eq!(a.as_str(), "a");
        assert_eq!(b.to_string(), "b");
        assert_eq!(format!("{a:?}"), "Label(\"a\")");
    }

    #[test]
    fn label_sets_are_sorted_and_deduplicated() {
        let labels = set(&["b", "a", "b", "c"]);
        assert_eq!(labels.len(), 3);
        assert!(!labels.is_empty());
        assert!(labels.contains(&"a".into()) && !labels.contains(&"d".into()));
        assert!(labels.intersects(&["d".into(), "c".into()]));
        assert!(!labels.intersects(&["d".into()]));
        assert!(!labels.intersects(&[]));
        assert_eq!(labels, set(&["c", "b", "a"]));
        let mut texts: Vec<&str> = labels.iter().map(Label::as_str).collect();
        texts.sort_unstable();
        assert_eq!(texts, ["a", "b", "c"]);
        assert!(LabelSet::empty().is_empty());
        assert!(!LabelSet::empty().contains(&"a".into()));
    }

    #[test]
    fn serde_of_labels_and_rules() {
        let labels = set(&["x", "y"]);
        let json = serde_json::to_string(&labels).unwrap();
        assert_eq!(serde_json::from_str::<LabelSet>(&json).unwrap(), labels);
        let rule = Rule::new(
            "r1",
            vec![
                ProtocolMatch::Tcp(PortSet::list([80, 443])),
                ProtocolMatch::Udp(PortSet::Any),
                ProtocolMatch::Icmp(IcmpTypes::Only(vec![8])),
                ProtocolMatch::Ip(47),
            ],
        )
        .with_labels(["k".into()])
        .with_sources([net("10.0.0.0/8")])
        .with_destinations([net("fd00::/64")]);
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"10.0.0.0/8\""), "{json}");
        assert_eq!(serde_json::from_str::<Rule>(&json).unwrap(), rule);
        let minimal: Rule = serde_json::from_str(r#"{"id": "m", "protocols": ["Any"]}"#).unwrap();
        assert_eq!(minimal, Rule::new("m", vec![ProtocolMatch::Any]));
    }

    #[test]
    fn validation() {
        let invalid = [
            Vec::new(),
            vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![]))],
            vec![ProtocolMatch::Udp(PortSet::Ranges(vec![
                RangeInclusive::new(90, 80),
            ]))],
            vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![]))],
            vec![ProtocolMatch::Ip(1)],
            vec![ProtocolMatch::Ip(6)],
            vec![ProtocolMatch::Ip(17)],
            vec![ProtocolMatch::Ip(58)],
        ];
        for protocols in invalid {
            let rules = [
                Rule::new("ok", vec![ProtocolMatch::Any]),
                Rule::new("bad", protocols.clone()),
            ];
            match RuleSet::new(rules) {
                Err(Error::InvalidRule { id, .. }) => assert_eq!(id.as_str(), "bad"),
                other => panic!("{protocols:?}: {other:?}"),
            }
        }
        assert!(RuleSet::new([Rule::new("ip", vec![ProtocolMatch::Ip(47)])]).is_ok());
        let rules = RuleSet::new([Rule::new("r", vec![ProtocolMatch::Any])]).unwrap();
        assert_eq!((rules.len(), rules.is_empty()), (1, false));
        assert_eq!(rules.rules()[0].id.as_str(), "r");
        assert!(RuleSet::empty().is_empty());
    }

    #[test]
    fn default_deny() {
        let flow = tcp("10.0.0.1", "10.0.0.2", 80);
        assert_eq!(RuleSet::empty().matching(&set(&["a"]), &flow), None);
    }

    #[test]
    fn labels_any_match_and_empty_sets() {
        let rules =
            one(Rule::new("l", vec![ProtocolMatch::Any]).with_labels(["a".into(), "b".into()]));
        let flow = tcp("10.0.0.1", "10.0.0.2", 80);
        assert_eq!(
            matches(&rules, &set(&["b", "z"]), &flow).as_deref(),
            Some("l")
        );
        assert_eq!(matches(&rules, &set(&["z"]), &flow), None);
        // An empty set matches only rules without labels.
        assert_eq!(matches(&rules, &LabelSet::empty(), &flow), None);
        let open = one(Rule::new("o", vec![ProtocolMatch::Any]));
        assert_eq!(
            matches(&open, &LabelSet::empty(), &flow).as_deref(),
            Some("o")
        );
    }

    #[test]
    fn prefixes_and_labels_are_a_conjunction() {
        let rules = one(Rule::new("p", vec![ProtocolMatch::Any])
            .with_labels(["a".into()])
            .with_sources([net("10.0.0.0/24")])
            .with_destinations([net("10.0.1.0/24"), net("fd00::/64")]));
        let labelled = set(&["a"]);
        assert!(
            rules
                .matching(&labelled, &tcp("10.0.0.5", "10.0.1.1", 1))
                .is_some()
        );
        // Outside the source prefix, outside the destinations, without the label.
        assert!(
            rules
                .matching(&labelled, &tcp("10.0.9.5", "10.0.1.1", 1))
                .is_none()
        );
        assert!(
            rules
                .matching(&labelled, &tcp("10.0.0.5", "10.0.2.1", 1))
                .is_none()
        );
        assert!(
            rules
                .matching(&set(&["b"]), &tcp("10.0.0.5", "10.0.1.1", 1))
                .is_none()
        );
        // An address of the other family never matches a prefix.
        assert!(
            rules
                .matching(&labelled, &tcp("fd00::5", "fd00::1", 1))
                .is_none()
        );
        // A family-mixed flow matches nothing.
        let open = one(Rule::new("o", vec![ProtocolMatch::Any]));
        assert!(
            open.matching(&labelled, &tcp("10.0.0.5", "fd00::1", 1))
                .is_none()
        );
    }

    #[test]
    fn ports_any_list_and_range() {
        let rules = RuleSet::new([
            Rule::new("single", vec![ProtocolMatch::Tcp(PortSet::single(22))]),
            Rule::new("list", vec![ProtocolMatch::Tcp(PortSet::list([80, 443]))]),
            Rule::new(
                "range",
                vec![ProtocolMatch::Tcp(PortSet::Ranges(vec![
                    RangeInclusive::new(8000, 8999),
                ]))],
            ),
            Rule::new("any", vec![ProtocolMatch::Udp(PortSet::Any)]),
        ])
        .unwrap();
        let labels = LabelSet::empty();
        let tcp_to = |port| matches(&rules, &labels, &tcp("10.0.0.1", "10.0.0.2", port));
        assert_eq!(tcp_to(22).as_deref(), Some("single"));
        assert_eq!(tcp_to(443).as_deref(), Some("list"));
        assert_eq!(tcp_to(8000).as_deref(), Some("range"));
        assert_eq!(tcp_to(8999).as_deref(), Some("range"));
        assert_eq!(tcp_to(7999), None);
        assert_eq!(tcp_to(9000), None);
        for port in [1, 22, 65535] {
            assert_eq!(
                matches(&rules, &labels, &udp("10.0.0.1", "10.0.0.2", port)).as_deref(),
                Some("any")
            );
        }
    }

    #[test]
    fn protocol_set_and_icmp_types() {
        let rules = RuleSet::new([
            Rule::new("tcp", vec![ProtocolMatch::Tcp(PortSet::Any)]),
            Rule::new(
                "echo",
                vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![8, 128]))],
            ),
            Rule::new("gre", vec![ProtocolMatch::Ip(47)]),
        ])
        .unwrap();
        let labels = LabelSet::empty();
        let (a, b, a6, b6) = (
            addr("10.0.0.1"),
            addr("10.0.0.2"),
            addr("fd00::1"),
            addr("fd00::2"),
        );
        let check = |flow: Flow| matches(&rules, &labels, &flow);
        assert_eq!(
            check(tcp("10.0.0.1", "10.0.0.2", 1)).as_deref(),
            Some("tcp")
        );
        assert_eq!(check(udp("10.0.0.1", "10.0.0.2", 1)), None);
        assert_eq!(check(Flow::icmp(a, b, 8)).as_deref(), Some("echo"));
        assert_eq!(check(Flow::icmp(a6, b6, 128)).as_deref(), Some("echo"));
        assert_eq!(check(Flow::icmp(a, b, 0)), None);
        assert_eq!(check(Flow::ip(a, b, 47)).as_deref(), Some("gre"));
        assert_eq!(check(Flow::ip(a, b, 50)), None);
        let any = one(Rule::new(
            "any",
            vec![ProtocolMatch::Icmp(IcmpTypes::Any), ProtocolMatch::Any],
        ));
        for flow in [
            Flow::icmp(a, b, 3),
            Flow::ip(a, b, 50),
            udp("10.0.0.1", "10.0.0.2", 9),
        ] {
            assert!(any.matching(&labels, &flow).is_some());
        }
    }

    #[test]
    fn first_matching_rule_reports_its_id() {
        let rules = RuleSet::new([
            Rule::new("narrow", vec![ProtocolMatch::Tcp(PortSet::single(80))])
                .with_labels(["a".into()]),
            Rule::new("shared", vec![ProtocolMatch::Tcp(PortSet::single(80))]),
            Rule::new("shared", vec![ProtocolMatch::Udp(PortSet::Any)]),
            Rule::new("wide", vec![ProtocolMatch::Any]),
        ])
        .unwrap();
        let flow = tcp("10.0.0.1", "10.0.0.2", 80);
        assert_eq!(
            matches(&rules, &set(&["a"]), &flow).as_deref(),
            Some("narrow")
        );
        assert_eq!(
            matches(&rules, &set(&["b"]), &flow).as_deref(),
            Some("shared")
        );
        // IDs need not be unique: the second "shared" rule reports the same id.
        let udp_flow = udp("10.0.0.1", "10.0.0.2", 53);
        assert_eq!(
            matches(&rules, &set(&["b"]), &udp_flow).as_deref(),
            Some("shared")
        );
        assert_eq!(
            matches(&rules, &set(&["b"]), &Flow::ip(flow.src, flow.dst, 47)).as_deref(),
            Some("wide")
        );
    }

    #[test]
    fn accepts_everything_needs_open_tcp_and_udp() {
        let both = RuleSet::new([
            Rule::new("t", vec![ProtocolMatch::Tcp(PortSet::Any)]),
            Rule::new("u", vec![ProtocolMatch::Udp(PortSet::Any)]),
        ])
        .unwrap();
        assert!(both.accepts_everything());
        assert!(one(Rule::new("a", vec![ProtocolMatch::Any])).accepts_everything());
        let labelled = one(Rule::new("a", vec![ProtocolMatch::Any]).with_labels(["x".into()]));
        assert!(!labelled.accepts_everything());
        let tcp_only = one(Rule::new("t", vec![ProtocolMatch::Tcp(PortSet::Any)]));
        assert!(!tcp_only.accepts_everything());
        assert!(!RuleSet::empty().accepts_everything());
    }

    #[test]
    fn decision_accessors() {
        let rule = Decision::Accept(Matched::Rule {
            namespace: None,
            id: "r".into(),
        });
        assert!(rule.is_accept());
        assert_eq!(rule.rule_id().map(RuleId::as_str), Some("r"));
        assert_eq!(rule.reason(), None);
        let grant = Decision::Accept(Matched::Grant("g".into()));
        assert_eq!(grant.rule_id().map(RuleId::as_str), Some("g"));
        assert_eq!(Decision::Accept(Matched::NotInstalled).rule_id(), None);
        let deny = Decision::Deny(crate::reasons::DENIED);
        assert!(!deny.is_accept());
        assert_eq!(deny.reason(), Some(crate::reasons::DENIED));
        assert_eq!(deny.rule_id(), None);
    }
}
