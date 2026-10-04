//! Access requests, compiled policies and the shared [`AclEngine`] with its
//! namespaces, grants and pinholes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use arc_swap::{ArcSwap, Guard};
use tracing::{debug, warn};

use crate::{
    Error,
    matcher::{
        DstMatcher, HostMatcher, PortMatcher, SrcMatcher, parse_dst, parse_ports, parse_protocol,
        parse_src,
    },
    namespace::{Grant, GrantEnd, NamespaceId, NamespacePolicy},
    net::{IpNet, Protocol},
    pinhole::{
        Direction, Pinhole, PinholeCounters, PinholeError, PinholeGuard, PinholeId, PinholeSpec,
        PinholeStats,
    },
    policy::{AclPolicy, AclTest},
};

// ── Public types ──────────────────────────────────────────────────────────────

/// How the source identity of an access request was established.
///
/// The ACL judge keys on a **principal**, not a bare IP. For the relay/direct
/// link modes the caller resolves the end-to-end client's WireGuard key and
/// builds [`SourceAssertion::WgPeerKey`]; for the terminate mode the gateway
/// asserted a binding. [`AccessRequest`] still carries `src_ip` for legacy CIDR rules and
/// logging, but the assertion is what carries the key principal + the
/// `source_class`/`source_anchor` used in decision logs.
#[derive(Debug, Clone)]
pub enum SourceAssertion {
    /// An end-to-end client WireGuard public key (wg-relay / wss-relay / direct).
    WgPeerKey {
        /// The client's 32-byte WireGuard public key.
        pubkey: [u8; 32],
    },
    /// The gateway terminated the client tunnel and asserted this binding.
    Terminate {
        /// The asserted binding (an optional tunnel IP + a stable anchor).
        binding: TerminateBinding,
    },
    /// An external identity-provider assertion.
    External {
        /// The identity-provider identifier.
        idp: String,
    },
}

/// A gateway-asserted terminate binding.
#[derive(Debug, Clone)]
pub struct TerminateBinding {
    /// The tunnel IP the gateway assigned, when present (kept for CIDR rules).
    pub ip: Option<IpAddr>,
    /// A stable identity string for rules/logs.
    pub anchor: String,
}

impl SourceAssertion {
    /// The decision-log source class string.
    #[must_use]
    pub const fn source_class(&self) -> &'static str {
        match self {
            Self::WgPeerKey { .. } => "client-wg-key",
            Self::Terminate { .. } => "terminate-binding",
            Self::External { .. } => "external-idp",
        }
    }

    /// A stable identity string for rules/logs.
    #[must_use]
    pub fn source_anchor(&self) -> String {
        match self {
            Self::WgPeerKey { pubkey } => wg_peer_anchor(pubkey),
            Self::Terminate { binding } => binding.anchor.clone(),
            Self::External { idp } => format!("idp:{idp}"),
        }
    }

    /// The terminate binding of a bare source IP: the principal of
    /// [`AccessRequest::from_ip`].
    pub(crate) fn from_ip(ip: IpAddr) -> Self {
        Self::Terminate {
            binding: TerminateBinding {
                ip: Some(ip),
                anchor: ip.to_string(),
            },
        }
    }

    /// The IP-bearing source, when any (terminate bindings). `None` for
    /// key/IdP assertions — those match by anchor, not CIDR.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Terminate { binding } => binding.ip,
            Self::WgPeerKey { .. } | Self::External { .. } => None,
        }
    }
}

/// Canonical anchor encoding for a WireGuard peer key: `key:<hex>` (64 lowercase
/// hex chars). This is the `src` form key principals use in rules, so an
/// inbound client key can be matched against a rule.
#[must_use]
pub fn wg_peer_anchor(pubkey: &[u8; 32]) -> String {
    let mut s = String::with_capacity(4 + 64);
    s.push_str("key:");
    for b in pubkey {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A connection access request to evaluate against the policy.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    /// Legacy source IP (tunnel/inner src) — still used by CIDR rules + logs.
    pub src_ip: IpAddr,
    /// Typed source assertion: the principal + how it was established.
    pub source: SourceAssertion,
    /// Destination IP address.
    pub dst_ip: IpAddr,
    /// Destination port.
    pub dst_port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
}

impl AccessRequest {
    /// Build a request from a bare source IP (the legacy/terminate path): the
    /// assertion is a [`SourceAssertion::Terminate`] binding carrying that IP.
    /// Behaviour-preserving for IP/CIDR rules.
    #[must_use]
    pub fn from_ip(src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, protocol: Protocol) -> Self {
        Self {
            src_ip,
            source: SourceAssertion::from_ip(src_ip),
            dst_ip,
            dst_port,
            protocol,
        }
    }

    /// Build a request whose source is an end-to-end client WireGuard key
    /// (wg-relay / wss-relay / direct). `src_ip` is retained for legacy CIDR
    /// rules + logs; the key is what the subject principals match against.
    #[must_use]
    pub const fn with_wg_peer_key(
        pubkey: [u8; 32],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            source: SourceAssertion::WgPeerKey { pubkey },
            dst_ip,
            dst_port,
            protocol,
        }
    }
}

/// Result of an ACL evaluation.
#[derive(Debug, Clone)]
pub struct AclDecision {
    /// `true` if an accept rule matched; `false` means default deny.
    pub allowed: bool,
    /// Index of the matched rule within the compiled rule list (if any).
    pub matched_rule_index: Option<usize>,
    /// Human-readable explanation.
    pub reason: String,
}

/// A failed built-in policy test.
#[derive(Debug, Clone)]
pub struct AclTestFailure {
    /// The test that failed.
    pub test: AclTest,
    /// Why it failed.
    pub reason: String,
}

// ── Internal compiled rule ────────────────────────────────────────────────────

#[derive(Debug)]
struct CompiledRule {
    src: Vec<SrcMatcher>,
    dst: Vec<DstMatcher>,
    /// `None` means match both TCP and UDP.
    proto: Option<Protocol>,
}

impl CompiledRule {
    fn matches(&self, req: &AccessRequest) -> bool {
        if !self.src.iter().any(|m| m.matches(&req.source)) {
            return false;
        }
        if !self.dst.iter().any(|m| m.matches(req.dst_ip, req.dst_port)) {
            return false;
        }
        self.proto.is_none_or(|proto| proto == req.protocol)
    }

    /// Whether the rule accepts every `protocol` request, whatever its
    /// source, destination and port.
    fn accepts_everything(&self, protocol: Protocol) -> bool {
        self.src.iter().any(|src| matches!(src, SrcMatcher::Any))
            && self.dst.iter().any(|dst| {
                matches!(dst.host, HostMatcher::Any) && matches!(dst.ports, PortMatcher::Any)
            })
            && self.proto.is_none_or(|proto| proto == protocol)
    }
}

// ── CompiledPolicy ────────────────────────────────────────────────────────────

/// A validated, compiled policy: evaluate connection requests against it.
///
/// Default policy is **deny** — traffic is blocked unless an explicit `accept`
/// rule matches. Immutable once compiled; share it through an [`AclEngine`].
#[derive(Debug)]
pub struct CompiledPolicy {
    compiled_rules: Vec<CompiledRule>,
    tests: Vec<AclTest>,
}

impl CompiledPolicy {
    /// Resolve and compile an [`AclPolicy`].
    ///
    /// Runs the built-in tests and returns [`Error::TestsFailed`] if any fail.
    pub fn compile(policy: AclPolicy) -> Result<Self, Error> {
        let hosts = resolve_hosts(&policy.hosts)?;

        let mut compiled_rules = Vec::with_capacity(policy.acls.len());
        for (i, rule) in policy.acls.iter().enumerate() {
            let src = rule
                .src
                .iter()
                .map(|s| parse_src(s, &hosts))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} src: {e}")))?;

            let dst = rule
                .dst
                .iter()
                .map(|s| parse_dst(s, &hosts))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} dst: {e}")))?;

            let proto = rule
                .proto
                .as_deref()
                .map(parse_protocol)
                .transpose()
                .map_err(|e| Error::InvalidPolicy(format!("rule {i} proto: {e}")))?;

            compiled_rules.push(CompiledRule { src, dst, proto });
        }

        let engine = Self {
            compiled_rules,
            tests: policy.tests,
        };

        let failures = engine.validate_tests();
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

        Ok(engine)
    }

    /// A policy that permits every flow. For an endpoint that does not filter
    /// its inbound — e.g. a wss-relay client decrypting responses to connections
    /// it originated. The shared WG decrypt path is otherwise fail-closed when no
    /// policy is loaded, which would drop the client's return traffic.
    #[must_use]
    pub fn permit_all() -> Self {
        Self {
            compiled_rules: vec![CompiledRule {
                src: vec![SrcMatcher::Any],
                dst: vec![DstMatcher {
                    host: HostMatcher::Any,
                    ports: PortMatcher::Any,
                }],
                proto: None,
            }],
            tests: Vec::new(),
        }
    }

    /// Evaluate whether `request` is allowed by the policy.
    ///
    /// Returns `allowed = true` only when an explicit accept rule matches.
    /// If no rule matches, the result is a default deny.
    pub fn is_allowed(&self, request: &AccessRequest) -> AclDecision {
        self.matched_rule(request).map_or_else(
            || AclDecision {
                allowed: false,
                matched_rule_index: None,
                reason: "denied: no matching accept rule".to_owned(),
            },
            |idx| AclDecision {
                allowed: true,
                matched_rule_index: Some(idx),
                reason: format!("accepted by rule {idx}"),
            },
        )
    }

    /// The index of the first rule accepting `request`, without building an
    /// [`AclDecision`] (the data path).
    pub(crate) fn matched_rule(&self, request: &AccessRequest) -> Option<usize> {
        for (idx, rule) in self.compiled_rules.iter().enumerate() {
            if rule.matches(request) {
                debug!(
                    src = %request.src_ip,
                    dst = %request.dst_ip,
                    port = request.dst_port,
                    proto = ?request.protocol,
                    rule = idx,
                    "ACL accept"
                );
                return Some(idx);
            }
        }

        // `debug!`, not `warn!`: the data path evaluates every packet, so a
        // warning per denied packet would flood the log.
        debug!(
            src = %request.src_ip,
            dst = %request.dst_ip,
            port = request.dst_port,
            proto = ?request.protocol,
            "ACL deny: no matching rule"
        );
        None
    }

    /// Whether every TCP and UDP request is accepted, whatever its source,
    /// destination and port.
    fn accepts_everything(&self) -> bool {
        [Protocol::Tcp, Protocol::Udp].into_iter().all(|protocol| {
            self.compiled_rules
                .iter()
                .any(|rule| rule.accepts_everything(protocol))
        })
    }

    /// Run the built-in policy tests and return a list of failures.
    pub fn validate_tests(&self) -> Vec<AclTestFailure> {
        let mut failures = Vec::new();

        for test in &self.tests {
            let Ok(src_ip) = test.src.parse::<IpAddr>() else {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!("cannot parse src IP '{}'", test.src),
                });
                continue;
            };

            let (dst_ip, dst_port) = match parse_test_dst(&test.dst) {
                Ok(pair) => pair,
                Err(reason) => {
                    failures.push(AclTestFailure {
                        test: test.clone(),
                        reason,
                    });
                    continue;
                }
            };

            let protocol = match test.proto.as_deref() {
                Some(raw) => match parse_protocol(raw) {
                    Ok(proto) => proto,
                    Err(reason) => {
                        failures.push(AclTestFailure {
                            test: test.clone(),
                            reason: format!("cannot parse test proto '{raw}': {reason}"),
                        });
                        continue;
                    }
                },
                None => Protocol::Tcp,
            };

            let req = AccessRequest::from_ip(src_ip, dst_ip, dst_port, protocol);
            let decision = self.is_allowed(&req);

            if decision.allowed != test.allow {
                failures.push(AclTestFailure {
                    test: test.clone(),
                    reason: format!(
                        "expected {}, got {} ({})",
                        if test.allow { "allow" } else { "deny" },
                        if decision.allowed { "allow" } else { "deny" },
                        decision.reason,
                    ),
                });
            }
        }

        failures
    }
}

// ── Namespaces, grants and the engine snapshot ────────────────────────────────

/// What a reply allowance depends on. An allowance whose dependency is gone
/// from the current [`Snapshot`] (or, for a pinhole, expired) is revoked on
/// its next lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplyDependency {
    /// A directed grant, by id.
    Grant(Arc<str>),
    /// An app pinhole.
    Pinhole(PinholeId),
}

/// The open pinhole matching a flow, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinholeMatch {
    /// An open pinhole matches.
    Open(PinholeId),
    /// Only expired pinholes match: the flow is not accepted, and the caller
    /// sweeps them ([`AclEngine::expire_pinholes`]).
    Expired,
    /// No pinhole matches.
    Absent,
}

/// The outcome of evaluating an inbound request from a namespace member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemberVerdict {
    /// Accepted by rule `index` of `namespace`.
    Rule {
        namespace: NamespaceId,
        index: usize,
    },
    /// Accepted by the directed grant with this id.
    Grant(Arc<str>),
    /// Accepted by an inbound pinhole.
    Pinhole(PinholeId),
    /// Nothing accepts the request, but an expired inbound pinhole matched:
    /// denied, and the caller sweeps expired pinholes.
    PinholeExpired,
    /// Nothing accepts the request.
    Denied,
    /// The destination is another peer sharing no namespace with the source,
    /// and no grant accepts the request.
    CrossNamespace,
}

/// A compiled protocol and port matcher (outbound rules, grants).
#[derive(Debug)]
struct CompiledPorts {
    /// `None` means both TCP and UDP.
    proto: Option<Protocol>,
    ports: PortMatcher,
}

impl CompiledPorts {
    fn compile(proto: Option<&str>, ports: Option<&str>, what: &str) -> Result<Self, Error> {
        let proto = proto
            .map(parse_protocol)
            .transpose()
            .map_err(|e| Error::InvalidPolicy(format!("{what} proto: {e}")))?;
        let ports = ports
            .map_or(Ok(PortMatcher::Any), parse_ports)
            .map_err(|e| Error::InvalidPolicy(format!("{what} ports: {e}")))?;
        Ok(Self { proto, ports })
    }

    fn matches(&self, protocol: Protocol, port: u16) -> bool {
        self.proto.is_none_or(|proto| proto == protocol) && self.ports.matches(port)
    }
}

#[derive(Debug)]
struct CompiledNamespace {
    source: NamespacePolicy,
    rules: CompiledPolicy,
    /// `None`: outbound to the members is unrestricted.
    outbound: Option<Vec<CompiledPorts>>,
}

impl CompiledNamespace {
    fn compile(id: &NamespaceId, source: NamespacePolicy) -> Result<Self, Error> {
        if id.is_app() && (!source.policy.acls.is_empty() || !source.allow_app_pinholes.is_empty())
        {
            return Err(Error::InvalidPolicy(format!(
                "app namespace '{id}' cannot have accept rules or allow app pinholes"
            )));
        }
        let rules = CompiledPolicy::compile(source.policy.clone())?;
        let outbound = source
            .outbound
            .as_ref()
            .map(|rules| {
                rules
                    .iter()
                    .enumerate()
                    .map(|(i, rule)| {
                        CompiledPorts::compile(
                            rule.proto.as_deref(),
                            Some(&rule.ports),
                            &format!("outbound rule {i}"),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Self {
            source,
            rules,
            outbound,
        })
    }
}

#[derive(Debug)]
struct CompiledGrant {
    id: Arc<str>,
    grant: Grant,
    ports: CompiledPorts,
}

/// The namespaces a principal belongs to.
#[derive(Debug, Clone)]
pub(crate) struct Membership {
    /// Sorted, without duplicates.
    namespaces: Vec<NamespaceId>,
    /// Every namespace of the principal restricts outbound traffic.
    outbound_restricted: bool,
}

impl Membership {
    fn contains(&self, id: &NamespaceId) -> bool {
        self.namespaces.binary_search(id).is_ok()
    }

    /// The source (non-app) namespaces.
    fn sources(&self) -> impl Iterator<Item = &NamespaceId> {
        self.namespaces.iter().filter(|id| !id.is_app())
    }

    /// Whether outbound traffic to the principal is restricted.
    pub(crate) const fn outbound_restricted(&self) -> bool {
        self.outbound_restricted
    }
}

fn grant_end_matches(end: &GrantEnd, principal: &str, membership: &Membership) -> bool {
    match end {
        GrantEnd::Peer(peer) => peer == principal,
        GrantEnd::Namespace(id) => membership.contains(id),
    }
}

/// The whole engine state: published as one immutable value, so a reader
/// sees the default policy, namespaces and grants of a single update.
#[derive(Debug, Default, Clone)]
pub(crate) struct Snapshot {
    default: Option<Arc<CompiledPolicy>>,
    namespaces: BTreeMap<NamespaceId, Arc<CompiledNamespace>>,
    /// Principal -> its namespaces (derived from `namespaces`).
    memberships: HashMap<String, Membership>,
    /// Member host addresses (`/32`, `/128`) with their principal (derived).
    hosts: HashMap<IpAddr, String>,
    /// The other member addresses with their principal, longest prefix first
    /// (derived).
    addresses: Vec<(IpNet, String)>,
    /// Whether some principal is outbound-restricted (derived).
    outbound_restrictions: bool,
    grants: BTreeMap<String, Arc<CompiledGrant>>,
    pinholes: BTreeMap<PinholeId, Arc<Pinhole>>,
    /// Bumped on every published update ([`AclEngine::generation`]).
    generation: u64,
    /// The default policy accepts every inbound request (derived).
    default_bypass: bool,
    /// The members whose inbound requests are all accepted by a namespace
    /// rule and that are not outbound-restricted (derived).
    bypass: HashSet<String>,
}

impl Snapshot {
    /// Whether a default policy or at least one namespace is stored.
    pub(crate) fn is_loaded(&self) -> bool {
        self.default.is_some() || !self.namespaces.is_empty()
    }

    /// The default policy, for principals in no namespace.
    pub(crate) fn default_policy(&self) -> Option<&CompiledPolicy> {
        self.default.as_deref()
    }

    /// The generation of this snapshot.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether every inbound TCP or UDP request from `principal` (`None`: a
    /// peer whose principal is not resolved because there are no members) is
    /// accepted without a dependency and without recording an outbound reply
    /// allowance, so the filter can skip its evaluation.
    pub(crate) fn bypasses(&self, principal: Option<&str>) -> bool {
        principal
            .filter(|principal| self.memberships.contains_key(*principal))
            .map_or(self.default_bypass, |principal| {
                self.bypass.contains(principal)
            })
    }

    /// Whether some pinhole (open or expired but not yet swept) belongs to
    /// `principal`.
    pub(crate) fn has_pinholes_of(&self, principal: &str) -> bool {
        self.pinholes
            .values()
            .any(|pinhole| pinhole.spec.peer == principal)
    }

    /// Whether any principal is a namespace member.
    pub(crate) fn has_members(&self) -> bool {
        !self.memberships.is_empty()
    }

    /// Whether any principal is outbound-restricted.
    pub(crate) const fn has_outbound_restrictions(&self) -> bool {
        self.outbound_restrictions
    }

    /// The namespaces of `principal`, `None` when it is in no namespace.
    pub(crate) fn membership(&self, principal: &str) -> Option<&Membership> {
        self.memberships.get(principal)
    }

    /// Whether any pinhole is stored (open or expired but not yet swept).
    pub(crate) fn has_pinholes(&self) -> bool {
        !self.pinholes.is_empty()
    }

    /// Whether `dependency` still exists in this snapshot; a pinhole must also
    /// be unexpired at `now()`.
    pub(crate) fn is_live(
        &self,
        dependency: &ReplyDependency,
        now: impl FnOnce() -> Instant,
    ) -> bool {
        match dependency {
            ReplyDependency::Grant(id) => self.grants.contains_key(&**id),
            ReplyDependency::Pinhole(id) => self
                .pinholes
                .get(id)
                .is_some_and(|pinhole| pinhole.is_open_at(now())),
        }
    }

    /// The pinhole of `principal` opening `direction` flows of `protocol` to
    /// `port`. The clock is read only when a pinhole matches.
    pub(crate) fn match_pinhole(
        &self,
        principal: &str,
        direction: Direction,
        protocol: Protocol,
        port: u16,
        now: impl Fn() -> Instant,
    ) -> PinholeMatch {
        let mut at = None;
        let mut found = PinholeMatch::Absent;
        for pinhole in self.pinholes.values() {
            if !pinhole.matches(principal, direction, protocol, port) {
                continue;
            }
            if pinhole.is_open_at(*at.get_or_insert_with(&now)) {
                return PinholeMatch::Open(pinhole.id);
            }
            found = PinholeMatch::Expired;
        }
        found
    }

    /// The member owning `ip` (longest prefix), with its namespaces.
    fn member_at(&self, ip: IpAddr) -> Option<(&str, &Membership)> {
        // A host address is always the longest prefix.
        let principal = match self.hosts.get(&ip) {
            Some(principal) => principal,
            None => &self.addresses.iter().find(|(net, _)| net.contains(&ip))?.1,
        };
        Some((principal, self.memberships.get(principal)?))
    }

    /// Evaluate an inbound `request` from `principal`, a namespace member.
    /// `now` is read only when a pinhole matches.
    pub(crate) fn evaluate_member(
        &self,
        request: &AccessRequest,
        principal: &str,
        membership: &Membership,
        now: impl Fn() -> Instant,
    ) -> MemberVerdict {
        let dst = self.member_at(request.dst_ip);
        let mut common = false;
        for id in membership.namespaces.iter().filter(|id| !id.is_app()) {
            // A local destination is in every namespace.
            if dst.is_some_and(|(_, dst)| !dst.contains(id)) {
                continue;
            }
            common = true;
            let Some(namespace) = self.namespaces.get(id) else {
                continue;
            };
            if let Some(index) = namespace.rules.matched_rule(request) {
                return MemberVerdict::Rule {
                    namespace: id.clone(),
                    index,
                };
            }
        }
        let Some((dst_principal, dst_membership)) = dst else {
            // Pinholes open the local node only.
            return match self.match_pinhole(
                principal,
                Direction::Inbound,
                request.protocol,
                request.dst_port,
                now,
            ) {
                PinholeMatch::Open(id) => MemberVerdict::Pinhole(id),
                PinholeMatch::Expired => MemberVerdict::PinholeExpired,
                PinholeMatch::Absent => MemberVerdict::Denied,
            };
        };
        let granted = self.grants.values().find(|grant| {
            grant_end_matches(&grant.grant.from, principal, membership)
                && grant_end_matches(&grant.grant.to, dst_principal, dst_membership)
                && grant.ports.matches(request.protocol, request.dst_port)
        });
        match granted {
            Some(grant) => MemberVerdict::Grant(Arc::clone(&grant.id)),
            None if common => MemberVerdict::Denied,
            None => MemberVerdict::CrossNamespace,
        }
    }

    /// Whether an outbound rule of one of `membership`'s namespaces accepts
    /// `protocol` to `port`.
    pub(crate) fn outbound_rule_accepts(
        &self,
        membership: &Membership,
        protocol: Protocol,
        port: u16,
    ) -> bool {
        membership
            .namespaces
            .iter()
            .filter_map(|id| self.namespaces.get(id)?.outbound.as_deref())
            .flatten()
            .any(|rule| rule.matches(protocol, port))
    }

    fn evaluate_default(&self, request: &AccessRequest) -> AclDecision {
        if let Some(policy) = self.default_policy() {
            return policy.is_allowed(request);
        }
        debug!(
            src = %request.src_ip,
            dst = %request.dst_ip,
            port = request.dst_port,
            proto = ?request.protocol,
            "ACL deny: no policy loaded"
        );
        AclDecision {
            allowed: false,
            matched_rule_index: None,
            reason: "denied: no policy loaded".to_owned(),
        }
    }

    /// Rebuild the indexes derived from `namespaces`.
    fn reindex(&mut self) {
        let mut memberships: HashMap<String, Membership> = HashMap::new();
        let mut addresses = Vec::new();
        for (id, namespace) in &self.namespaces {
            let restricts = namespace.outbound.is_some();
            for member in &namespace.source.members {
                let membership = memberships
                    .entry(member.principal.clone())
                    .or_insert_with(|| Membership {
                        namespaces: Vec::new(),
                        outbound_restricted: true,
                    });
                // `namespaces` iterates in order, so the list stays sorted.
                if membership.namespaces.last() != Some(id) {
                    membership.namespaces.push(id.clone());
                    membership.outbound_restricted &= restricts;
                }
                addresses.extend(
                    member
                        .addresses
                        .iter()
                        .map(|net| (*net, member.principal.clone())),
                );
            }
        }
        addresses.sort_by(|(a, a_principal), (b, b_principal)| {
            b.prefix_len()
                .cmp(&a.prefix_len())
                .then_with(|| a_principal.cmp(b_principal))
        });
        addresses.dedup();
        let mut hosts = HashMap::new();
        addresses.retain(|(net, principal)| {
            let host = net.prefix_len() == if net.network().is_ipv4() { 32 } else { 128 };
            if host {
                // Sorted by principal: the smallest one owns a shared address.
                hosts
                    .entry(net.network())
                    .or_insert_with(|| principal.clone());
            }
            !host
        });
        self.outbound_restrictions = memberships.values().any(|m| m.outbound_restricted);
        self.memberships = memberships;
        self.hosts = hosts;
        self.addresses = addresses;
    }

    /// Recompute the bypass flags. A member bypasses when it is not
    /// outbound-restricted and, for every destination (the local node and
    /// every member address), a common source namespace accepts everything
    /// (an accept rule from `*` to `*:*` for TCP and UDP).
    fn rebypass(&mut self) {
        self.default_bypass = self
            .default
            .as_ref()
            .is_some_and(|policy| policy.accepts_everything());
        let open: HashSet<&NamespaceId> = self
            .namespaces
            .iter()
            .filter(|(id, namespace)| !id.is_app() && namespace.rules.accepts_everything())
            .map(|(id, _)| id)
            .collect();
        let mut bypass = HashSet::new();
        if !open.is_empty() {
            let owners: HashSet<&str> = self
                .hosts
                .values()
                .chain(self.addresses.iter().map(|(_, principal)| principal))
                .map(String::as_str)
                .collect();
            // Members with the same open namespaces share the outcome.
            let mut outcomes: HashMap<Vec<&NamespaceId>, bool> = HashMap::new();
            for (principal, membership) in &self.memberships {
                if membership.outbound_restricted {
                    continue;
                }
                let mine: Vec<&NamespaceId> = membership
                    .namespaces
                    .iter()
                    .filter(|id| open.contains(id))
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let reaches_all = *outcomes.entry(mine).or_insert_with_key(|mine| {
                    owners.iter().all(|owner| {
                        self.memberships
                            .get(*owner)
                            .is_some_and(|m| mine.iter().any(|id| m.contains(id)))
                    })
                });
                if reaches_all {
                    bypass.insert(principal.clone());
                }
            }
        }
        self.bypass = bypass;
    }

    /// Whether `peer` may hold a pinhole of `kind` in `app_namespace`
    /// (`source_gated`: it held a source namespace when the pinhole opened).
    fn pinhole_permission(
        &self,
        app_namespace: &NamespaceId,
        peer: &str,
        kind: &str,
        source_gated: bool,
    ) -> Result<(), PinholeError> {
        let membership = self.membership(peer).filter(|m| m.contains(app_namespace));
        let Some(membership) = membership else {
            return Err(PinholeError::NotMember);
        };
        let mut sources = membership.sources().peekable();
        if sources.peek().is_none() {
            // A session-only peer is governed by its own pinholes, unless it
            // has lost the source namespace that permitted the pinhole.
            return if source_gated {
                Err(PinholeError::NotPermitted)
            } else {
                Ok(())
            };
        }
        let permitted = sources.any(|id| {
            self.namespaces
                .get(id)
                .is_some_and(|ns| ns.source.allow_app_pinholes.contains(kind))
        });
        if permitted {
            Ok(())
        } else {
            Err(PinholeError::NotPermitted)
        }
    }

    /// Remove the pinholes expired at `now`; returns how many.
    fn sweep_pinholes(&mut self, now: Instant) -> u64 {
        let before = self.pinholes.len();
        self.pinholes.retain(|_, pinhole| pinhole.is_open_at(now));
        (before - self.pinholes.len()) as u64
    }

    /// After a namespace change, remove the pinholes whose app namespace is
    /// gone or that are no longer permitted; returns how many of each.
    fn recheck_pinholes(&mut self) -> (u64, u64) {
        let (mut namespace_removed, mut revoked) = (0, 0);
        let mut pinholes = std::mem::take(&mut self.pinholes);
        pinholes.retain(|_, pinhole| {
            if !self.namespaces.contains_key(&pinhole.app_namespace) {
                namespace_removed += 1;
                return false;
            }
            let permitted = self
                .pinhole_permission(
                    &pinhole.app_namespace,
                    &pinhole.spec.peer,
                    &pinhole.spec.kind,
                    pinhole.source_gated,
                )
                .is_ok();
            if !permitted {
                revoked += 1;
            }
            permitted
        });
        self.pinholes = pinholes;
        (namespace_removed, revoked)
    }
}

// ── AclEngine ─────────────────────────────────────────────────────────────────

/// Shared ACL engine: the default [`CompiledPolicy`], rule namespaces,
/// directed grants and app pinholes.
///
/// Fail-closed: until a policy or namespace is loaded (and after
/// [`clear`](Self::clear) with no namespace stored, or after
/// [`clear_all`](Self::clear_all)) every request is denied. A principal in
/// no namespace is denied while no default policy is loaded; a namespace
/// member is governed by its namespaces (plus grants and pinholes) either
/// way.
/// The whole state is one immutable snapshot: writers serialize on a mutex
/// and publish a new snapshot atomically, readers take one lock-free load, so
/// the engine can be shared through an `Arc` and queried per packet while
/// another thread updates it.
///
/// The default policy ([`load`](Self::load), [`store`](Self::store),
/// [`clear`](Self::clear), [`policy`](Self::policy),
/// [`is_allowed`](Self::is_allowed)) applies to principals that are members
/// of no namespace. [`evaluate`](Self::evaluate) evaluates a request with
/// namespaces, grants and pinholes, as [`AclFilter`](crate::AclFilter) does
/// for inbound packets. See the crate docs for the namespace model and
/// pinholes.
pub struct AclEngine {
    snapshot: ArcSwap<Snapshot>,
    writer: Mutex<()>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    pinholes: PinholeCounters,
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::with_clock(Instant::now)
    }
}

impl fmt::Debug for AclEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclEngine")
            .field("snapshot", &self.snapshot)
            .field("pinhole_stats", &self.pinhole_stats())
            .finish_non_exhaustive()
    }
}

impl AclEngine {
    /// An engine with no policy loaded (denies everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine with no policy loaded whose pinhole expiry follows `clock`
    /// instead of [`Instant::now`]; e.g. `|| tokio::time::Instant::now().into_std()`
    /// to follow paused tokio time in tests.
    pub fn with_clock(clock: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self {
            snapshot: ArcSwap::default(),
            writer: Mutex::default(),
            clock: Box::new(clock),
            pinholes: PinholeCounters::default(),
        }
    }

    /// Compile `policy` and make it the active default policy, which applies
    /// to principals in no namespace (namespace members are governed by their
    /// namespaces whether or not a default policy is loaded).
    ///
    /// On error (invalid policy or failed built-in tests) the previously
    /// loaded policy, if any, stays in effect.
    pub fn load(&self, policy: AclPolicy) -> Result<(), Error> {
        match CompiledPolicy::compile(policy) {
            Ok(compiled) => {
                self.store(Arc::new(compiled));
                Ok(())
            }
            Err(err) => {
                warn!(error = %err, "ACL policy rejected; keeping the previous policy");
                Err(err)
            }
        }
    }

    /// Make an already compiled policy the active default policy (see
    /// [`load`](Self::load)).
    pub fn store(&self, policy: Arc<CompiledPolicy>) {
        self.publish(|snapshot| snapshot.default = Some(policy));
    }

    /// Unload the default policy only. Principals in no namespace return to
    /// fail-closed (their new flows are dropped with
    /// [`reasons::NO_POLICY`](crate::reasons::NO_POLICY) by the filter);
    /// namespaces, grants and pinholes stay, and their members are evaluated
    /// as before. See [`clear_all`](Self::clear_all) to remove everything.
    pub fn clear(&self) {
        self.publish(|snapshot| snapshot.default = None);
    }

    /// Emergency stop: remove the default policy and every namespace, grant
    /// and pinhole in one atomic snapshot swap, so the engine is unloaded and
    /// the filter drops every inbound packet, replies included, with
    /// [`reasons::NO_POLICY`](crate::reasons::NO_POLICY).
    ///
    /// Open pinholes are counted in [`PinholeStats::cleared`] (pinholes
    /// already expired are counted as expired); their guards become no-ops.
    /// Later updates ([`load`](Self::load),
    /// [`store_namespace`](Self::store_namespace), ...) work as usual.
    pub fn clear_all(&self) {
        let cleared = self.publish(|snapshot| {
            let cleared = snapshot.pinholes.len() as u64;
            *snapshot = Snapshot::default();
            cleared
        });
        PinholeCounters::add(&self.pinholes.cleared, cleared);
        warn!(
            pinholes = cleared,
            "ACL cleared: every policy, namespace, grant and pinhole removed"
        );
    }

    /// Whether the default policy is loaded or at least one namespace is
    /// stored. When `false`, the filter drops every inbound packet, replies
    /// included, with [`reasons::NO_POLICY`](crate::reasons::NO_POLICY).
    pub fn is_loaded(&self) -> bool {
        self.snapshot.load().is_loaded()
    }

    /// The active default policy, if any.
    pub fn policy(&self) -> Option<Arc<CompiledPolicy>> {
        self.snapshot.load().default.clone()
    }

    /// Evaluate `request` against the active default policy, ignoring
    /// namespaces.
    ///
    /// With no policy loaded the request is denied.
    pub fn is_allowed(&self, request: &AccessRequest) -> AclDecision {
        self.snapshot.load().evaluate_default(request)
    }

    /// Evaluate `request` as an inbound flow, with namespaces and grants.
    ///
    /// The principal is `request.source`'s source anchor. A principal in no
    /// namespace is evaluated against the default policy, like
    /// [`is_allowed`](Self::is_allowed). For a namespace member the
    /// destination address is resolved to a member peer (longest prefix) or
    /// the local node, and the request is accepted by a rule of a shared
    /// namespace (`matched_rule_index` is the index within that namespace) or
    /// by a directed grant (`matched_rule_index` is `None`). This is the
    /// decision [`AclFilter`](crate::AclFilter) applies to a new inbound flow;
    /// the filter's reply table is not consulted.
    pub fn evaluate(&self, request: &AccessRequest) -> AclDecision {
        let snapshot = self.snapshot.load();
        let principal = request.source.source_anchor();
        let Some(membership) = snapshot.membership(&principal) else {
            return snapshot.evaluate_default(request);
        };
        let verdict = snapshot.evaluate_member(request, &principal, membership, || self.now());
        let (allowed, matched_rule_index, reason) = match verdict {
            MemberVerdict::Rule { namespace, index } => (
                true,
                Some(index),
                format!("accepted by namespace {namespace} rule {index}"),
            ),
            MemberVerdict::Grant(id) => (true, None, format!("accepted by grant {id}")),
            MemberVerdict::Pinhole(id) => (true, None, format!("accepted by pinhole {id}")),
            MemberVerdict::PinholeExpired | MemberVerdict::Denied => {
                if verdict == MemberVerdict::PinholeExpired {
                    self.expire_pinholes();
                }
                (false, None, "denied: no matching accept rule".to_owned())
            }
            MemberVerdict::CrossNamespace => (false, None, "denied: cross namespace".to_owned()),
        };
        AclDecision {
            allowed,
            matched_rule_index,
            reason,
        }
    }

    /// Compile `policy` and store it as namespace `id`, replacing only that
    /// namespace.
    ///
    /// The namespace's rules are compiled and their built-in tests run, as
    /// [`load`](Self::load) does. An app namespace ([`NamespaceId::is_app`])
    /// with accept rules or allowed app pinholes is rejected with
    /// [`Error::InvalidPolicy`]. On error the previous state stays in effect.
    pub fn store_namespace(
        &self,
        id: impl Into<NamespaceId>,
        policy: NamespacePolicy,
    ) -> Result<(), Error> {
        let id = id.into();
        let compiled = match CompiledNamespace::compile(&id, policy) {
            Ok(compiled) => Arc::new(compiled),
            Err(err) => {
                warn!(namespace = %id, error = %err, "ACL namespace rejected; keeping the previous state");
                return Err(err);
            }
        };
        self.publish(|snapshot| {
            snapshot.namespaces.insert(id, compiled);
            snapshot.reindex();
            self.recheck_pinholes(snapshot);
        });
        Ok(())
    }

    /// Remove namespace `id`. Returns whether it existed.
    ///
    /// Removing an app namespace closes its pinholes; removing a source
    /// namespace revokes the pinholes it permitted.
    pub fn remove_namespace(&self, id: &str) -> bool {
        self.publish(|snapshot| {
            let removed = snapshot.namespaces.remove(id).is_some();
            if removed {
                snapshot.reindex();
                self.recheck_pinholes(snapshot);
            }
            removed
        })
    }

    /// The stored namespaces, sorted.
    pub fn namespaces(&self) -> Vec<NamespaceId> {
        self.snapshot.load().namespaces.keys().cloned().collect()
    }

    /// The namespaces `principal` is a member of, sorted.
    pub fn memberships(&self, principal: &str) -> Vec<NamespaceId> {
        self.snapshot
            .load()
            .membership(principal)
            .map(|m| m.namespaces.clone())
            .unwrap_or_default()
    }

    /// Store a directed grant under `id`, replacing any grant with that id.
    ///
    /// Returns [`Error::InvalidPolicy`] for an invalid protocol or port syntax,
    /// or when an end is an app namespace (app access goes only through
    /// pinholes); the previous state then stays in effect. Reply allowances
    /// that depend on a grant survive its replacement under the same id.
    pub fn store_grant(&self, id: impl Into<String>, grant: Grant) -> Result<(), Error> {
        let id = id.into();
        for end in [&grant.from, &grant.to] {
            if let GrantEnd::Namespace(ns) = end
                && ns.is_app()
            {
                return Err(Error::InvalidPolicy(format!(
                    "grant '{id}' cannot name app namespace '{ns}'"
                )));
            }
        }
        let ports = CompiledPorts::compile(
            grant.proto.as_deref(),
            grant.ports.as_deref(),
            &format!("grant '{id}'"),
        )?;
        let compiled = Arc::new(CompiledGrant {
            id: Arc::from(id.as_str()),
            grant,
            ports,
        });
        self.publish(|snapshot| {
            snapshot.grants.insert(id, compiled);
        });
        Ok(())
    }

    /// Remove the grant `id`. Returns whether it existed. New flows it
    /// accepted are denied from now on, and reply allowances depending on it
    /// are revoked on their next lookup.
    pub fn remove_grant(&self, id: &str) -> bool {
        self.publish(|snapshot| snapshot.grants.remove(id).is_some())
    }

    /// The stored grants, sorted by id.
    pub fn grants(&self) -> Vec<(String, Grant)> {
        self.snapshot
            .load()
            .grants
            .iter()
            .map(|(id, grant)| (id.clone(), grant.grant.clone()))
            .collect()
    }

    /// Open a pinhole in app namespace `app_namespace` for `spec`: one peer,
    /// one direction, one protocol and one destination port, until the
    /// returned guard is dropped or `spec.expires_at` passes.
    ///
    /// The namespace must be a stored app namespace with `spec.peer` as a
    /// member, and `spec.expires_at` must be in the future per the engine
    /// clock. When the peer is a member of at least one source (non-app)
    /// namespace, one of them must list `spec.kind` in
    /// [`allow_app_pinholes`](NamespacePolicy::allow_app_pinholes); a peer
    /// only in app namespaces is governed by its own pinholes. On error
    /// nothing changes.
    pub fn open_pinhole(
        self: &Arc<Self>,
        app_namespace: impl Into<NamespaceId>,
        spec: PinholeSpec,
    ) -> Result<PinholeGuard, PinholeError> {
        let app_namespace = app_namespace.into();
        let id = self.publish(|snapshot| {
            if !snapshot.namespaces.contains_key(&app_namespace) {
                return Err(PinholeError::UnknownNamespace);
            }
            if !app_namespace.is_app() {
                return Err(PinholeError::NotAppNamespace);
            }
            if !snapshot
                .membership(&spec.peer)
                .is_some_and(|m| m.contains(&app_namespace))
            {
                return Err(PinholeError::NotMember);
            }
            if spec.expires_at <= self.now() {
                return Err(PinholeError::Expired);
            }
            let source_gated = snapshot
                .membership(&spec.peer)
                .is_some_and(|m| m.sources().next().is_some());
            if let Err(err) =
                snapshot.pinhole_permission(&app_namespace, &spec.peer, &spec.kind, source_gated)
            {
                PinholeCounters::add(&self.pinholes.not_permitted, 1);
                return Err(err);
            }
            let id = PinholeId::new(self.pinholes.next_id.fetch_add(1, Ordering::Relaxed) + 1);
            snapshot.pinholes.insert(
                id,
                Arc::new(Pinhole {
                    id,
                    app_namespace,
                    spec,
                    source_gated,
                }),
            );
            PinholeCounters::add(&self.pinholes.opened, 1);
            Ok(id)
        })?;
        debug!(pinhole = %id, "ACL pinhole opened");
        Ok(PinholeGuard::new(self, id))
    }

    /// Remove the pinholes that have reached their expiry; returns how many.
    ///
    /// Evaluation treats an expired pinhole as closed immediately; this sweep
    /// (or the next update of the engine, or the filter seeing the expired
    /// pinhole) removes it and counts it in [`PinholeStats::expired`].
    pub fn expire_pinholes(&self) -> usize {
        let now = self.now();
        let snapshot = self.snapshot.load();
        if snapshot.pinholes.values().all(|p| p.is_open_at(now)) {
            return 0;
        }
        drop(snapshot);
        let (expired, ()) = self.publish_swept(|_| ());
        usize::try_from(expired).unwrap_or(usize::MAX)
    }

    /// The policy generation: starts at 0 and increases on every published
    /// change (default policy, namespaces, grants, pinholes opened, closed,
    /// swept after expiry or revoked, [`clear_all`](Self::clear_all)). The
    /// filter tags its cached verdicts with it, so no cached verdict outlives
    /// a change; a pinhole that expired but is not swept yet is caught by the
    /// filter's expiry check instead.
    pub fn generation(&self) -> u64 {
        self.snapshot.load().generation
    }

    /// The pinhole counters.
    pub fn pinhole_stats(&self) -> PinholeStats {
        self.pinholes.stats()
    }

    /// The engine clock.
    pub(crate) fn now(&self) -> Instant {
        (self.clock)()
    }

    pub(crate) fn is_pinhole_open(&self, id: PinholeId) -> bool {
        self.snapshot
            .load()
            .is_live(&ReplyDependency::Pinhole(id), || self.now())
    }

    pub(crate) fn close_pinhole(&self, id: PinholeId) {
        if !self.snapshot.load().pinholes.contains_key(&id) {
            return;
        }
        let closed = self.publish(|snapshot| snapshot.pinholes.remove(&id).is_some());
        if closed {
            PinholeCounters::add(&self.pinholes.closed, 1);
            debug!(pinhole = %id, "ACL pinhole closed");
        }
    }

    fn recheck_pinholes(&self, snapshot: &mut Snapshot) {
        let (namespace_removed, revoked) = snapshot.recheck_pinholes();
        PinholeCounters::add(&self.pinholes.namespace_removed, namespace_removed);
        PinholeCounters::add(&self.pinholes.revoked, revoked);
    }

    /// The current snapshot: one lock-free load.
    pub(crate) fn snapshot(&self) -> Guard<Arc<Snapshot>> {
        self.snapshot.load()
    }

    /// Apply `update` to a copy of the current snapshot and publish it.
    /// Expired pinholes are swept first.
    fn publish<T>(&self, update: impl FnOnce(&mut Snapshot) -> T) -> T {
        self.publish_swept(update).1
    }

    /// [`publish`](Self::publish), also returning how many expired pinholes
    /// were swept.
    fn publish_swept<T>(&self, update: impl FnOnce(&mut Snapshot) -> T) -> (u64, T) {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = Snapshot::clone(&self.snapshot.load());
        let generation = next.generation + 1;
        let expired = next.sweep_pinholes(self.now());
        PinholeCounters::add(&self.pinholes.expired, expired);
        let out = update(&mut next);
        next.generation = generation;
        next.rebypass();
        self.snapshot.store(Arc::new(next));
        (expired, out)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

/// Parse a test destination string like `"192.168.1.10:5432"`.
fn parse_test_dst(s: &str) -> Result<(IpAddr, u16), String> {
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
    Ok((ip, port))
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AclAction, AclRule, AclTest};

    fn make_policy(acls: Vec<AclRule>, tests: Vec<AclTest>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::new(),
            acls,
            tests,
        }
    }

    #[test]
    fn permit_all_allows_every_flow() {
        let e = CompiledPolicy::permit_all();
        let a = AccessRequest::from_ip(
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            443,
            Protocol::Tcp,
        );
        assert!(e.is_allowed(&a).allowed);
        let b = AccessRequest::from_ip(
            "10.0.0.112".parse().unwrap(),
            "10.0.0.111".parse().unwrap(),
            18888,
            Protocol::Udp,
        );
        assert!(e.is_allowed(&b).allowed);
    }

    fn accept_rule(src: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            src: src.iter().map(ToString::to_string).collect(),
            dst: dst.iter().map(ToString::to_string).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn req(src: &str, dst: &str, port: u16, proto: Protocol) -> AccessRequest {
        AccessRequest::from_ip(src.parse().unwrap(), dst.parse().unwrap(), port, proto)
    }

    // ── default deny ──────────────────────────────────────────────────────

    #[test]
    fn empty_policy_denies_everything() {
        let engine = CompiledPolicy::compile(make_policy(vec![], vec![])).unwrap();
        let d = engine.is_allowed(&req("10.0.0.1", "192.168.1.1", 80, Protocol::Tcp));
        assert!(!d.allowed);
        assert!(d.matched_rule_index.is_none());
    }

    // ── wildcard accept ───────────────────────────────────────────────────

    #[test]
    fn wildcard_rule_allows_any_connection() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 9999, Protocol::Udp))
                .allowed
        );
    }

    // ── CIDR src/dst matching ─────────────────────────────────────────────

    #[test]
    fn cidr_rule_allows_in_range_denies_outside() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("10.0.0.5", "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        // src outside range
        assert!(
            !engine
                .is_allowed(&req("10.0.1.5", "192.168.1.5", 80, Protocol::Tcp))
                .allowed
        );
        // dst outside range
        assert!(
            !engine
                .is_allowed(&req("10.0.0.5", "192.168.2.5", 80, Protocol::Tcp))
                .allowed
        );
        // wrong port
        assert!(
            !engine
                .is_allowed(&req("10.0.0.5", "192.168.1.5", 443, Protocol::Tcp))
                .allowed
        );
    }

    // ── host alias resolution ─────────────────────────────────────────────

    #[test]
    fn host_alias_resolves_correctly() {
        let mut policy = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["db:5432"], Some("tcp"))],
            vec![],
        );
        policy
            .hosts
            .insert("db".to_owned(), "192.168.1.10/32".to_owned());
        let engine = CompiledPolicy::compile(policy).unwrap();

        assert!(
            engine
                .is_allowed(&req("10.0.0.2", "192.168.1.10", 5432, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("10.0.0.2", "192.168.1.11", 5432, Protocol::Tcp))
                .allowed
        );
    }

    // ── protocol filtering ────────────────────────────────────────────────

    #[test]
    fn proto_tcp_rule_rejects_udp() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:80"], Some("tcp"))],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn no_proto_rule_matches_tcp_and_udp() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:53"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "8.8.8.8", 53, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "8.8.8.8", 53, Protocol::Udp))
                .allowed
        );
    }

    // ── port ranges and lists ─────────────────────────────────────────────

    #[test]
    fn port_range_rule() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:8000-8999"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn port_list_rule() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["*"], &["*:80,443"], None)],
            vec![],
        ))
        .unwrap();

        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 443, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 8080, Protocol::Tcp))
                .allowed
        );
    }

    // ── priority ordering ─────────────────────────────────────────────────

    #[test]
    fn first_matching_rule_wins() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![
                accept_rule(&["10.0.0.0/24"], &["*:80"], None),
                accept_rule(&["*"], &["*:*"], None),
            ],
            vec![],
        ))
        .unwrap();

        let d = engine.is_allowed(&req("10.0.0.5", "1.2.3.4", 80, Protocol::Tcp));
        assert!(d.allowed);
        assert_eq!(d.matched_rule_index, Some(0));

        let d2 = engine.is_allowed(&req("172.16.0.1", "1.2.3.4", 9090, Protocol::Tcp));
        assert!(d2.allowed);
        assert_eq!(d2.matched_rule_index, Some(1));
    }

    // ── built-in tests ────────────────────────────────────────────────────

    #[test]
    fn builtin_tests_pass_on_valid_policy() {
        let policy = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:80".to_owned(),
                    proto: None,
                    allow: true,
                },
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:443".to_owned(),
                    proto: None,
                    allow: false,
                },
            ],
        );
        assert!(CompiledPolicy::compile(policy).is_ok());
    }

    #[test]
    fn builtin_tests_can_validate_udp_policy() {
        let policy = make_policy(
            vec![accept_rule(
                &["10.0.0.0/24"],
                &["192.168.1.0/24:53"],
                Some("udp"),
            )],
            vec![
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("udp".to_owned()),
                    allow: true,
                },
                AclTest {
                    src: "10.0.0.2".to_owned(),
                    dst: "192.168.1.5:53".to_owned(),
                    proto: Some("tcp".to_owned()),
                    allow: false,
                },
            ],
        );
        assert!(CompiledPolicy::compile(policy).is_ok());
    }

    #[test]
    fn builtin_tests_fail_returns_error() {
        let policy = make_policy(
            vec![],
            vec![AclTest {
                src: "10.0.0.2".to_owned(),
                dst: "192.168.1.5:80".to_owned(),
                proto: None,
                allow: true, // expects allow, but empty policy denies
            }],
        );
        let err = CompiledPolicy::compile(policy).unwrap_err();
        assert!(matches!(err, crate::Error::TestsFailed { count: 1 }));
    }

    // ── invalid policy ────────────────────────────────────────────────────

    #[test]
    fn invalid_host_alias_in_rule_returns_error() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["does-not-exist"], &["*:80"], None)],
            vec![],
        ));
        assert!(engine.is_err());
    }

    #[test]
    fn invalid_cidr_in_hosts_returns_error() {
        let mut policy = make_policy(vec![], vec![]);
        policy
            .hosts
            .insert("bad".to_owned(), "not-a-cidr".to_owned());
        assert!(CompiledPolicy::compile(policy).is_err());
    }

    // ── subject-key source matching ───────────────────────────────────────

    #[test]
    fn source_class_and_anchor_strings() {
        let key = [0xABu8; 32];
        let wg = SourceAssertion::WgPeerKey { pubkey: key };
        assert_eq!(wg.source_class(), "client-wg-key");
        assert_eq!(wg.source_anchor(), format!("key:{}", "ab".repeat(32)));
        let t = SourceAssertion::Terminate {
            binding: TerminateBinding {
                ip: Some("10.0.0.5".parse().unwrap()),
                anchor: "10.0.0.5".into(),
            },
        };
        assert_eq!(t.source_class(), "terminate-binding");
        assert_eq!(t.source_anchor(), "10.0.0.5");
        let e = SourceAssertion::External { idp: "okta".into() };
        assert_eq!(e.source_class(), "external-idp");
        assert_eq!(e.source_anchor(), "idp:okta");
    }

    #[test]
    fn key_principal_rule_matches_wg_peer_key_only() {
        let key = [7u8; 32];
        let key_src = format!("key:{}", "07".repeat(32));
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&[&key_src], &["*:*"], None)],
            vec![],
        ))
        .unwrap();

        // A request from the matching WG key is accepted.
        let allowed = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            key,
            "0.0.0.0".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(allowed.allowed, "matching client-wg-key must be accepted");

        // A different key is denied (default-deny).
        let other = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            [9u8; 32],
            "0.0.0.0".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(!other.allowed, "a non-authorised key must be denied");

        // An IP/terminate source never matches a key principal.
        let ip_src = engine.is_allowed(&req("10.0.0.2", "10.0.0.2", 80, Protocol::Tcp));
        assert!(
            !ip_src.allowed,
            "a CIDR/terminate source must not match a key rule"
        );
    }

    #[test]
    fn cidr_rule_does_not_match_a_keyed_source() {
        let engine = CompiledPolicy::compile(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        // A WgPeerKey source carries no IP → a CIDR rule cannot match it.
        let d = engine.is_allowed(&AccessRequest::with_wg_peer_key(
            [1u8; 32],
            "10.0.0.7".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            80,
            Protocol::Tcp,
        ));
        assert!(
            !d.allowed,
            "CIDR rule must not match a key-only source even with a legacy src_ip"
        );
    }

    // ── AclEngine (shared, atomic reload) ─────────────────────────────────

    fn port_policy(port: u16) -> AclPolicy {
        make_policy(
            vec![accept_rule(&["*"], &[&format!("*:{port}")], None)],
            vec![],
        )
    }

    #[test]
    fn engine_is_fail_closed_before_first_load() {
        let engine = AclEngine::new();
        assert!(!engine.is_loaded());
        assert!(engine.policy().is_none());
        let d = engine.is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp));
        assert!(!d.allowed);
        assert!(d.matched_rule_index.is_none());
        assert_eq!(d.reason, "denied: no policy loaded");
        assert!(!AclEngine::default().is_loaded());
    }

    #[test]
    fn engine_load_then_allow() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        assert!(engine.is_loaded());
        let d = engine.is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp));
        assert!(d.allowed);
        assert_eq!(d.matched_rule_index, Some(0));
        assert!(
            !engine
                .is_allowed(&req("10.0.0.1", "10.0.0.2", 443, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn engine_failed_reload_keeps_previous_policy() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        let before = engine.policy().unwrap();

        // Built-in test failure.
        let failing = make_policy(
            vec![],
            vec![AclTest {
                src: "10.0.0.2".to_owned(),
                dst: "192.168.1.5:80".to_owned(),
                proto: None,
                allow: true,
            }],
        );
        assert!(matches!(
            engine.load(failing),
            Err(crate::Error::TestsFailed { count: 1 })
        ));
        // Compile failure.
        assert!(
            engine
                .load(make_policy(
                    vec![accept_rule(&["does-not-exist"], &["*:80"], None)],
                    vec![],
                ))
                .is_err()
        );

        let after = engine.policy().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert!(
            engine
                .is_allowed(&req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn engine_store_and_clear() {
        let engine = AclEngine::new();
        engine.store(Arc::new(CompiledPolicy::permit_all()));
        assert!(
            engine
                .is_allowed(&req("1.2.3.4", "5.6.7.8", 9, Protocol::Udp))
                .allowed
        );

        engine.clear();
        assert!(!engine.is_loaded());
        let d = engine.is_allowed(&req("1.2.3.4", "5.6.7.8", 9, Protocol::Udp));
        assert!(!d.allowed);
        assert_eq!(d.reason, "denied: no policy loaded");
    }

    #[test]
    fn engine_concurrent_readers_during_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Policy A accepts port 80 by rule 0; policy B accepts it by rule 1.
        // Readers must only ever observe one of the two whole policies (or
        // the fail-closed state while cleared), never a mix.
        let policy_a = port_policy(80);
        let policy_b = make_policy(
            vec![
                accept_rule(&["*"], &["*:443"], None),
                accept_rule(&["*"], &["*:80"], None),
            ],
            vec![],
        );
        let engine = AclEngine::new();
        engine.load(policy_a.clone()).unwrap();
        let stop = AtomicBool::new(false);
        let request = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);

        std::thread::scope(|s| {
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        let mut seen = 0u64;
                        loop {
                            let d = engine.is_allowed(&request);
                            if let Some(idx) = d.matched_rule_index {
                                assert!(d.allowed);
                                assert!(idx <= 1, "unexpected rule {idx}");
                                assert_eq!(d.reason, format!("accepted by rule {idx}"));
                            } else {
                                assert!(!d.allowed);
                                assert_eq!(d.reason, "denied: no policy loaded");
                            }
                            // A snapshot stays stable across evaluations.
                            if let Some(p) = engine.policy() {
                                let first = p.is_allowed(&request).matched_rule_index;
                                let second = p.is_allowed(&request).matched_rule_index;
                                assert_eq!(first, second);
                            }
                            seen += 1;
                            if stop.load(Ordering::Relaxed) {
                                break seen;
                            }
                        }
                    })
                })
                .collect();

            for i in 0..2000 {
                match i % 3 {
                    0 => engine.load(policy_b.clone()).unwrap(),
                    1 => engine.load(policy_a.clone()).unwrap(),
                    _ => engine.clear(),
                }
            }
            stop.store(true, Ordering::Relaxed);
            for reader in readers {
                assert!(reader.join().unwrap() > 0);
            }
        });
    }

    // ── namespaces and grants ─────────────────────────────────────────────

    use crate::namespace::{NamespaceMember, OutboundRule};

    fn anchor(byte: u8) -> String {
        wg_peer_anchor(&[byte; 32])
    }

    fn key_req(byte: u8, dst: &str, port: u16, proto: Protocol) -> AccessRequest {
        AccessRequest::with_wg_peer_key(
            [byte; 32],
            "fd00::ff".parse().unwrap(),
            dst.parse().unwrap(),
            port,
            proto,
        )
    }

    /// A namespace with members `(key byte, address)` accepting `port` from anyone.
    fn ns(members: &[(u8, &str)], port: u16) -> NamespacePolicy {
        NamespacePolicy {
            members: members
                .iter()
                .map(|(byte, address)| NamespaceMember {
                    principal: anchor(*byte),
                    addresses: vec![address.parse().unwrap()],
                })
                .collect(),
            policy: port_policy(port),
            ..NamespacePolicy::default()
        }
    }

    fn namespace_ptr(engine: &AclEngine, id: &str) -> Arc<CompiledNamespace> {
        Arc::clone(engine.snapshot().namespaces.get(id).unwrap())
    }

    #[test]
    fn store_replace_and_remove_one_namespace() {
        let engine = AclEngine::new();
        assert!(!engine.is_loaded());
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 80))
            .unwrap();
        engine
            .store_namespace("quick", ns(&[(2, "fd00::2")], 22))
            .unwrap();
        assert!(engine.is_loaded());
        assert!(engine.policy().is_none());
        assert_eq!(
            engine.namespaces(),
            vec![NamespaceId::from("nsd:a"), NamespaceId::from("quick")]
        );
        let quick = namespace_ptr(&engine, "quick");

        // Replace nsd:a: quick is untouched.
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1"), (3, "fd00::3")], 443))
            .unwrap();
        assert!(Arc::ptr_eq(&quick, &namespace_ptr(&engine, "quick")));
        assert!(
            engine
                .evaluate(&key_req(1, "fd00::99", 443, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(1, "fd00::99", 80, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .evaluate(&key_req(2, "fd00::99", 22, Protocol::Tcp))
                .allowed
        );
        assert_eq!(
            engine.memberships(&anchor(3)),
            vec![NamespaceId::from("nsd:a")]
        );

        // Remove nsd:a: its members leave, quick stays.
        assert!(engine.remove_namespace("nsd:a"));
        assert!(!engine.remove_namespace("nsd:a"));
        assert!(Arc::ptr_eq(&quick, &namespace_ptr(&engine, "quick")));
        assert_eq!(engine.namespaces(), vec![NamespaceId::from("quick")]);
        assert_eq!(engine.memberships(&anchor(1)), Vec::<NamespaceId>::new());
        // A former member falls back to the (unloaded) default policy.
        let d = engine.evaluate(&key_req(1, "fd00::99", 443, Protocol::Tcp));
        assert_eq!(d.reason, "denied: no policy loaded");

        assert!(engine.remove_namespace("quick"));
        assert!(!engine.is_loaded());
    }

    #[test]
    fn failed_store_namespace_keeps_previous_state() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 80))
            .unwrap();
        let before = namespace_ptr(&engine, "nsd:a");

        let mut failing = ns(&[(1, "fd00::1")], 443);
        failing.policy.tests.push(AclTest {
            src: "10.0.0.2".to_owned(),
            dst: "192.168.1.5:80".to_owned(),
            proto: None,
            allow: true,
        });
        assert!(matches!(
            engine.store_namespace("nsd:a", failing.clone()),
            Err(crate::Error::TestsFailed { count: 1 })
        ));
        assert!(engine.store_namespace("nsd:new", failing).is_err());
        let mut bad_outbound = ns(&[(1, "fd00::1")], 443);
        bad_outbound.outbound = Some(vec![OutboundRule {
            proto: Some("icmp".to_owned()),
            ports: "*".to_owned(),
        }]);
        assert!(matches!(
            engine.store_namespace("nsd:a", bad_outbound.clone()),
            Err(crate::Error::InvalidPolicy(_))
        ));
        bad_outbound.outbound = Some(vec![OutboundRule {
            proto: None,
            ports: "9-1".to_owned(),
        }]);
        assert!(engine.store_namespace("nsd:a", bad_outbound).is_err());

        assert!(Arc::ptr_eq(&before, &namespace_ptr(&engine, "nsd:a")));
        assert_eq!(engine.namespaces(), vec![NamespaceId::from("nsd:a")]);
        assert!(
            engine
                .evaluate(&key_req(1, "fd00::99", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn rules_of_all_namespaces_of_a_principal_apply() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 80))
            .unwrap();
        engine
            .store_namespace("quick", ns(&[(1, "fd00::1"), (2, "fd00::2")], 22))
            .unwrap();
        assert_eq!(
            engine.memberships(&anchor(1)),
            vec![NamespaceId::from("nsd:a"), NamespaceId::from("quick")]
        );
        let to_local = |port| engine.evaluate(&key_req(1, "fd00::99", port, Protocol::Tcp));
        let d = to_local(80);
        assert!(d.allowed);
        assert_eq!(d.reason, "accepted by namespace nsd:a rule 0");
        let d = to_local(22);
        assert!(d.allowed);
        assert_eq!(d.reason, "accepted by namespace quick rule 0");
        assert!(!to_local(443).allowed);
        // Towards peer 2 only the shared namespace applies.
        assert!(
            engine
                .evaluate(&key_req(1, "fd00::2", 22, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(1, "fd00::2", 80, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn destination_resolves_by_longest_prefix() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        engine
            .store_namespace("nsd:b", ns(&[(2, "fd00::/64")], 22))
            .unwrap();
        engine
            .store_namespace("nsd:c", ns(&[(3, "fd00::3")], 22))
            .unwrap();
        // fd00::3 is peer 3 (/128), not peer 2 (/64).
        let d = engine.evaluate(&key_req(1, "fd00::3", 22, Protocol::Tcp));
        assert_eq!(d.reason, "denied: cross namespace");
        assert!(
            engine
                .evaluate(&key_req(3, "fd00::3", 22, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(3, "fd00::4", 22, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .evaluate(&key_req(2, "fd00::4", 22, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn app_namespaces_never_widen_permissions() {
        let engine = AclEngine::new();
        assert!(matches!(
            engine.store_namespace("app:s1", ns(&[(1, "fd00::1")], 22)),
            Err(crate::Error::InvalidPolicy(_))
        ));
        let mut pinholes = ns(&[(1, "fd00::1")], 22);
        pinholes.policy = AclPolicy::default();
        pinholes.allow_app_pinholes.insert("transfer".to_owned());
        assert!(matches!(
            engine.store_namespace("app:s1", pinholes.clone()),
            Err(crate::Error::InvalidPolicy(_))
        ));
        // Allowed on a non-app namespace.
        engine.store_namespace("nsd:a", pinholes).unwrap();
        // Outbound rules are allowed on an app namespace.
        let mut session = ns(&[(2, "fd00::2")], 22);
        session.policy = AclPolicy::default();
        session.outbound = Some(Vec::new());
        engine.store_namespace("app:s1", session).unwrap();
        assert_eq!(
            engine.memberships(&anchor(2)),
            vec![NamespaceId::from("app:s1")]
        );
        // A member only of an app namespace gets nothing, even with a
        // permissive default policy.
        engine.store(Arc::new(CompiledPolicy::permit_all()));
        assert!(
            !engine
                .evaluate(&key_req(2, "fd00::99", 22, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn principals_in_no_namespace_use_the_default_policy() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        for request in [
            req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp),
            req("10.0.0.1", "fd00::1", 22, Protocol::Tcp),
            key_req(2, "fd00::1", 80, Protocol::Tcp),
            key_req(2, "fd00::1", 22, Protocol::Tcp),
        ] {
            let evaluated = engine.evaluate(&request);
            let default = engine.is_allowed(&request);
            assert_eq!(evaluated.allowed, default.allowed);
            assert_eq!(evaluated.matched_rule_index, default.matched_rule_index);
            assert_eq!(evaluated.reason, default.reason);
        }
        // is_allowed ignores namespaces, even for members.
        assert!(
            !engine
                .is_allowed(&key_req(1, "fd00::99", 22, Protocol::Tcp))
                .allowed
        );
        assert!(
            engine
                .evaluate(&key_req(1, "fd00::99", 22, Protocol::Tcp))
                .allowed
        );
        // clear unloads only the default policy.
        engine.clear();
        assert!(engine.is_loaded());
        assert!(
            engine
                .evaluate(&key_req(1, "fd00::99", 22, Protocol::Tcp))
                .allowed
        );
    }

    #[test]
    fn grants_are_directed_and_validated() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        engine
            .store_namespace("nsd:b", ns(&[(2, "fd00::2")], 22))
            .unwrap();
        let grant = Grant {
            from: GrantEnd::Namespace("nsd:a".into()),
            to: GrantEnd::Peer(anchor(2)),
            proto: Some("udp".to_owned()),
            ports: Some("5000-5010".to_owned()),
        };
        for (proto, ports) in [(Some("icmp"), None), (None, Some("x")), (None, Some("9-1"))] {
            let bad = Grant {
                proto: proto.map(str::to_owned),
                ports: ports.map(str::to_owned),
                ..grant.clone()
            };
            assert!(matches!(
                engine.store_grant("bad", bad),
                Err(crate::Error::InvalidPolicy(_))
            ));
        }
        assert_eq!(engine.grants(), Vec::new());

        assert_eq!(
            engine
                .evaluate(&key_req(1, "fd00::2", 5005, Protocol::Udp))
                .reason,
            "denied: cross namespace"
        );
        engine.store_grant("g1", grant.clone()).unwrap();
        assert_eq!(engine.grants(), vec![("g1".to_owned(), grant)]);
        let d = engine.evaluate(&key_req(1, "fd00::2", 5005, Protocol::Udp));
        assert!(d.allowed);
        assert_eq!(d.reason, "accepted by grant g1");
        assert_eq!(d.matched_rule_index, None);
        assert!(
            !engine
                .evaluate(&key_req(1, "fd00::2", 5011, Protocol::Udp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(1, "fd00::2", 5005, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(2, "fd00::1", 5005, Protocol::Udp))
                .allowed
        );

        assert!(engine.remove_grant("g1"));
        assert_eq!(engine.grants(), Vec::new());
        assert!(
            !engine
                .evaluate(&key_req(1, "fd00::2", 5005, Protocol::Udp))
                .allowed
        );
    }

    #[test]
    fn outbound_restriction_needs_every_namespace() {
        let engine = AclEngine::new();
        let mut restricted = ns(&[(1, "fd00::1"), (2, "fd00::2")], 22);
        restricted.outbound = Some(Vec::new());
        engine.store_namespace("nsd:a", restricted).unwrap();
        engine
            .store_namespace("nsd:b", ns(&[(2, "fd00::2")], 22))
            .unwrap();
        let snapshot = engine.snapshot();
        assert!(snapshot.has_outbound_restrictions());
        assert!(
            snapshot
                .membership(&anchor(1))
                .unwrap()
                .outbound_restricted()
        );
        assert!(
            !snapshot
                .membership(&anchor(2))
                .unwrap()
                .outbound_restricted()
        );
        assert!(snapshot.membership(&anchor(3)).is_none());
        drop(snapshot);
        engine.remove_namespace("nsd:a");
        assert!(!engine.snapshot().has_outbound_restrictions());
    }

    #[test]
    fn engine_concurrent_readers_during_store_namespace() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Version A accepts port 80 by rule 0, version B by rule 1; the other
        // namespace never changes. Readers only ever see whole versions.
        let ns_a = ns(&[(1, "fd00::1")], 80);
        let mut ns_b = ns(&[(1, "fd00::1")], 443);
        ns_b.policy.acls.push(accept_rule(&["*"], &["*:80"], None));
        let engine = AclEngine::new();
        engine.store_namespace("nsd:a", ns_a.clone()).unwrap();
        engine
            .store_namespace("quick", ns(&[(2, "fd00::2")], 22))
            .unwrap();
        let stop = AtomicBool::new(false);
        let request = key_req(1, "fd00::99", 80, Protocol::Tcp);
        let other = key_req(2, "fd00::99", 22, Protocol::Tcp);

        std::thread::scope(|s| {
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        let mut seen = 0u64;
                        loop {
                            let d = engine.evaluate(&request);
                            if let Some(idx) = d.matched_rule_index {
                                assert!(d.allowed);
                                assert!(idx <= 1, "unexpected rule {idx}");
                                assert_eq!(
                                    d.reason,
                                    format!("accepted by namespace nsd:a rule {idx}")
                                );
                            } else {
                                assert!(!d.allowed);
                                assert_eq!(d.reason, "denied: no policy loaded");
                            }
                            assert!(engine.evaluate(&other).allowed);
                            seen += 1;
                            if stop.load(Ordering::Relaxed) {
                                break seen;
                            }
                        }
                    })
                })
                .collect();

            for i in 0..2000 {
                match i % 3 {
                    0 => engine.store_namespace("nsd:a", ns_b.clone()).unwrap(),
                    1 => engine.store_namespace("nsd:a", ns_a.clone()).unwrap(),
                    _ => assert!(engine.remove_namespace("nsd:a")),
                }
            }
            stop.store(true, Ordering::Relaxed);
            for reader in readers {
                assert!(reader.join().unwrap() > 0);
            }
        });
    }

    #[test]
    fn grants_cannot_name_app_namespaces() {
        let engine = AclEngine::new();
        for (from, to) in [
            (
                GrantEnd::Namespace("app:s1".into()),
                GrantEnd::Peer(anchor(2)),
            ),
            (
                GrantEnd::Peer(anchor(1)),
                GrantEnd::Namespace("app:s1".into()),
            ),
        ] {
            let grant = Grant {
                from,
                to,
                proto: None,
                ports: None,
            };
            assert!(matches!(
                engine.store_grant("g", grant),
                Err(crate::Error::InvalidPolicy(_))
            ));
        }
        assert_eq!(engine.grants(), Vec::new());
    }

    // ── pinholes ──────────────────────────────────────────────────────────

    /// An engine whose clock is moved by hand, with the clock handle.
    fn manual_engine() -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&clock);
        let engine = AclEngine::with_clock(move || *handle.lock().unwrap());
        (Arc::new(engine), clock)
    }

    fn advance(clock: &Mutex<Instant>, secs: u64) {
        *clock.lock().unwrap() += Duration::from_secs(secs);
    }

    fn now(clock: &Mutex<Instant>) -> Instant {
        *clock.lock().unwrap()
    }

    /// A namespace of `members` without rules, allowing pinholes of `kinds`.
    fn source(members: &[(u8, &str)], kinds: &[&str]) -> NamespacePolicy {
        NamespacePolicy {
            policy: AclPolicy::default(),
            allow_app_pinholes: kinds.iter().map(ToString::to_string).collect(),
            ..ns(members, 0)
        }
    }

    /// An app namespace of `members`.
    fn app(members: &[(u8, &str)]) -> NamespacePolicy {
        source(members, &[])
    }

    fn spec(peer: u8, port: u16, expires_at: Instant) -> PinholeSpec {
        PinholeSpec {
            peer: anchor(peer),
            kind: "transfer".to_owned(),
            protocol: Protocol::Tcp,
            direction: Direction::Inbound,
            dst_port: port,
            expires_at,
        }
    }

    use std::time::Duration;

    #[test]
    fn open_pinhole_errors() {
        let (engine, clock) = manual_engine();
        engine
            .store_namespace(
                "nsd:a",
                source(&[(1, "fd00::1"), (3, "fd00::3")], &["chat"]),
            )
            .unwrap();
        engine
            .store_namespace("nsd:b", source(&[(3, "fd00::3")], &["transfer"]))
            .unwrap();
        engine
            .store_namespace(
                "app:s1",
                app(&[(1, "fd00::1"), (2, "fd00::2"), (3, "fd00::3")]),
            )
            .unwrap();
        let later = now(&clock) + Duration::from_secs(60);
        let open = |ns: &str, spec| engine.open_pinhole(ns, spec).map(|guard| guard.id());

        assert_eq!(
            open("app:none", spec(2, 80, later)),
            Err(PinholeError::UnknownNamespace)
        );
        assert_eq!(
            open("nsd:a", spec(1, 80, later)),
            Err(PinholeError::NotAppNamespace)
        );
        assert_eq!(
            open("app:s1", spec(4, 80, later)),
            Err(PinholeError::NotMember)
        );
        assert_eq!(
            open("app:s1", spec(2, 80, now(&clock))),
            Err(PinholeError::Expired)
        );
        // Peer 1's only source namespace does not allow "transfer".
        assert_eq!(
            open("app:s1", spec(1, 80, later)),
            Err(PinholeError::NotPermitted)
        );
        assert_eq!(engine.pinhole_stats().not_permitted, 1);
        assert!(engine.snapshot().pinholes.is_empty());
        // Peer 3 is permitted by one of its source namespaces; peer 2 is a
        // session-only peer.
        let guard = engine.open_pinhole("app:s1", spec(3, 80, later)).unwrap();
        let session = engine.open_pinhole("app:s1", spec(2, 80, later)).unwrap();
        assert_ne!(guard.id(), session.id());
        assert!(guard.is_open() && session.is_open());
        assert_eq!(
            engine.pinhole_stats(),
            PinholeStats {
                opened: 2,
                not_permitted: 1,
                ..PinholeStats::default()
            }
        );
    }

    #[test]
    fn guard_closes_and_evaluation_follows() {
        let (engine, clock) = manual_engine();
        engine
            .store_namespace("app:s1", app(&[(2, "fd00::2")]))
            .unwrap();
        let later = now(&clock) + Duration::from_secs(60);
        let request = key_req(2, "fd00::99", 80, Protocol::Tcp);
        assert!(!engine.evaluate(&request).allowed);

        let guard = engine.open_pinhole("app:s1", spec(2, 80, later)).unwrap();
        let d = engine.evaluate(&request);
        assert!(d.allowed);
        assert_eq!(d.reason, format!("accepted by pinhole {}", guard.id()));
        // Only that port, protocol and direction, and only to the local node.
        assert!(
            !engine
                .evaluate(&key_req(2, "fd00::99", 81, Protocol::Tcp))
                .allowed
        );
        assert!(
            !engine
                .evaluate(&key_req(2, "fd00::99", 80, Protocol::Udp))
                .allowed
        );
        engine
            .store_namespace("nsd:x", ns(&[(5, "fd00::5")], 22))
            .unwrap();
        assert!(
            !engine
                .evaluate(&key_req(2, "fd00::5", 80, Protocol::Tcp))
                .allowed
        );

        guard.close();
        assert!(!engine.evaluate(&request).allowed);
        assert_eq!(engine.pinhole_stats().closed, 1);
    }

    #[test]
    fn pinholes_expire_with_the_engine_clock() {
        let (engine, clock) = manual_engine();
        engine
            .store_namespace("app:s1", app(&[(2, "fd00::2")]))
            .unwrap();
        let request = key_req(2, "fd00::99", 80, Protocol::Tcp);
        let short = engine
            .open_pinhole("app:s1", spec(2, 80, now(&clock) + Duration::from_secs(10)))
            .unwrap();
        let long = engine
            .open_pinhole("app:s1", spec(2, 81, now(&clock) + Duration::from_secs(30)))
            .unwrap();
        assert_eq!(engine.expire_pinholes(), 0);

        advance(&clock, 10);
        // Absent immediately, swept by the evaluation that sees it.
        assert!(!short.is_open());
        assert!(!engine.evaluate(&request).allowed);
        assert_eq!(engine.pinhole_stats().expired, 1);
        assert_eq!(engine.expire_pinholes(), 0);
        assert!(long.is_open());

        // Swept by the next mutation.
        advance(&clock, 20);
        engine.clear();
        assert_eq!(engine.pinhole_stats().expired, 2);
        assert_eq!(engine.expire_pinholes(), 0);

        // Dropping guards of expired pinholes counts nothing more.
        drop((short, long));
        assert_eq!(
            engine.pinhole_stats(),
            PinholeStats {
                opened: 2,
                expired: 2,
                ..PinholeStats::default()
            }
        );

        let third = engine
            .open_pinhole("app:s1", spec(2, 80, now(&clock) + Duration::from_secs(5)))
            .unwrap();
        advance(&clock, 5);
        assert_eq!(engine.expire_pinholes(), 1);
        assert!(!third.is_open());
        assert_eq!(engine.pinhole_stats().expired, 3);
    }

    #[test]
    fn namespace_changes_close_pinholes() {
        let (engine, clock) = manual_engine();
        let later = now(&clock) + Duration::from_secs(60);
        engine
            .store_namespace("nsd:a", source(&[(1, "fd00::1")], &["transfer"]))
            .unwrap();
        engine
            .store_namespace("nsd:b", source(&[(3, "fd00::3")], &["transfer"]))
            .unwrap();
        engine
            .store_namespace("app:s1", app(&[(1, "fd00::1"), (2, "fd00::2")]))
            .unwrap();
        engine
            .store_namespace("app:s2", app(&[(2, "fd00::2"), (3, "fd00::3")]))
            .unwrap();

        // Removing the app namespace closes its pinholes only.
        let s1 = engine.open_pinhole("app:s1", spec(2, 80, later)).unwrap();
        let s2 = engine.open_pinhole("app:s2", spec(2, 80, later)).unwrap();
        assert!(engine.remove_namespace("app:s1"));
        assert!(!s1.is_open());
        assert!(s2.is_open());
        assert_eq!(engine.pinhole_stats().namespace_removed, 1);

        // The app namespace dropping the peer revokes its pinhole.
        engine
            .store_namespace("app:s1", app(&[(1, "fd00::1"), (2, "fd00::2")]))
            .unwrap();
        let peer1 = engine.open_pinhole("app:s1", spec(1, 80, later)).unwrap();
        engine
            .store_namespace("app:s1", app(&[(2, "fd00::2")]))
            .unwrap();
        assert!(!peer1.is_open());
        assert_eq!(engine.pinhole_stats().revoked, 1);

        // The source namespace no longer allowing the kind revokes it.
        let peer3 = engine.open_pinhole("app:s2", spec(3, 80, later)).unwrap();
        engine
            .store_namespace("nsd:b", source(&[(3, "fd00::3")], &["transfer", "chat"]))
            .unwrap();
        assert!(peer3.is_open());
        engine
            .store_namespace("nsd:b", source(&[(3, "fd00::3")], &["chat"]))
            .unwrap();
        assert!(!peer3.is_open());

        // Dropped from its only source namespace: revoked, although a
        // session-only peer could open a new one.
        engine
            .store_namespace("nsd:b", source(&[(3, "fd00::3")], &["transfer"]))
            .unwrap();
        let peer3 = engine.open_pinhole("app:s2", spec(3, 80, later)).unwrap();
        engine
            .store_namespace("nsd:b", source(&[(4, "fd00::4")], &["transfer"]))
            .unwrap();
        assert!(!peer3.is_open());
        assert!(s2.is_open());
        assert_eq!(
            engine.pinhole_stats(),
            PinholeStats {
                opened: 5,
                namespace_removed: 1,
                revoked: 3,
                ..PinholeStats::default()
            }
        );
        drop((s1, s2, peer1, peer3));
        assert_eq!(engine.pinhole_stats().closed, 1);
    }

    #[test]
    fn guard_outliving_its_engine_is_harmless() {
        let (engine, clock) = manual_engine();
        engine
            .store_namespace("app:s1", app(&[(2, "fd00::2")]))
            .unwrap();
        let guard = engine
            .open_pinhole("app:s1", spec(2, 80, now(&clock) + Duration::from_secs(5)))
            .unwrap();
        drop(engine);
        assert!(!guard.is_open());
        guard.close();
    }
}
