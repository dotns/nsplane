//! The shared [`AclEngine`] with its default rules and their policy state,
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
    matcher::{parse_ports, parse_protocol, protocols},
    namespace::{Grant, GrantEnd, NamespaceId, NamespaceKind, NamespacePolicy},
    net::{IpNet, Protocol},
    pinhole::{
        Direction, Pinhole, PinholeCounters, PinholeError, PinholeGuard, PinholeId, PinholeSpec,
        PinholeStats,
    },
    policy::{AclPolicy, AclTest},
    reasons,
    rules::{
        Decision, Flow, Label, LabelSet, Matched, NotInstalled, PolicyState, PortSet, Protocols,
        RuleId, RuleSet, Transport,
    },
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A failed built-in policy test.
#[derive(Debug, Clone)]
pub struct AclTestFailure {
    /// The test that failed.
    pub test: AclTest,
    /// Why it failed.
    pub reason: String,
}

// ── Evaluation ────────────────────────────────────────────────────────────────

/// What a reply allowance depends on. An allowance whose dependency is gone
/// from the current [`Snapshot`] (or, for a pinhole, expired) is revoked on
/// its next lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReplyDependency {
    /// A directed grant, by id.
    Grant(Arc<str>),
    /// A pinhole.
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

/// The outcome of evaluating a new inbound flow, borrowing the snapshot (no
/// rule ID is cloned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Evaluation<'s> {
    /// Accepted by a default rule (`namespace: None`) or a namespace rule.
    Rule {
        namespace: Option<&'s NamespaceId>,
        id: &'s RuleId,
    },
    /// Accepted by the directed grant with this id.
    Grant(&'s RuleId),
    /// Accepted by an inbound pinhole.
    Pinhole(PinholeId),
    /// Accepted by [`NotInstalled::Accept`].
    NotInstalled,
    /// Nothing accepts the flow, but an expired inbound pinhole matched:
    /// denied with [`reasons::DENIED`], and the caller sweeps expired
    /// pinholes.
    PinholeExpired,
    /// Denied with this reason.
    Deny(&'static str),
}

impl Evaluation<'_> {
    /// The reply dependency of an accepted flow.
    pub(crate) fn dependency(&self) -> Option<ReplyDependency> {
        match self {
            Self::Grant(id) => Some(ReplyDependency::Grant(id.shared())),
            Self::Pinhole(id) => Some(ReplyDependency::Pinhole(*id)),
            Self::Rule { .. } | Self::NotInstalled | Self::PinholeExpired | Self::Deny(_) => None,
        }
    }

    fn log(&self, flow: &Flow) {
        let (proto, port) = match flow.transport {
            Transport::Tcp { dst_port, .. } => (6, Some(dst_port)),
            Transport::Udp { dst_port, .. } => (17, Some(dst_port)),
            Transport::Icmp { .. } if flow.src.is_ipv4() => (1, None),
            Transport::Icmp { .. } => (58, None),
            Transport::Ip(number) => (number, None),
        };
        let (src, dst) = (flow.src, flow.dst);
        // `debug!`, not `warn!`: the data path evaluates new flows, so a
        // warning per denied flow would flood the log.
        match self {
            Self::Rule { namespace, id } => {
                debug!(%src, %dst, proto, ?port, rule = %id, namespace = ?namespace.map(NamespaceId::as_str), "ACL accept");
            }
            Self::Grant(id) => debug!(%src, %dst, proto, ?port, grant = %id, "ACL accept"),
            Self::Pinhole(id) => debug!(%src, %dst, proto, ?port, pinhole = %id, "ACL accept"),
            Self::NotInstalled => {
                debug!(%src, %dst, proto, ?port, reason = "not installed", "ACL accept");
            }
            Self::PinholeExpired => {
                debug!(%src, %dst, proto, ?port, reason = reasons::DENIED, "ACL deny");
            }
            Self::Deny(reason) => debug!(%src, %dst, proto, ?port, reason, "ACL deny"),
        }
    }
}

// ── Namespaces, grants and the engine snapshot ────────────────────────────────

/// Compile string protocol and ports (outbound rules, grants); `Err` holds
/// the reason.
fn compile_ports(proto: Option<&str>, ports: Option<&str>) -> Result<Protocols, String> {
    let proto = proto
        .map(parse_protocol)
        .transpose()
        .map_err(|e| format!("proto: {e}"))?;
    let ports = ports
        .map_or(Ok(PortSet::Any), parse_ports)
        .map_err(|e| format!("ports: {e}"))?;
    Protocols::compile(&protocols(proto, ports))
}

#[derive(Debug)]
struct CompiledNamespace {
    source: NamespacePolicy,
    rules: RuleSet,
    /// `None`: outbound to the members is unrestricted.
    outbound: Option<Vec<Protocols>>,
}

impl CompiledNamespace {
    fn is_rules(&self) -> bool {
        self.source.kind == NamespaceKind::Rules
    }

    fn compile(id: &NamespaceId, source: NamespacePolicy) -> Result<Self, Error> {
        let invalid = |reason: String| Error::InvalidNamespace {
            id: id.clone(),
            reason,
        };
        if source.kind == NamespaceKind::Pinholes
            && (!source.policy.acls.is_empty() || !source.pinhole_kinds.is_empty())
        {
            return Err(invalid(
                "a pinhole namespace cannot have accept rules or pinhole kinds".to_owned(),
            ));
        }
        let rules = RuleSet::from_document(source.policy.clone())?;
        let outbound = source
            .outbound
            .as_ref()
            .map(|rules| {
                rules
                    .iter()
                    .enumerate()
                    .map(|(i, rule)| {
                        compile_ports(rule.proto.as_deref(), Some(&rule.ports))
                            .map_err(|e| invalid(format!("outbound rule {i} {e}")))
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

/// One end of a compiled grant.
#[derive(Debug)]
enum End {
    Label(Label),
    Namespace(NamespaceId),
}

impl End {
    fn new(end: &GrantEnd) -> Self {
        match end {
            GrantEnd::Label(label) => Self::Label(label.clone()),
            GrantEnd::Namespace(id) => Self::Namespace(id.clone()),
        }
    }

    /// Whether the source end matches a source with `labels`.
    fn matches_source(&self, labels: &LabelSet, membership: &Membership) -> bool {
        match self {
            Self::Label(label) => labels.contains(label),
            Self::Namespace(id) => membership.has_rules(id),
        }
    }

    /// Whether the destination end matches the member label `owner`.
    fn matches_owner(&self, owner: &Label, membership: &Membership) -> bool {
        match self {
            Self::Label(label) => label == owner,
            Self::Namespace(id) => membership.has_rules(id),
        }
    }
}

#[derive(Debug)]
struct CompiledGrant {
    id: RuleId,
    grant: Grant,
    from: End,
    to: End,
    protocols: Protocols,
}

/// The namespaces of a member label, or the union over a source's labels.
#[derive(Debug, Clone)]
pub(crate) struct Membership {
    /// Sorted, without duplicates.
    namespaces: Vec<NamespaceId>,
    /// The [`NamespaceKind::Rules`] namespaces among them, sorted.
    rules: Vec<NamespaceId>,
    /// Every namespace restricts outbound traffic.
    outbound_restricted: bool,
}

impl Membership {
    fn contains(&self, id: &NamespaceId) -> bool {
        self.namespaces.binary_search(id).is_ok()
    }

    /// Whether `id` is one of the [`NamespaceKind::Rules`] namespaces.
    fn has_rules(&self, id: &NamespaceId) -> bool {
        self.rules.binary_search(id).is_ok()
    }

    /// Whether outbound traffic to the source is restricted.
    pub(crate) const fn outbound_restricted(&self) -> bool {
        self.outbound_restricted
    }
}

/// The default rule set.
#[derive(Debug, Clone, Default)]
enum DefaultRules {
    #[default]
    NotInstalled,
    Installed(Arc<RuleSet>),
    Failed,
}

/// The whole engine state: published as one immutable value, so a reader
/// sees the default rules, namespaces and grants of a single update.
#[derive(Debug, Default, Clone)]
pub(crate) struct Snapshot {
    default: DefaultRules,
    /// What applies to sources in no namespace while nothing is installed.
    not_installed: NotInstalled,
    namespaces: BTreeMap<NamespaceId, Arc<CompiledNamespace>>,
    /// Member label -> its namespaces (derived from `namespaces`).
    memberships: HashMap<Label, Arc<Membership>>,
    /// Member host addresses (`/32`, `/128`) with their member label (derived).
    hosts: HashMap<IpAddr, Label>,
    /// The other member addresses with their member label, longest prefix
    /// first (derived).
    addresses: Vec<(IpNet, Label)>,
    /// Whether some member label is outbound-restricted (derived).
    outbound_restrictions: bool,
    grants: BTreeMap<RuleId, Arc<CompiledGrant>>,
    pinholes: BTreeMap<PinholeId, Arc<Pinhole>>,
    /// Bumped on every published update ([`AclEngine::generation`]).
    generation: u64,
    /// Sources in no namespace accept every inbound TCP and UDP flow
    /// (derived).
    default_bypass: bool,
    /// The rule namespaces accepting every inbound TCP and UDP flow
    /// (derived).
    open: HashSet<NamespaceId>,
    /// The distinct namespace sets of the members owning an address
    /// (derived, empty while `open` is).
    owner_sets: Vec<Vec<NamespaceId>>,
}

impl Snapshot {
    /// Whether rules are installed, a namespace is stored, or nothing is
    /// installed and [`NotInstalled::Accept`] applies.
    pub(crate) fn is_loaded(&self) -> bool {
        match self.default {
            DefaultRules::Installed(_) => true,
            DefaultRules::NotInstalled if self.not_installed == NotInstalled::Accept => true,
            DefaultRules::NotInstalled | DefaultRules::Failed => !self.namespaces.is_empty(),
        }
    }

    pub(crate) fn policy_state(&self) -> PolicyState {
        match &self.default {
            DefaultRules::NotInstalled => PolicyState::NotInstalled,
            DefaultRules::Installed(rules) => PolicyState::Installed { rules: rules.len() },
            DefaultRules::Failed => PolicyState::Failed,
        }
    }

    /// The generation of this snapshot.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether every inbound TCP or UDP flow from a known source with
    /// `membership` (`None`: in no namespace) is accepted without a
    /// dependency and without recording an outbound reply allowance, so the
    /// filter can skip its evaluation.
    pub(crate) fn bypasses(&self, membership: Option<&Membership>) -> bool {
        let Some(membership) = membership else {
            return self.default_bypass;
        };
        let open = |id: &NamespaceId| self.open.contains(id) && membership.contains(id);
        // The local node is in every namespace; each owner must share one.
        !membership.outbound_restricted
            && membership.namespaces.iter().any(open)
            && self
                .owner_sets
                .iter()
                .all(|namespaces| namespaces.iter().any(open))
    }

    /// Whether some pinhole (open or expired but not yet swept) belongs to a
    /// label of `labels`.
    pub(crate) fn has_pinholes_of(&self, labels: &LabelSet) -> bool {
        !self.pinholes.is_empty()
            && self
                .pinholes
                .values()
                .any(|pinhole| labels.contains(&pinhole.spec.label))
    }

    /// Whether any member label is outbound-restricted.
    pub(crate) const fn has_outbound_restrictions(&self) -> bool {
        self.outbound_restrictions
    }

    /// The namespaces of the member label `label`, `None` when it is in no
    /// namespace.
    fn membership(&self, label: &Label) -> Option<&Arc<Membership>> {
        self.memberships.get(label)
    }

    /// The namespaces of a source with `labels`: the union over its member
    /// labels, `None` when it is in no namespace.
    pub(crate) fn membership_of(&self, labels: &LabelSet) -> Option<Arc<Membership>> {
        if self.memberships.is_empty() {
            return None;
        }
        let mut found = labels
            .iter()
            .filter_map(|label| self.memberships.get(label));
        let first = found.next()?;
        let Some(second) = found.next() else {
            return Some(Arc::clone(first));
        };
        let mut union = Membership::clone(first);
        for membership in std::iter::once(second).chain(found) {
            union
                .namespaces
                .extend(membership.namespaces.iter().cloned());
            union.rules.extend(membership.rules.iter().cloned());
            union.outbound_restricted &= membership.outbound_restricted;
        }
        union.namespaces.sort_unstable();
        union.namespaces.dedup();
        union.rules.sort_unstable();
        union.rules.dedup();
        Some(Arc::new(union))
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

    /// The pinhole of a label of `labels` opening `direction` flows of
    /// `protocol` to `port`. The clock is read only when a pinhole matches.
    pub(crate) fn match_pinhole(
        &self,
        labels: &LabelSet,
        direction: Direction,
        protocol: Protocol,
        port: u16,
        now: impl Fn() -> Instant,
    ) -> PinholeMatch {
        let mut at = None;
        let mut found = PinholeMatch::Absent;
        for pinhole in self.pinholes.values() {
            if !pinhole.matches(direction, protocol, port) || !labels.contains(&pinhole.spec.label)
            {
                continue;
            }
            if pinhole.is_open_at(*at.get_or_insert_with(&now)) {
                return PinholeMatch::Open(pinhole.id);
            }
            found = PinholeMatch::Expired;
        }
        found
    }

    /// The member label owning `ip` (longest prefix), with its namespaces.
    fn member_at(&self, ip: IpAddr) -> Option<(&Label, &Membership)> {
        // A host address is always the longest prefix.
        let owner = match self.hosts.get(&ip) {
            Some(owner) => owner,
            None => &self.addresses.iter().find(|(net, _)| net.contains(&ip))?.1,
        };
        Some((owner, self.memberships.get(owner)?))
    }

    /// Evaluate a new inbound `flow` from a source with `labels` and
    /// `membership` (`None`: in no namespace). `now` is read only when a
    /// pinhole matches.
    pub(crate) fn evaluate(
        &self,
        labels: &LabelSet,
        membership: Option<&Membership>,
        flow: &Flow,
        now: impl Fn() -> Instant,
    ) -> Evaluation<'_> {
        let evaluation = membership.map_or_else(
            || self.evaluate_default(labels, flow),
            |membership| self.evaluate_member(labels, membership, flow, now),
        );
        evaluation.log(flow);
        evaluation
    }

    fn evaluate_default(&self, labels: &LabelSet, flow: &Flow) -> Evaluation<'_> {
        match &self.default {
            DefaultRules::NotInstalled => match self.not_installed {
                NotInstalled::Accept => Evaluation::NotInstalled,
                NotInstalled::Deny => Evaluation::Deny(reasons::NO_POLICY),
            },
            DefaultRules::Installed(rules) => {
                rules
                    .first_match(labels, flow)
                    .map_or(Evaluation::Deny(reasons::DENIED), |id| Evaluation::Rule {
                        namespace: None,
                        id,
                    })
            }
            DefaultRules::Failed => Evaluation::Deny(reasons::POLICY_FAILED),
        }
    }

    fn evaluate_member(
        &self,
        labels: &LabelSet,
        membership: &Membership,
        flow: &Flow,
        now: impl Fn() -> Instant,
    ) -> Evaluation<'_> {
        let dst = self.member_at(flow.dst);
        let mut common = false;
        for id in &membership.rules {
            // A local destination is in every namespace.
            if dst.is_some_and(|(_, dst)| !dst.contains(id)) {
                continue;
            }
            common = true;
            let Some((id, namespace)) = self.namespaces.get_key_value(id) else {
                continue;
            };
            if let Some(rule) = namespace.rules.first_match(labels, flow) {
                return Evaluation::Rule {
                    namespace: Some(id),
                    id: rule,
                };
            }
        }
        let Some((owner, dst_membership)) = dst else {
            // Pinholes open the local node only, for TCP and UDP.
            let Some((protocol, port)) = flow.port() else {
                return Evaluation::Deny(reasons::DENIED);
            };
            return match self.match_pinhole(labels, Direction::Inbound, protocol, port, now) {
                PinholeMatch::Open(id) => Evaluation::Pinhole(id),
                PinholeMatch::Expired => Evaluation::PinholeExpired,
                PinholeMatch::Absent => Evaluation::Deny(reasons::DENIED),
            };
        };
        let granted = self.grants.values().find(|grant| {
            grant.from.matches_source(labels, membership)
                && grant.to.matches_owner(owner, dst_membership)
                && grant.protocols.matches(flow.transport)
        });
        match granted {
            Some(grant) => Evaluation::Grant(&grant.id),
            None if common => Evaluation::Deny(reasons::DENIED),
            None => Evaluation::Deny(reasons::CROSS_NAMESPACE),
        }
    }

    /// Whether an outbound rule of one of `membership`'s namespaces accepts
    /// `transport`.
    pub(crate) fn outbound_rule_accepts(
        &self,
        membership: &Membership,
        transport: Transport,
    ) -> bool {
        membership
            .namespaces
            .iter()
            .filter_map(|id| self.namespaces.get(id)?.outbound.as_deref())
            .flatten()
            .any(|rule| rule.matches(transport))
    }

    /// Rebuild the indexes derived from `namespaces`.
    fn reindex(&mut self) {
        let mut memberships: HashMap<Label, Membership> = HashMap::new();
        let mut addresses = Vec::new();
        for (id, namespace) in &self.namespaces {
            let restricts = namespace.outbound.is_some();
            for member in &namespace.source.members {
                let membership =
                    memberships
                        .entry(member.label.clone())
                        .or_insert_with(|| Membership {
                            namespaces: Vec::new(),
                            rules: Vec::new(),
                            outbound_restricted: true,
                        });
                // `namespaces` iterates in order, so the lists stay sorted.
                if membership.namespaces.last() != Some(id) {
                    membership.namespaces.push(id.clone());
                    if namespace.is_rules() {
                        membership.rules.push(id.clone());
                    }
                    membership.outbound_restricted &= restricts;
                }
                addresses.extend(
                    member
                        .addresses
                        .iter()
                        .map(|net| (*net, member.label.clone())),
                );
            }
        }
        addresses.sort_by(|(a, a_owner), (b, b_owner)| {
            b.prefix_len()
                .cmp(&a.prefix_len())
                .then_with(|| a_owner.cmp(b_owner))
        });
        addresses.dedup();
        let mut hosts = HashMap::new();
        addresses.retain(|(net, owner)| {
            let host = net.prefix_len() == if net.network().is_ipv4() { 32 } else { 128 };
            if host {
                // Sorted by label: the smallest one owns a shared address.
                hosts.entry(net.network()).or_insert_with(|| owner.clone());
            }
            !host
        });
        self.outbound_restrictions = memberships.values().any(|m| m.outbound_restricted);
        self.memberships = memberships
            .into_iter()
            .map(|(label, membership)| (label, Arc::new(membership)))
            .collect();
        self.hosts = hosts;
        self.addresses = addresses;
    }

    /// Recompute the bypass inputs: whether sources in no namespace accept
    /// everything, the open rule namespaces (an accept rule from any source
    /// to any destination for every TCP and UDP port), and the distinct
    /// namespace sets of the address owners.
    fn rebypass(&mut self) {
        self.default_bypass = match &self.default {
            DefaultRules::NotInstalled => self.not_installed == NotInstalled::Accept,
            DefaultRules::Installed(rules) => rules.accepts_everything(),
            DefaultRules::Failed => false,
        };
        self.open = self
            .namespaces
            .iter()
            .filter(|(_, namespace)| namespace.is_rules() && namespace.rules.accepts_everything())
            .map(|(id, _)| id.clone())
            .collect();
        self.owner_sets = if self.open.is_empty() {
            Vec::new()
        } else {
            let owners: HashSet<&Label> = self
                .hosts
                .values()
                .chain(self.addresses.iter().map(|(_, owner)| owner))
                .collect();
            let sets: HashSet<&[NamespaceId]> = owners
                .into_iter()
                .filter_map(|owner| Some(&*self.memberships.get(owner)?.namespaces))
                .collect();
            sets.into_iter().map(<[NamespaceId]>::to_vec).collect()
        };
    }

    /// Whether `label` may hold a pinhole of `kind` in the pinhole namespace
    /// `namespace` (`source_gated`: it held a rule namespace when the
    /// pinhole opened).
    fn pinhole_permission(
        &self,
        namespace: &NamespaceId,
        label: &Label,
        kind: &str,
        source_gated: bool,
    ) -> Result<(), PinholeError> {
        let membership = self.membership(label).filter(|m| m.contains(namespace));
        let Some(membership) = membership else {
            return Err(PinholeError::NotMember);
        };
        if membership.rules.is_empty() {
            // A label only in pinhole namespaces is governed by its own
            // pinholes, unless it has lost the rule namespace that permitted
            // the pinhole.
            return if source_gated {
                Err(PinholeError::NotPermitted)
            } else {
                Ok(())
            };
        }
        let permitted = membership.rules.iter().any(|id| {
            self.namespaces
                .get(id)
                .is_some_and(|ns| ns.source.pinhole_kinds.contains(kind))
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

    /// After a namespace change, remove the pinholes whose namespace is gone
    /// or that are no longer permitted (including a namespace that is no
    /// longer a pinhole namespace); returns how many of each.
    fn recheck_pinholes(&mut self) -> (u64, u64) {
        let (mut namespace_removed, mut revoked) = (0, 0);
        let mut pinholes = std::mem::take(&mut self.pinholes);
        pinholes.retain(|_, pinhole| {
            let Some(namespace) = self.namespaces.get(&pinhole.namespace) else {
                namespace_removed += 1;
                return false;
            };
            // A namespace stored again as a rule namespace holds no pinholes.
            let permitted = !namespace.is_rules()
                && self
                    .pinhole_permission(
                        &pinhole.namespace,
                        &pinhole.spec.label,
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

/// Shared ACL engine: the default [`RuleSet`], rule namespaces, directed
/// grants and pinholes.
///
/// The default rule set applies to sources in no namespace and has a
/// [`PolicyState`]: not installed (the engine's [`NotInstalled`] action
/// applies, deny by default), installed ([`install`](Self::install)), or
/// failed ([`fail`](Self::fail), fail closed). A namespace member is
/// governed by its namespaces (plus grants and pinholes) in every state.
/// The whole state is one immutable snapshot: writers serialize on a mutex
/// and publish a new snapshot atomically, readers take one lock-free load, so
/// the engine can be shared through an `Arc` and queried per packet while
/// another thread updates it.
///
/// [`evaluate`](Self::evaluate) decides a new inbound flow with namespaces,
/// grants and pinholes, as [`AclFilter`](crate::AclFilter) does for inbound
/// packets. See the crate docs for the namespace model and pinholes.
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
    /// An engine with nothing installed (denies everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An engine with nothing installed whose pinhole expiry follows `clock`
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

    /// Sets what applies to sources in no namespace while no rule set is
    /// installed. Default [`NotInstalled::Deny`]: their new flows are denied
    /// with [`reasons::NO_POLICY`]. With [`NotInstalled::Accept`] every flow
    /// they send is accepted.
    #[must_use]
    pub fn with_not_installed(self, action: NotInstalled) -> Self {
        let mut snapshot = Snapshot::clone(&self.snapshot.load());
        snapshot.not_installed = action;
        snapshot.rebypass();
        self.snapshot.store(Arc::new(snapshot));
        self
    }

    /// Compile `policy` and install it as the default rule set (see
    /// [`RuleSet::from_document`]).
    ///
    /// On error (invalid policy or failed built-in tests) the previous state
    /// stays in effect.
    pub fn load(&self, policy: AclPolicy) -> Result<(), Error> {
        match RuleSet::from_document(policy) {
            Ok(rules) => {
                self.install(rules);
                Ok(())
            }
            Err(err) => {
                warn!(error = %err, "ACL policy rejected; keeping the previous policy");
                Err(err)
            }
        }
    }

    /// Install `rules` as the default rule set, which applies to sources in
    /// no namespace, in one atomic swap. The state becomes
    /// [`PolicyState::Installed`]; an empty set denies every new flow.
    pub fn install(&self, rules: impl Into<Arc<RuleSet>>) {
        let rules = rules.into();
        self.publish(|snapshot| snapshot.default = DefaultRules::Installed(rules));
    }

    /// Remove the default rule set: the state becomes
    /// [`PolicyState::NotInstalled`] and the engine's [`NotInstalled`] action
    /// applies to sources in no namespace. Namespaces, grants and pinholes
    /// stay. See [`clear_all`](Self::clear_all) to remove everything.
    pub fn uninstall(&self) {
        self.publish(|snapshot| snapshot.default = DefaultRules::NotInstalled);
    }

    /// Report that the caller failed to build its rules: the state becomes
    /// [`PolicyState::Failed`] and new flows of sources in no namespace are
    /// denied with [`reasons::POLICY_FAILED`] (fail closed). With nothing
    /// else loaded every inbound packet, replies included, is dropped. The
    /// engine never enters this state on its own.
    pub fn fail(&self) {
        warn!("ACL default rules failed: sources in no namespace fail closed");
        self.publish(|snapshot| snapshot.default = DefaultRules::Failed);
    }

    /// The state of the default rule set.
    pub fn policy_state(&self) -> PolicyState {
        self.snapshot.load().policy_state()
    }

    /// Emergency stop: remove the default rule set and every namespace, grant
    /// and pinhole in one atomic snapshot swap and enter
    /// [`PolicyState::Failed`], so the filter drops every inbound packet,
    /// replies included, with [`reasons::POLICY_FAILED`] (even with
    /// [`NotInstalled::Accept`]).
    ///
    /// Open pinholes are counted in [`PinholeStats::cleared`] (pinholes
    /// already expired are counted as expired); their guards become no-ops.
    /// Later updates ([`install`](Self::install),
    /// [`store_namespace`](Self::store_namespace), ...) work as usual.
    pub fn clear_all(&self) {
        let cleared = self.publish(|snapshot| {
            let cleared = snapshot.pinholes.len() as u64;
            *snapshot = Snapshot {
                default: DefaultRules::Failed,
                not_installed: snapshot.not_installed,
                ..Snapshot::default()
            };
            cleared
        });
        PinholeCounters::add(&self.pinholes.cleared, cleared);
        warn!(
            pinholes = cleared,
            "ACL cleared: every rule, namespace, grant and pinhole removed"
        );
    }

    /// Whether anything is loaded: rules are installed, a namespace is
    /// stored, or nothing is installed under [`NotInstalled::Accept`]. When
    /// `false`, the filter drops every inbound packet, replies included, with
    /// [`reasons::NO_POLICY`] (or [`reasons::POLICY_FAILED`] in
    /// [`PolicyState::Failed`]).
    pub fn is_loaded(&self) -> bool {
        self.snapshot.load().is_loaded()
    }

    /// The installed default rule set, if any.
    pub fn rules(&self) -> Option<Arc<RuleSet>> {
        match &self.snapshot.load().default {
            DefaultRules::Installed(rules) => Some(Arc::clone(rules)),
            DefaultRules::NotInstalled | DefaultRules::Failed => None,
        }
    }

    /// The decision for a new inbound flow `flow` from a source with
    /// `labels`, with namespaces, grants and pinholes.
    ///
    /// A source whose labels are members of no namespace is decided by the
    /// default rule set and its [`PolicyState`]. For a namespace member the
    /// destination address is resolved to a member (longest prefix) or the
    /// local node, and the flow is accepted by a rule of a shared namespace,
    /// a directed grant or an inbound pinhole. This is the decision
    /// [`AclFilter`](crate::AclFilter) applies to the first packet of a new
    /// inbound flow; the filter's reply table is not consulted and nothing is
    /// cached. A flow whose addresses are of different families is denied
    /// with [`reasons::MALFORMED`].
    pub fn evaluate(&self, labels: &LabelSet, flow: &Flow) -> Decision {
        if flow.is_mixed() {
            return Decision::Deny(reasons::MALFORMED);
        }
        let snapshot = self.snapshot.load();
        let membership = snapshot.membership_of(labels);
        let evaluation = snapshot.evaluate(labels, membership.as_deref(), flow, || self.now());
        match evaluation {
            Evaluation::Rule { namespace, id } => Decision::Accept(Matched::Rule {
                namespace: namespace.cloned(),
                id: id.clone(),
            }),
            Evaluation::Grant(id) => Decision::Accept(Matched::Grant(id.clone())),
            Evaluation::Pinhole(id) => Decision::Accept(Matched::Pinhole(id)),
            Evaluation::NotInstalled => Decision::Accept(Matched::NotInstalled),
            Evaluation::PinholeExpired => {
                self.expire_pinholes();
                Decision::Deny(reasons::DENIED)
            }
            Evaluation::Deny(reason) => Decision::Deny(reason),
        }
    }

    /// Compile `policy` and store it as namespace `id`, replacing only that
    /// namespace.
    ///
    /// The namespace's rules are compiled and their built-in tests run, as
    /// [`load`](Self::load) does. A [`NamespaceKind::Pinholes`] namespace
    /// with accept rules or pinhole kinds, or an invalid outbound rule, is
    /// rejected with [`Error::InvalidNamespace`]. On error the previous state
    /// stays in effect.
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
    /// Removing a pinhole namespace closes its pinholes; removing a rule
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

    /// The namespaces the member label `label` is in, sorted.
    pub fn memberships(&self, label: &Label) -> Vec<NamespaceId> {
        self.snapshot
            .load()
            .membership(label)
            .map(|m| m.namespaces.clone())
            .unwrap_or_default()
    }

    /// Store a directed grant under `id`, replacing any grant with that id.
    ///
    /// Returns [`Error::InvalidGrant`] for an invalid protocol or port syntax,
    /// or when an end names a stored [`NamespaceKind::Pinholes`] namespace
    /// (its members get access only through pinholes); the previous state
    /// then stays in effect. A namespace end matches only while the
    /// namespace is of kind [`NamespaceKind::Rules`]. Reply allowances that
    /// depend on a grant survive its replacement under the same id.
    pub fn store_grant(&self, id: impl Into<RuleId>, grant: Grant) -> Result<(), Error> {
        let id = id.into();
        let invalid = |reason: String| Error::InvalidGrant {
            id: id.clone(),
            reason,
        };
        let snapshot = self.snapshot.load();
        for end in [&grant.from, &grant.to] {
            if let GrantEnd::Namespace(ns) = end
                && snapshot.namespaces.get(ns).is_some_and(|ns| !ns.is_rules())
            {
                return Err(invalid(format!("cannot name pinhole namespace '{ns}'")));
            }
        }
        drop(snapshot);
        let protocols =
            compile_ports(grant.proto.as_deref(), grant.ports.as_deref()).map_err(invalid)?;
        let compiled = Arc::new(CompiledGrant {
            id: id.clone(),
            from: End::new(&grant.from),
            to: End::new(&grant.to),
            grant,
            protocols,
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
    pub fn grants(&self) -> Vec<(RuleId, Grant)> {
        self.snapshot
            .load()
            .grants
            .iter()
            .map(|(id, grant)| (id.clone(), grant.grant.clone()))
            .collect()
    }

    /// Open a pinhole in the pinhole namespace `namespace` for `spec`: one
    /// label, one direction, one protocol and one destination port, until
    /// the returned guard is dropped or `spec.expires_at` passes.
    ///
    /// The namespace must be a stored [`NamespaceKind::Pinholes`] namespace
    /// with `spec.label` as a member, and `spec.expires_at` must be in the
    /// future per the engine clock. When the label is a member of at least
    /// one [`NamespaceKind::Rules`] namespace, one of them must list
    /// `spec.kind` in [`pinhole_kinds`](NamespacePolicy::pinhole_kinds); a
    /// label only in pinhole namespaces is governed by its own pinholes. On
    /// error nothing changes.
    pub fn open_pinhole(
        self: &Arc<Self>,
        namespace: impl Into<NamespaceId>,
        spec: PinholeSpec,
    ) -> Result<PinholeGuard, PinholeError> {
        let namespace = namespace.into();
        let id = self.publish(|snapshot| {
            let Some(stored) = snapshot.namespaces.get(&namespace) else {
                return Err(PinholeError::UnknownNamespace);
            };
            if stored.is_rules() {
                return Err(PinholeError::NotPinholeNamespace);
            }
            if !snapshot
                .membership(&spec.label)
                .is_some_and(|m| m.contains(&namespace))
            {
                return Err(PinholeError::NotMember);
            }
            if spec.expires_at <= self.now() {
                return Err(PinholeError::Expired);
            }
            let source_gated = snapshot
                .membership(&spec.label)
                .is_some_and(|m| !m.rules.is_empty());
            if let Err(err) =
                snapshot.pinhole_permission(&namespace, &spec.label, &spec.kind, source_gated)
            {
                PinholeCounters::add(&self.pinholes.not_permitted, 1);
                return Err(err);
            }
            let id = PinholeId::new(self.pinholes.next_id.fetch_add(1, Ordering::Relaxed) + 1);
            snapshot.pinholes.insert(
                id,
                Arc::new(Pinhole {
                    id,
                    namespace,
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
    /// change (default rules and their state, namespaces, grants, pinholes
    /// opened, closed, swept after expiry or revoked,
    /// [`clear_all`](Self::clear_all)). The filter tags its cached verdicts
    /// with it, so no cached verdict outlives a change; a pinhole that
    /// expired but is not swept yet is caught by the filter's expiry check
    /// instead.
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

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::*;
    use crate::namespace::{NamespaceMember, OutboundRule};
    use crate::policy::{AclAction, AclRule};
    use crate::rules::{IcmpTypes, ProtocolMatch, Rule};

    fn make_policy(acls: Vec<AclRule>, tests: Vec<AclTest>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::new(),
            acls,
            tests,
        }
    }

    fn accept_rule(src: &[&str], dst: &[&str], proto: Option<&str>) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            src: src.iter().map(ToString::to_string).collect(),
            dst: dst.iter().map(ToString::to_string).collect(),
            proto: proto.map(str::to_owned),
        }
    }

    fn flow(src: &str, dst: &str, port: u16, proto: Protocol) -> Flow {
        let src = SocketAddr::new(src.parse().unwrap(), 4000);
        let dst = SocketAddr::new(dst.parse().unwrap(), port);
        match proto {
            Protocol::Tcp => Flow::tcp(src, dst),
            Protocol::Udp => Flow::udp(src, dst),
        }
    }

    /// A flow from a source without labels.
    fn req(src: &str, dst: &str, port: u16, proto: Protocol) -> (LabelSet, Flow) {
        (LabelSet::empty(), flow(src, dst, port, proto))
    }

    fn allowed(rules: &RuleSet, (labels, flow): &(LabelSet, Flow)) -> bool {
        rules.matching(labels, flow).is_some()
    }

    fn matched(rules: &RuleSet, (labels, flow): &(LabelSet, Flow)) -> Option<String> {
        rules
            .matching(labels, flow)
            .map(|id| id.as_str().to_owned())
    }

    fn evaluate(engine: &AclEngine, (labels, flow): &(LabelSet, Flow)) -> Decision {
        engine.evaluate(labels, flow)
    }

    fn rule(namespace: Option<&str>, id: &str) -> Decision {
        Decision::Accept(Matched::Rule {
            namespace: namespace.map(NamespaceId::from),
            id: id.into(),
        })
    }

    // ── documents ─────────────────────────────────────────────────────────

    #[test]
    fn empty_policy_denies_everything() {
        let rules = RuleSet::from_document(make_policy(vec![], vec![])).unwrap();
        assert!(!allowed(
            &rules,
            &req("10.0.0.1", "192.168.1.1", 80, Protocol::Tcp)
        ));
    }

    #[test]
    fn wildcard_rule_allows_any_connection() {
        let rules = RuleSet::from_document(make_policy(
            vec![accept_rule(&["*"], &["*:*"], None)],
            vec![],
        ))
        .unwrap();
        assert!(allowed(
            &rules,
            &req("1.2.3.4", "5.6.7.8", 9999, Protocol::Udp)
        ));
    }

    #[test]
    fn cidr_rule_allows_in_range_denies_outside() {
        let rules = RuleSet::from_document(make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![],
        ))
        .unwrap();
        assert!(allowed(
            &rules,
            &req("10.0.0.5", "192.168.1.5", 80, Protocol::Tcp)
        ));
        // src outside range
        assert!(!allowed(
            &rules,
            &req("10.0.1.5", "192.168.1.5", 80, Protocol::Tcp)
        ));
        // dst outside range
        assert!(!allowed(
            &rules,
            &req("10.0.0.5", "192.168.2.5", 80, Protocol::Tcp)
        ));
        // wrong port
        assert!(!allowed(
            &rules,
            &req("10.0.0.5", "192.168.1.5", 443, Protocol::Tcp)
        ));
    }

    #[test]
    fn host_alias_resolves_correctly() {
        let mut policy = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["db:5432"], Some("tcp"))],
            vec![],
        );
        policy
            .hosts
            .insert("db".to_owned(), "192.168.1.10/32".to_owned());
        let rules = RuleSet::from_document(policy).unwrap();
        assert!(allowed(
            &rules,
            &req("10.0.0.2", "192.168.1.10", 5432, Protocol::Tcp)
        ));
        assert!(!allowed(
            &rules,
            &req("10.0.0.2", "192.168.1.11", 5432, Protocol::Tcp)
        ));
    }

    #[test]
    fn document_protocols_and_ports() {
        let rules = RuleSet::from_document(make_policy(
            vec![
                accept_rule(&["*"], &["*:80"], Some("tcp")),
                accept_rule(&["*"], &["*:53"], None),
                accept_rule(&["*"], &["*:8000-8999"], Some("udp")),
                accept_rule(&["*"], &["*:443,8443"], Some("tcp")),
            ],
            vec![],
        ))
        .unwrap();
        let check = |port, proto| matched(&rules, &req("1.2.3.4", "5.6.7.8", port, proto));
        assert_eq!(check(80, Protocol::Tcp).as_deref(), Some("0"));
        assert_eq!(check(80, Protocol::Udp), None);
        assert_eq!(check(53, Protocol::Tcp).as_deref(), Some("1"));
        assert_eq!(check(53, Protocol::Udp).as_deref(), Some("1"));
        assert_eq!(check(8080, Protocol::Udp).as_deref(), Some("2"));
        assert_eq!(check(8080, Protocol::Tcp), None);
        assert_eq!(check(8443, Protocol::Tcp).as_deref(), Some("3"));
        assert_eq!(check(444, Protocol::Tcp), None);
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = RuleSet::from_document(make_policy(
            vec![
                accept_rule(&["10.0.0.0/24"], &["*:80"], None),
                accept_rule(&["*"], &["*:*"], None),
            ],
            vec![],
        ))
        .unwrap();
        let first = req("10.0.0.5", "1.2.3.4", 80, Protocol::Tcp);
        assert_eq!(matched(&rules, &first).as_deref(), Some("0"));
        let second = req("172.16.0.1", "1.2.3.4", 9090, Protocol::Tcp);
        assert_eq!(matched(&rules, &second).as_deref(), Some("1"));
    }

    #[test]
    fn builtin_tests_run_on_compilation() {
        let test = |dst: &str, proto: Option<&str>, allow| AclTest {
            src: "10.0.0.2".to_owned(),
            dst: dst.to_owned(),
            proto: proto.map(str::to_owned),
            allow,
        };
        let tcp = make_policy(
            vec![accept_rule(&["10.0.0.0/24"], &["192.168.1.0/24:80"], None)],
            vec![
                test("192.168.1.5:80", None, true),
                test("192.168.1.5:443", None, false),
            ],
        );
        assert!(RuleSet::from_document(tcp).is_ok());
        let udp = make_policy(
            vec![accept_rule(
                &["10.0.0.0/24"],
                &["192.168.1.0/24:53"],
                Some("udp"),
            )],
            vec![
                test("192.168.1.5:53", Some("udp"), true),
                test("192.168.1.5:53", Some("tcp"), false),
            ],
        );
        assert!(RuleSet::from_document(udp).is_ok());
        // Expects allow, but an empty policy denies; unparsable tests fail too.
        let failing = make_policy(
            vec![],
            vec![
                test("192.168.1.5:80", None, true),
                test("192.168.1.5", None, false),
                test("192.168.1.5:80", Some("icmp"), false),
            ],
        );
        assert!(matches!(
            RuleSet::from_document(failing),
            Err(Error::TestsFailed { count: 3 })
        ));
    }

    #[test]
    fn invalid_documents_return_errors() {
        assert!(
            RuleSet::from_document(make_policy(
                vec![accept_rule(&["does-not-exist"], &["*:80"], None)],
                vec![],
            ))
            .is_err()
        );
        let mut policy = make_policy(vec![], vec![]);
        policy
            .hosts
            .insert("bad".to_owned(), "not-a-cidr".to_owned());
        assert!(RuleSet::from_document(policy).is_err());
    }

    // ── labels ────────────────────────────────────────────────────────────

    /// The `key:<hex>` text of the document's key source `[byte; 32]`.
    fn anchor(byte: u8) -> String {
        format!("key:{}", format!("{byte:02x}").repeat(32))
    }

    fn key_label(byte: u8) -> Label {
        Label::from(anchor(byte))
    }

    fn key_labels(byte: u8) -> LabelSet {
        LabelSet::new([key_label(byte)])
    }

    /// A flow from a source labelled with the key `[byte; 32]`.
    fn key_req(byte: u8, dst: &str, port: u16, proto: Protocol) -> (LabelSet, Flow) {
        (key_labels(byte), flow("fd00::ff", dst, port, proto))
    }

    #[test]
    fn key_rules_match_the_label_and_cidr_rules_the_flow_source() {
        let key_src = format!("key:{}", "07".repeat(32));
        let rules = RuleSet::from_document(make_policy(
            vec![
                accept_rule(&[&key_src], &["*:80"], None),
                accept_rule(&["fd00::/16"], &["*:443"], None),
            ],
            vec![],
        ))
        .unwrap();
        assert!(allowed(&rules, &key_req(7, "fd00::2", 80, Protocol::Tcp)));
        // A different key is denied (default-deny).
        assert!(!allowed(&rules, &key_req(9, "fd00::2", 80, Protocol::Tcp)));
        // A source without the label never matches a key rule.
        assert!(!allowed(
            &rules,
            &req("fd00::7", "fd00::2", 80, Protocol::Tcp)
        ));
        // A CIDR rule reads the flow's source address, whatever the labels.
        assert!(allowed(
            &rules,
            &req("fd00::7", "fd00::2", 443, Protocol::Tcp)
        ));
        assert!(allowed(&rules, &key_req(7, "fd00::2", 443, Protocol::Tcp)));
        assert!(!allowed(
            &rules,
            &req("fd01::7", "fd00::2", 443, Protocol::Tcp)
        ));
    }

    // ── policy states ─────────────────────────────────────────────────────

    fn port_policy(port: u16) -> AclPolicy {
        make_policy(
            vec![accept_rule(&["*"], &[&format!("*:{port}")], None)],
            vec![],
        )
    }

    fn port_rules(id: &str, port: u16) -> RuleSet {
        RuleSet::new([Rule::new(
            id,
            vec![ProtocolMatch::Tcp(PortSet::single(port))],
        )])
        .unwrap()
    }

    #[test]
    fn not_installed_denies_by_default() {
        let engine = AclEngine::new();
        assert_eq!(engine.policy_state(), PolicyState::NotInstalled);
        assert!(!engine.is_loaded());
        assert!(engine.rules().is_none());
        let request = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);
        assert_eq!(
            evaluate(&engine, &request),
            Decision::Deny(reasons::NO_POLICY)
        );
        assert!(!AclEngine::default().is_loaded());
    }

    #[test]
    fn not_installed_can_accept() {
        let engine = AclEngine::new().with_not_installed(NotInstalled::Accept);
        assert_eq!(engine.policy_state(), PolicyState::NotInstalled);
        assert!(engine.is_loaded());
        assert!(engine.snapshot().bypasses(None));
        for request in [
            req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp),
            key_req(1, "fd00::2", 9, Protocol::Udp),
            (
                LabelSet::empty(),
                Flow::icmp("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), 8),
            ),
        ] {
            assert_eq!(
                evaluate(&engine, &request),
                Decision::Accept(Matched::NotInstalled)
            );
        }
        // Installed rules take over; uninstalling returns to the action.
        engine.install(port_rules("web", 80));
        let other = req("10.0.0.1", "10.0.0.2", 81, Protocol::Tcp);
        assert_eq!(evaluate(&engine, &other), Decision::Deny(reasons::DENIED));
        engine.uninstall();
        assert_eq!(
            evaluate(&engine, &other),
            Decision::Accept(Matched::NotInstalled)
        );
    }

    #[test]
    fn installed_rules_decide_and_report_their_id() {
        let engine = AclEngine::new();
        let generation = engine.generation();
        engine.install(port_rules("web", 80));
        assert!(engine.generation() > generation);
        assert_eq!(engine.policy_state(), PolicyState::Installed { rules: 1 });
        assert!(engine.is_loaded());
        assert_eq!(engine.rules().unwrap().rules()[0].id.as_str(), "web");
        let web = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);
        let decision = evaluate(&engine, &web);
        assert_eq!(decision, rule(None, "web"));
        assert_eq!(decision.rule_id().map(RuleId::as_str), Some("web"));
        assert_eq!(
            evaluate(&engine, &req("10.0.0.1", "10.0.0.2", 443, Protocol::Tcp)),
            Decision::Deny(reasons::DENIED)
        );
        // A family-mixed flow is malformed.
        let mixed = (
            LabelSet::empty(),
            flow("10.0.0.1", "fd00::2", 80, Protocol::Tcp),
        );
        assert_eq!(
            evaluate(&engine, &mixed),
            Decision::Deny(reasons::MALFORMED)
        );
        // An installed empty set denies every new flow but counts as loaded.
        engine.install(Arc::new(RuleSet::empty()));
        assert_eq!(engine.policy_state(), PolicyState::Installed { rules: 0 });
        assert!(engine.is_loaded());
        assert_eq!(evaluate(&engine, &web), Decision::Deny(reasons::DENIED));
        // `load` installs a compiled document.
        engine.load(port_policy(80)).unwrap();
        assert_eq!(evaluate(&engine, &web), rule(None, "0"));
    }

    #[test]
    fn typed_rules_accept_icmp_and_other_protocols() {
        let engine = AclEngine::new();
        engine.install(
            RuleSet::new([
                Rule::new("echo", vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![8]))]),
                Rule::new("gre", vec![ProtocolMatch::Ip(47)]).with_labels(["a".into()]),
            ])
            .unwrap(),
        );
        let (a, b) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        let labels = LabelSet::new(["a".into()]);
        assert_eq!(
            engine.evaluate(&labels, &Flow::icmp(a, b, 8)),
            rule(None, "echo")
        );
        assert_eq!(
            engine.evaluate(&labels, &Flow::icmp(a, b, 0)),
            Decision::Deny(reasons::DENIED)
        );
        assert_eq!(
            engine.evaluate(&labels, &Flow::ip(a, b, 47)),
            rule(None, "gre")
        );
        assert_eq!(
            engine.evaluate(&LabelSet::empty(), &Flow::ip(a, b, 47)),
            Decision::Deny(reasons::DENIED)
        );
    }

    #[test]
    fn failed_state_fails_closed() {
        let engine = AclEngine::new().with_not_installed(NotInstalled::Accept);
        engine.install(port_rules("web", 80));
        let generation = engine.generation();
        engine.fail();
        assert!(engine.generation() > generation);
        assert_eq!(engine.policy_state(), PolicyState::Failed);
        assert!(engine.rules().is_none());
        assert!(!engine.is_loaded());
        let web = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);
        assert_eq!(
            evaluate(&engine, &web),
            Decision::Deny(reasons::POLICY_FAILED)
        );
        // Namespace members are still governed by their namespaces.
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        assert!(engine.is_loaded());
        assert_eq!(
            evaluate(&engine, &key_req(1, "fd00::99", 22, Protocol::Tcp)),
            rule(Some("nsd:a"), "0")
        );
        assert_eq!(
            evaluate(&engine, &web),
            Decision::Deny(reasons::POLICY_FAILED)
        );
        // Installing recovers.
        engine.install(port_rules("web", 80));
        assert_eq!(evaluate(&engine, &web), rule(None, "web"));
    }

    #[test]
    fn clear_all_leaves_the_state_failed() {
        let (engine, clock) = manual_engine();
        let engine = Arc::try_unwrap(engine)
            .unwrap()
            .with_not_installed(NotInstalled::Accept);
        let engine = Arc::new(engine);
        engine.install(port_rules("web", 80));
        engine
            .store_namespace("app:s1", app(&[(2, "fd00::2")]))
            .unwrap();
        engine
            .store_grant(
                "g",
                Grant {
                    from: GrantEnd::Label(key_label(1)),
                    to: GrantEnd::Label(key_label(2)),
                    proto: None,
                    ports: None,
                },
            )
            .unwrap();
        let guard = engine
            .open_pinhole("app:s1", spec(2, 80, now(&clock) + Duration::from_secs(60)))
            .unwrap();
        engine.clear_all();
        assert_eq!(engine.policy_state(), PolicyState::Failed);
        assert!(!engine.is_loaded());
        assert!(engine.namespaces().is_empty() && engine.grants().is_empty());
        assert!(!guard.is_open());
        assert_eq!(engine.pinhole_stats().cleared, 1);
        // Fail closed even with `NotInstalled::Accept`.
        assert_eq!(
            evaluate(&engine, &req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp)),
            Decision::Deny(reasons::POLICY_FAILED)
        );
        // `uninstall` returns to `NotInstalled`, whose action is kept.
        engine.uninstall();
        assert_eq!(engine.policy_state(), PolicyState::NotInstalled);
        assert_eq!(
            evaluate(&engine, &req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp)),
            Decision::Accept(Matched::NotInstalled)
        );
    }

    #[test]
    fn engine_failed_reload_keeps_previous_rules() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        let before = engine.rules().unwrap();

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
            Err(Error::TestsFailed { count: 1 })
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

        let after = engine.rules().unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert!(evaluate(&engine, &req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp)).is_accept());
    }

    #[test]
    fn engine_concurrent_readers_during_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Set A accepts port 80 by rule "a"; set B by rule "b" (after a rule
        // for 443). Readers must only ever observe one of the two whole sets
        // (or the not-installed state), never a mix.
        let set_a = Arc::new(port_rules("a", 80));
        let set_b = Arc::new(
            RuleSet::new([
                Rule::new("b443", vec![ProtocolMatch::Tcp(PortSet::single(443))]),
                Rule::new("b", vec![ProtocolMatch::Tcp(PortSet::single(80))]),
            ])
            .unwrap(),
        );
        let engine = AclEngine::new();
        engine.install(Arc::clone(&set_a));
        let stop = AtomicBool::new(false);
        let request = req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp);

        std::thread::scope(|s| {
            let readers: Vec<_> = (0..4)
                .map(|_| {
                    s.spawn(|| {
                        let mut seen = 0u64;
                        loop {
                            let d = evaluate(&engine, &request);
                            assert!(
                                d == rule(None, "a")
                                    || d == rule(None, "b")
                                    || d == Decision::Deny(reasons::NO_POLICY),
                                "{d:?}"
                            );
                            // A snapshot stays stable across evaluations.
                            if let Some(rules) = engine.rules() {
                                let first = matched(&rules, &request);
                                assert_eq!(first, matched(&rules, &request));
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
                    0 => engine.install(Arc::clone(&set_b)),
                    1 => engine.install(Arc::clone(&set_a)),
                    _ => engine.uninstall(),
                }
            }
            stop.store(true, Ordering::Relaxed);
            for reader in readers {
                assert!(reader.join().unwrap() > 0);
            }
        });
    }

    // ── namespaces and grants ─────────────────────────────────────────────

    /// A namespace with members `(key byte, address)` accepting `port` from anyone.
    fn ns(members: &[(u8, &str)], port: u16) -> NamespacePolicy {
        NamespacePolicy {
            members: members
                .iter()
                .map(|(byte, address)| NamespaceMember {
                    label: key_label(*byte),
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
        assert!(engine.rules().is_none());
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
        assert!(evaluate(&engine, &key_req(1, "fd00::99", 443, Protocol::Tcp)).is_accept());
        assert!(!evaluate(&engine, &key_req(1, "fd00::99", 80, Protocol::Tcp)).is_accept());
        assert!(evaluate(&engine, &key_req(2, "fd00::99", 22, Protocol::Tcp)).is_accept());
        assert_eq!(
            engine.memberships(&key_label(3)),
            vec![NamespaceId::from("nsd:a")]
        );

        // Remove nsd:a: its members leave, quick stays.
        assert!(engine.remove_namespace("nsd:a"));
        assert!(!engine.remove_namespace("nsd:a"));
        assert!(Arc::ptr_eq(&quick, &namespace_ptr(&engine, "quick")));
        assert_eq!(engine.namespaces(), vec![NamespaceId::from("quick")]);
        assert_eq!(engine.memberships(&key_label(1)), Vec::<NamespaceId>::new());
        // A former member falls back to the (not installed) default rules.
        assert_eq!(
            evaluate(&engine, &key_req(1, "fd00::99", 443, Protocol::Tcp)),
            Decision::Deny(reasons::NO_POLICY)
        );

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
            Err(Error::TestsFailed { count: 1 })
        ));
        assert!(engine.store_namespace("nsd:new", failing).is_err());
        let mut bad_outbound = ns(&[(1, "fd00::1")], 443);
        bad_outbound.outbound = Some(vec![OutboundRule {
            proto: Some("icmp".to_owned()),
            ports: "*".to_owned(),
        }]);
        assert!(matches!(
            engine.store_namespace("nsd:a", bad_outbound.clone()),
            Err(Error::InvalidNamespace { id, .. }) if id.as_str() == "nsd:a"
        ));
        bad_outbound.outbound = Some(vec![OutboundRule {
            proto: None,
            ports: "9-1".to_owned(),
        }]);
        assert!(engine.store_namespace("nsd:a", bad_outbound).is_err());

        assert!(Arc::ptr_eq(&before, &namespace_ptr(&engine, "nsd:a")));
        assert_eq!(engine.namespaces(), vec![NamespaceId::from("nsd:a")]);
        assert!(evaluate(&engine, &key_req(1, "fd00::99", 80, Protocol::Tcp)).is_accept());
    }

    #[test]
    fn rules_of_all_namespaces_of_a_label_apply() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 80))
            .unwrap();
        engine
            .store_namespace("quick", ns(&[(1, "fd00::1"), (2, "fd00::2")], 22))
            .unwrap();
        assert_eq!(
            engine.memberships(&key_label(1)),
            vec![NamespaceId::from("nsd:a"), NamespaceId::from("quick")]
        );
        let to_local = |port| evaluate(&engine, &key_req(1, "fd00::99", port, Protocol::Tcp));
        assert_eq!(to_local(80), rule(Some("nsd:a"), "0"));
        assert_eq!(to_local(22), rule(Some("quick"), "0"));
        assert_eq!(to_local(443), Decision::Deny(reasons::DENIED));
        // Towards peer 2 only the shared namespace applies.
        assert!(evaluate(&engine, &key_req(1, "fd00::2", 22, Protocol::Tcp)).is_accept());
        assert!(!evaluate(&engine, &key_req(1, "fd00::2", 80, Protocol::Tcp)).is_accept());
    }

    #[test]
    fn a_source_is_a_member_through_each_of_its_labels() {
        let engine = AclEngine::new();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 80))
            .unwrap();
        let mut restricted = ns(&[(2, "fd00::2")], 22);
        restricted.outbound = Some(Vec::new());
        engine.store_namespace("quick", restricted).unwrap();
        let both = LabelSet::new([Label::from(anchor(1)), Label::from(anchor(2))]);
        let to_local =
            |port| engine.evaluate(&both, &flow("fd00::ff", "fd00::99", port, Protocol::Tcp));
        assert_eq!(to_local(80), rule(Some("nsd:a"), "0"));
        assert_eq!(to_local(22), rule(Some("quick"), "0"));
        let snapshot = engine.snapshot();
        let union = snapshot.membership_of(&both).unwrap();
        assert_eq!(
            union.namespaces,
            vec![NamespaceId::from("nsd:a"), NamespaceId::from("quick")]
        );
        // Restricted only when every namespace is.
        assert!(!union.outbound_restricted());
        assert!(
            snapshot
                .membership_of(&key_labels(2))
                .unwrap()
                .outbound_restricted()
        );
        assert!(snapshot.membership_of(&key_labels(3)).is_none());
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
        assert_eq!(
            evaluate(&engine, &key_req(1, "fd00::3", 22, Protocol::Tcp)),
            Decision::Deny(reasons::CROSS_NAMESPACE)
        );
        assert!(evaluate(&engine, &key_req(3, "fd00::3", 22, Protocol::Tcp)).is_accept());
        assert!(!evaluate(&engine, &key_req(3, "fd00::4", 22, Protocol::Tcp)).is_accept());
        assert!(evaluate(&engine, &key_req(2, "fd00::4", 22, Protocol::Tcp)).is_accept());
    }

    #[test]
    fn pinhole_namespaces_never_widen_permissions() {
        let engine = AclEngine::new();
        let with_rules = NamespacePolicy {
            kind: NamespaceKind::Pinholes,
            ..ns(&[(1, "fd00::1")], 22)
        };
        assert!(matches!(
            engine.store_namespace("s1", with_rules),
            Err(Error::InvalidNamespace { .. })
        ));
        let mut pinholes = app(&[(1, "fd00::1")]);
        pinholes.pinhole_kinds.insert("transfer".to_owned());
        assert!(matches!(
            engine.store_namespace("s1", pinholes.clone()),
            Err(Error::InvalidNamespace { .. })
        ));
        // Allowed on a rule namespace; the id means nothing.
        pinholes.kind = NamespaceKind::Rules;
        engine.store_namespace("app:x", pinholes).unwrap();
        // Outbound rules are allowed on a pinhole namespace.
        let mut session = app(&[(2, "fd00::2")]);
        session.outbound = Some(Vec::new());
        engine.store_namespace("s1", session).unwrap();
        assert_eq!(
            engine.memberships(&key_label(2)),
            vec![NamespaceId::from("s1")]
        );
        // A member only of a pinhole namespace gets nothing, even with
        // permissive default rules.
        engine.install(RuleSet::new([Rule::new("all", vec![ProtocolMatch::Any])]).unwrap());
        assert!(!evaluate(&engine, &key_req(2, "fd00::99", 22, Protocol::Tcp)).is_accept());
    }

    #[test]
    fn sources_in_no_namespace_use_the_default_rules() {
        let engine = AclEngine::new();
        engine.load(port_policy(80)).unwrap();
        engine
            .store_namespace("nsd:a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        let rules = engine.rules().unwrap();
        for request in [
            req("10.0.0.1", "10.0.0.2", 80, Protocol::Tcp),
            req("fd00::5", "fd00::1", 22, Protocol::Tcp),
            key_req(2, "fd00::1", 80, Protocol::Tcp),
            key_req(2, "fd00::1", 22, Protocol::Tcp),
        ] {
            // `RuleSet::matching` equals `evaluate` for them.
            let expected = matched(&rules, &request)
                .map_or(Decision::Deny(reasons::DENIED), |id| rule(None, &id));
            assert_eq!(evaluate(&engine, &request), expected);
        }
        // The default rules ignore namespaces, even for members.
        assert!(!allowed(&rules, &key_req(1, "fd00::99", 22, Protocol::Tcp)));
        assert!(evaluate(&engine, &key_req(1, "fd00::99", 22, Protocol::Tcp)).is_accept());
        // uninstall removes only the default rules.
        engine.uninstall();
        assert!(engine.is_loaded());
        assert!(evaluate(&engine, &key_req(1, "fd00::99", 22, Protocol::Tcp)).is_accept());
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
            to: GrantEnd::Label(key_label(2)),
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
                Err(Error::InvalidGrant { id, .. }) if id.as_str() == "bad"
            ));
        }
        assert_eq!(engine.grants(), Vec::new());

        assert_eq!(
            evaluate(&engine, &key_req(1, "fd00::2", 5005, Protocol::Udp)),
            Decision::Deny(reasons::CROSS_NAMESPACE)
        );
        engine.store_grant("g1", grant.clone()).unwrap();
        assert_eq!(engine.grants(), vec![(RuleId::from("g1"), grant)]);
        let d = evaluate(&engine, &key_req(1, "fd00::2", 5005, Protocol::Udp));
        assert_eq!(d, Decision::Accept(Matched::Grant("g1".into())));
        assert_eq!(d.rule_id().map(RuleId::as_str), Some("g1"));
        assert!(!evaluate(&engine, &key_req(1, "fd00::2", 5011, Protocol::Udp)).is_accept());
        assert!(!evaluate(&engine, &key_req(1, "fd00::2", 5005, Protocol::Tcp)).is_accept());
        assert!(!evaluate(&engine, &key_req(2, "fd00::1", 5005, Protocol::Udp)).is_accept());
        assert!(engine.remove_grant("g1"));
        assert_eq!(engine.grants(), Vec::new());
        assert!(!evaluate(&engine, &key_req(1, "fd00::2", 5005, Protocol::Udp)).is_accept());
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
                .membership(&key_label(1))
                .unwrap()
                .outbound_restricted()
        );
        assert!(
            !snapshot
                .membership(&key_label(2))
                .unwrap()
                .outbound_restricted()
        );
        assert!(snapshot.membership(&key_label(3)).is_none());
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
                            let d = evaluate(&engine, &request);
                            assert!(
                                d == rule(Some("nsd:a"), "0")
                                    || d == rule(Some("nsd:a"), "1")
                                    || d == Decision::Deny(reasons::NO_POLICY),
                                "{d:?}"
                            );
                            assert!(evaluate(&engine, &other).is_accept());
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
    fn grants_cannot_name_pinhole_namespaces() {
        let engine = AclEngine::new();
        engine
            .store_namespace("s1", app(&[(1, "fd00::1"), (2, "fd00::2")]))
            .unwrap();
        engine
            .store_namespace("team-a", ns(&[(1, "fd00::1")], 22))
            .unwrap();
        for (from, to) in [
            (
                GrantEnd::Namespace("s1".into()),
                GrantEnd::Label(key_label(2)),
            ),
            (
                GrantEnd::Label(key_label(1)),
                GrantEnd::Namespace("s1".into()),
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
                Err(Error::InvalidGrant { .. })
            ));
        }
        assert_eq!(engine.grants(), Vec::new());
        // A grant naming a namespace that later becomes a pinhole namespace
        // stops matching it.
        let grant = Grant {
            from: GrantEnd::Namespace("team-a".into()),
            to: GrantEnd::Label(key_label(2)),
            proto: None,
            ports: None,
        };
        engine.store_grant("g", grant).unwrap();
        let to_peer2 = key_req(1, "fd00::2", 22, Protocol::Tcp);
        assert_eq!(
            evaluate(&engine, &to_peer2),
            Decision::Accept(Matched::Grant("g".into()))
        );
        engine
            .store_namespace("team-a", app(&[(1, "fd00::1")]))
            .unwrap();
        assert_eq!(
            evaluate(&engine, &to_peer2),
            Decision::Deny(reasons::CROSS_NAMESPACE)
        );
    }

    #[test]
    fn label_grant_ends_and_the_smallest_owner_of_a_shared_address() {
        let engine = AclEngine::new();
        // "host:a" and "host:b" both own fd00::5; "host:a" is the smaller.
        let member = |label: &str, address: &str| NamespaceMember {
            label: label.into(),
            addresses: vec![address.parse().unwrap()],
        };
        let namespace = |members| NamespacePolicy {
            members,
            ..NamespacePolicy::default()
        };
        engine
            .store_namespace("team-a", namespace(vec![member("host:a", "fd00::5")]))
            .unwrap();
        engine
            .store_namespace("team-b", namespace(vec![member("host:b", "fd00::5")]))
            .unwrap();
        engine
            .store_namespace("team-c", namespace(vec![member("team-c", "fd00::9")]))
            .unwrap();
        let grant = |to: &str| Grant {
            from: GrantEnd::Label("team-c".into()),
            to: GrantEnd::Label(to.into()),
            proto: Some("tcp".to_owned()),
            ports: Some("80".to_owned()),
        };
        let source = LabelSet::new(["team-c".into(), "extra".into()]);
        let to_shared = flow("fd00::9", "fd00::5", 80, Protocol::Tcp);
        engine.store_grant("to-b", grant("host:b")).unwrap();
        assert_eq!(
            engine.evaluate(&source, &to_shared),
            Decision::Deny(reasons::CROSS_NAMESPACE)
        );
        engine.store_grant("to-a", grant("host:a")).unwrap();
        assert_eq!(
            engine.evaluate(&source, &to_shared),
            Decision::Accept(Matched::Grant("to-a".into()))
        );
        // The source end matches any label of the source's set.
        assert_eq!(
            engine.evaluate(&LabelSet::new(["extra".into()]), &to_shared),
            Decision::Deny(reasons::NO_POLICY)
        );
        // A namespace end matches the owner's namespaces.
        engine.remove_grant("to-a");
        engine
            .store_grant(
                "ns",
                Grant {
                    to: GrantEnd::Namespace("team-a".into()),
                    ..grant("host:a")
                },
            )
            .unwrap();
        assert!(engine.evaluate(&source, &to_shared).is_accept());
    }

    #[test]
    fn a_multi_label_source_bypasses_when_its_open_namespaces_cover_every_owner() {
        let engine = AclEngine::new();
        let open = |members: &[(u8, &str)]| NamespacePolicy {
            policy: make_policy(vec![accept_rule(&["*"], &["*:*"], None)], vec![]),
            ..ns(members, 0)
        };
        engine
            .store_namespace("team-a", open(&[(1, "fd00::1")]))
            .unwrap();
        engine
            .store_namespace("team-b", open(&[(2, "fd00::2")]))
            .unwrap();
        let snapshot = engine.snapshot();
        let bypasses =
            |labels: &LabelSet| snapshot.bypasses(snapshot.membership_of(labels).as_deref());
        // Each label alone shares an open namespace with one owner only.
        assert!(!bypasses(&key_labels(1)));
        assert!(!bypasses(&key_labels(2)));
        let both = LabelSet::new([key_label(1), key_label(2)]);
        assert!(bypasses(&both));
        drop(snapshot);
        // Restricted through every namespace: no bypass.
        let mut restricted = open(&[(1, "fd00::1")]);
        restricted.outbound = Some(Vec::new());
        engine.store_namespace("team-a", restricted).unwrap();
        let mut restricted = open(&[(2, "fd00::2")]);
        restricted.outbound = Some(Vec::new());
        engine.store_namespace("team-b", restricted).unwrap();
        let snapshot = engine.snapshot();
        assert!(!snapshot.bypasses(snapshot.membership_of(&both).as_deref()));
    }

    #[test]
    fn a_pinhole_serves_every_source_carrying_its_label() {
        let (engine, clock) = manual_engine();
        engine
            .store_namespace("team-a", source(&[(1, "fd00::1")], &["transfer"]))
            .unwrap();
        engine
            .store_namespace("s1", app(&[(1, "fd00::1"), (2, "fd00::2")]))
            .unwrap();
        let later = now(&clock) + Duration::from_secs(60);
        // Label 1 is permitted by team-a's pinhole kinds; label 2 is only in
        // the pinhole namespace.
        let first = engine.open_pinhole("s1", spec(1, 80, later)).unwrap();
        assert_eq!(
            engine
                .open_pinhole("s1", spec(1, 81, later))
                .map(|g| g.id()),
            Ok(PinholeId::new(2))
        );
        let other = PinholeSpec {
            kind: "chat".to_owned(),
            ..spec(1, 82, later)
        };
        assert_eq!(
            engine.open_pinhole("s1", other).map(|g| g.id()),
            Err(PinholeError::NotPermitted)
        );
        let flow = flow("fd00::ff", "fd00::99", 80, Protocol::Tcp);
        let both = LabelSet::new([key_label(3), key_label(1)]);
        assert_eq!(
            engine.evaluate(&both, &flow),
            Decision::Accept(Matched::Pinhole(first.id()))
        );
        // A source without the label does not use it.
        assert_eq!(
            engine.evaluate(&key_labels(2), &flow),
            Decision::Deny(reasons::DENIED)
        );
        // Stored again as a rule namespace, it holds no pinhole.
        engine
            .store_namespace("s1", source(&[(1, "fd00::1"), (2, "fd00::2")], &[]))
            .unwrap();
        assert!(!first.is_open());
        assert_eq!(engine.pinhole_stats().revoked, 1);
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

    /// A rule namespace of `members` without rules, permitting pinholes of
    /// `kinds`.
    fn source(members: &[(u8, &str)], kinds: &[&str]) -> NamespacePolicy {
        NamespacePolicy {
            policy: AclPolicy::default(),
            pinhole_kinds: kinds.iter().map(ToString::to_string).collect(),
            ..ns(members, 0)
        }
    }

    /// A pinhole namespace of `members`.
    fn app(members: &[(u8, &str)]) -> NamespacePolicy {
        NamespacePolicy {
            kind: NamespaceKind::Pinholes,
            ..source(members, &[])
        }
    }

    fn spec(peer: u8, port: u16, expires_at: Instant) -> PinholeSpec {
        PinholeSpec {
            label: key_label(peer),
            kind: "transfer".to_owned(),
            protocol: Protocol::Tcp,
            direction: Direction::Inbound,
            dst_port: port,
            expires_at,
        }
    }

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
            Err(PinholeError::NotPinholeNamespace)
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
        assert!(!evaluate(&engine, &request).is_accept());

        let guard = engine.open_pinhole("app:s1", spec(2, 80, later)).unwrap();
        assert_eq!(
            evaluate(&engine, &request),
            Decision::Accept(Matched::Pinhole(guard.id()))
        );
        // Only that port, protocol and direction, and only to the local node.
        assert!(!evaluate(&engine, &key_req(2, "fd00::99", 81, Protocol::Tcp)).is_accept());
        assert!(!evaluate(&engine, &key_req(2, "fd00::99", 80, Protocol::Udp)).is_accept());
        let (labels, _) = &request;
        let icmp = Flow::icmp(
            "fd00::ff".parse().unwrap(),
            "fd00::99".parse().unwrap(),
            128,
        );
        assert_eq!(
            engine.evaluate(labels, &icmp),
            Decision::Deny(reasons::DENIED)
        );
        engine
            .store_namespace("nsd:x", ns(&[(5, "fd00::5")], 22))
            .unwrap();
        assert!(!evaluate(&engine, &key_req(2, "fd00::5", 80, Protocol::Tcp)).is_accept());

        guard.close();
        assert!(!evaluate(&engine, &request).is_accept());
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
        assert_eq!(evaluate(&engine, &request), Decision::Deny(reasons::DENIED));
        assert_eq!(engine.pinhole_stats().expired, 1);
        assert_eq!(engine.expire_pinholes(), 0);
        assert!(long.is_open());

        // Swept by the next mutation.
        advance(&clock, 20);
        engine.uninstall();
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
