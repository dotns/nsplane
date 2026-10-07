//! [`AclFilter`]: a sans-I/O [`PacketFilter`] enforcing the ACL policy on
//! inbound packets and the outbound rules of restricted peers.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{FiveTuple, IcmpHeader, IpPacket, PacketBuf, PeerId, protocol};

use crate::engine::{AclEngine, Evaluation, Membership, PinholeMatch, ReplyDependency, Snapshot};
use crate::lru::{FlowHash, LruMap};
use crate::net::{IpNet, Protocol};
use crate::pinhole::Direction;
use crate::reasons;
use crate::rules::{Flow, LabelSet, PolicyState, Transport};

// ── Peer identity ─────────────────────────────────────────────────────────────

/// Resolves the [`LabelSet`] of a peer: the labels the rules, namespaces,
/// grants and pinholes see for its packets.
///
/// Implemented by closures `Fn(PeerId) -> Option<LabelSet>`, by
/// [`PeerLabelMap`] and by `Arc<T>` of any implementation, so a caller can
/// keep a handle to update the labels while the filter uses them.
pub trait PeerIdentity: Send + Sync + 'static {
    /// The labels of `peer`; `None`: unknown peer (its inbound packets are
    /// dropped with [`reasons::UNKNOWN_PEER`]).
    fn labels(&self, peer: PeerId) -> Option<LabelSet>;

    /// The labels of `peer` for a packet whose remote address is `remote`:
    /// the IP source of an inbound packet, the IP destination of an
    /// outbound one. [`AclFilter`] resolves every source through this
    /// method.
    ///
    /// The default ignores `remote` and returns [`labels`](Self::labels).
    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        let _ = remote;
        self.labels(peer)
    }

    /// Whether [`labels_for`](Self::labels_for) of `peer` depends on the
    /// address. [`AclFilter`] asks once per peer and identity generation,
    /// then caches the labels of such a peer per address, and of any other
    /// peer per peer; so a versioned implementation must return `true` for
    /// every peer whose labels depend on the address. Default `false`.
    fn by_source(&self, peer: PeerId) -> bool {
        let _ = peer;
        false
    }

    /// The identity generation: a non-zero value that changes whenever any
    /// answer may have changed (bumped once the change is visible to
    /// [`labels_for`](Self::labels_for) and [`by_source`](Self::by_source)).
    /// [`AclFilter`] caches the resolved peers and the flow verdicts under
    /// it.
    ///
    /// The default, 0, means "not versioned": the filter then resolves the
    /// peer and evaluates the policy on every packet (no label cache, no
    /// flow verdict cache, no bypass), so correctness never depends on it.
    /// Closures keep the default; [`PeerLabelMap`] is versioned.
    fn generation(&self) -> u64 {
        0
    }
}

impl<F> PeerIdentity for F
where
    F: Fn(PeerId) -> Option<LabelSet> + Send + Sync + 'static,
{
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        self(peer)
    }
}

impl<T: PeerIdentity + ?Sized> PeerIdentity for Arc<T> {
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        (**self).labels(peer)
    }

    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        (**self).labels_for(peer, remote)
    }

    fn by_source(&self, peer: PeerId) -> bool {
        (**self).by_source(peer)
    }

    fn generation(&self) -> u64 {
        (**self).generation()
    }
}

/// A concurrent, versioned map from peers to their labels.
///
/// Wrap it in an `Arc` and hand a clone to the filter to update it at runtime.
/// Every [`insert`](Self::insert), [`insert_by_source`](Self::insert_by_source)
/// and [`remove`](Self::remove) bumps its
/// [generation](PeerIdentity::generation) under its write lock, so the
/// filter's cached labels and verdicts never outlive a change.
#[derive(Debug)]
pub struct PeerLabelMap {
    map: RwLock<HashMap<PeerId, Entry>>,
    generation: AtomicU64,
}

/// The labels of a peer in a [`PeerLabelMap`].
#[derive(Debug)]
enum Entry {
    Labels(LabelSet),
    /// Labels per remote address, longest prefix first.
    BySource(Vec<(IpNet, LabelSet)>),
}

impl Default for PeerLabelMap {
    fn default() -> Self {
        Self {
            map: RwLock::default(),
            generation: AtomicU64::new(1),
        }
    }
}

impl PeerLabelMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the labels of `peer`, replacing any previous entry.
    pub fn insert(&self, peer: PeerId, labels: LabelSet) {
        self.set(peer, Entry::Labels(labels));
    }

    /// Set the labels of `peer` per remote address, replacing any previous
    /// entry: the longest prefix of `by_address` containing the address wins
    /// (the first one listed among equally long prefixes), and an address
    /// outside every prefix makes the source unknown. For a peer whose
    /// packets carry several source addresses.
    /// [`labels`](PeerIdentity::labels) of such a peer is `None`.
    pub fn insert_by_source(&self, peer: PeerId, mut by_address: Vec<(IpNet, LabelSet)>) {
        // Stable: equally long prefixes keep their order.
        by_address.sort_by_key(|(net, _)| std::cmp::Reverse(net.prefix_len()));
        self.set(peer, Entry::BySource(by_address));
    }

    fn set(&self, peer: PeerId, entry: Entry) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        map.insert(peer, entry);
        // Still under the write lock: a reader seeing the new generation
        // also sees the new labels.
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<PeerId, Entry>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remove the entry of `peer`; the peer becomes unknown.
    pub fn remove(&self, peer: PeerId) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        map.remove(&peer);
        self.generation.fetch_add(1, Ordering::Release);
    }
}

impl PeerIdentity for PeerLabelMap {
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        match self.read().get(&peer)? {
            Entry::Labels(labels) => Some(labels.clone()),
            Entry::BySource(_) => None,
        }
    }

    fn labels_for(&self, peer: PeerId, remote: IpAddr) -> Option<LabelSet> {
        match self.read().get(&peer)? {
            Entry::Labels(labels) => Some(labels.clone()),
            Entry::BySource(by_address) => by_address
                .iter()
                .find(|(net, _)| net.contains(&remote))
                .map(|(_, labels)| labels.clone()),
        }
    }

    fn by_source(&self, peer: PeerId) -> bool {
        matches!(self.read().get(&peer), Some(Entry::BySource(_)))
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

// ── Configuration and statistics ──────────────────────────────────────────────

/// Settings of an [`AclFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclFilterConfig {
    /// Maximum number of fragmented packets whose first-fragment verdict is
    /// remembered (at least 1). When full, the oldest entry is evicted.
    /// Default 1024.
    pub fragment_capacity: usize,
    /// Accept inbound packets that are neither TCP nor UDP (ICMP, IPv6
    /// fragments, ...) without consulting the policy, and track ICMP echo
    /// replies. Default `false`: such packets are dropped.
    pub allow_other_protocols: bool,
    /// Accept inbound replies to flows the local side opened (stateful
    /// replies, not a conntrack/NAT). Default `true`.
    ///
    /// When `false` the filter records no reply allowance in either
    /// direction: outbound TCP, UDP and ICMP echo packets record no inbound
    /// allowance, accepted inbound flows from outbound-restricted peers
    /// record no outbound allowance (their replies need an outbound rule or
    /// an outbound pinhole), and no pending dependency is kept. Every inbound
    /// packet is then judged by the policy alone. The only state left is the
    /// flow verdict cache, which is exact: a verdict is reused only under the
    /// policy and identity generations it was computed under, a pinhole
    /// verdict is checked against the pinhole's expiry on every hit, and an
    /// expired-pinhole verdict is never cached, so a hit equals a fresh
    /// evaluation (checked by the differential tests).
    pub stateful_replies: bool,
    /// Maximum number of reply allowances (at least 1). When full, the least
    /// recently seen entry is evicted. Default 4096.
    pub reply_capacity: usize,
    /// How long a reply allowance lives without traffic. Default 120 s.
    pub reply_idle_timeout: Duration,
    /// How inbound non-first IPv4 fragments are gated. Default
    /// [`FragmentMode::Outcome`].
    pub fragments: FragmentMode,
    /// Accept an inbound IPv4 packet (at least 20 bytes) whose destination
    /// is this address without consulting the policy, before anything else
    /// (counted in [`AclFilterStats::bypassed`]). Default `None`.
    pub accept_to_local: Option<Ipv4Addr>,
    /// Accept an inbound IPv4 ICMP echo reply without consulting the policy,
    /// after [`accept_to_local`](Self::accept_to_local) and before anything
    /// else (counted in [`AclFilterStats::bypassed`]). The check reads the
    /// raw header: IPv4, a header length of at least 20 bytes, at least 8
    /// bytes after it, protocol 1 and type 0; a non-first fragment passing
    /// it is accepted too. Default `false`.
    pub accept_icmp_echo_reply: bool,
    /// Whether IPv6 packets are evaluated. Default [`Ipv6Mode::Evaluate`].
    ///
    /// [`Ipv6Mode::Accept`] passes every IPv6 packet (version nibble 6), in
    /// both directions, before anything else and without recording any
    /// state (counted in [`AclFilterStats::ipv6_accepted`]). ns runs no ACL
    /// on IPv6: its account filter only checks where an inbound IPv6 packet
    /// is addressed, which nsplane does in the core with a peer's
    /// `inbound_destinations` (`nsplane-core` `PeerConfig`), and it has no
    /// outbound ACL.
    pub ipv6: Ipv6Mode,
}

impl Default for AclFilterConfig {
    fn default() -> Self {
        Self {
            fragment_capacity: 1024,
            allow_other_protocols: false,
            stateful_replies: true,
            reply_capacity: 4096,
            reply_idle_timeout: Duration::from_secs(120),
            fragments: FragmentMode::Outcome,
            accept_to_local: None,
            accept_icmp_echo_reply: false,
            ipv6: Ipv6Mode::Evaluate,
        }
    }
}

impl AclFilterConfig {
    /// The settings of the ACL step of an ns account: for inbound IPv4
    /// packets the filter equals ns `is_local_node_packet(pkt, local) ||
    /// is_icmp_echo_reply(pkt) || acl_check_packet(..)` (the first term only
    /// when `local` is set), with the labels of a [`PeerLabelMap`] built as
    /// `docs/specs/acl-source-identity.md` describes.
    ///
    /// That is: no reply allowances ([`stateful_replies`](Self::stateful_replies)
    /// off), protocols other than TCP and UDP dropped, IPv4 fragments gated by
    /// [`FragmentMode::ALLOW_ONLY`], `local` in
    /// [`accept_to_local`](Self::accept_to_local) and
    /// [`accept_icmp_echo_reply`](Self::accept_icmp_echo_reply) on, and IPv6
    /// packets accepted unevaluated ([`Ipv6Mode::Accept`], as ns: IPv6 is
    /// authorized by the core's inbound destinations). Drop reasons follow
    /// this filter (a packet ns drops is dropped here, possibly with another
    /// reason), and outbound IPv4 packets keep this filter's handling.
    pub fn crates_acl(local: Option<Ipv4Addr>) -> Self {
        Self {
            allow_other_protocols: false,
            stateful_replies: false,
            fragments: FragmentMode::ALLOW_ONLY,
            accept_to_local: local,
            accept_icmp_echo_reply: true,
            ipv6: Ipv6Mode::Accept,
            ..Self::default()
        }
    }
}

/// Per-filter address scopes of an [`AclFilter`] (beyond [`AclFilterConfig`]).
///
/// Built with [`new`](Self::new) and the `with_*` setters; the default scopes
/// nothing and costs nothing on the packet path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AclFilterScope {
    /// Allowed source prefixes of outbound packets. `None` (default): no check.
    ///
    /// When set, every outbound packet (to any peer, of any protocol, every
    /// fragment included) whose source address is in none of the prefixes is
    /// dropped with [`reasons::OUTBOUND_SOURCE`] before the destination rules,
    /// the outbound pinholes and the reply allowances are consulted, and
    /// leaves no state. The source address is read from the raw IPv4 or IPv6
    /// header; a packet too short to hold it (or of another IP version) is
    /// dropped too. An empty list drops every outbound packet.
    /// [`Ipv6Mode::Accept`] still passes IPv6 packets unevaluated.
    pub outbound_sources: Option<Vec<IpNet>>,
    /// Accept rules for inbound packets that are neither TCP nor UDP, scoped to
    /// destinations. Empty (default): today's handling (dropped unless
    /// [`AclFilterConfig::allow_other_protocols`]).
    ///
    /// Checked after the reply allowances and `allow_other_protocols`, still
    /// behind a loaded policy: a packet some rule matches is accepted (counted
    /// in [`AclFilterStats::accepted`]), any other is dropped with
    /// [`reasons::PROTOCOL`]. Non-first fragments follow their first fragment.
    /// With [`AclFilterConfig::stateful_replies`] on, an accepted packet from
    /// an outbound-restricted peer (other than an ICMP message that is not an
    /// echo request) allows its reply back to that peer, and an outbound ICMP
    /// echo request allows its inbound reply.
    pub other_protocols: Vec<OtherProtocolRule>,
}

/// An [`AclFilterScope::other_protocols`] rule: inbound packets of `protocol`
/// addressed to one of `destinations` are accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtherProtocolRule {
    /// The packets the rule applies to.
    pub protocol: OtherProtocol,
    /// The destination prefixes the rule accepts; empty accepts nothing.
    pub destinations: Vec<IpNet>,
}

impl OtherProtocolRule {
    /// A rule accepting `protocol` to `destinations`.
    #[must_use]
    pub fn new(protocol: OtherProtocol, destinations: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            protocol,
            destinations: destinations.into_iter().collect(),
        }
    }

    /// Whether the rule accepts `packet` (neither TCP nor UDP).
    fn accepts(&self, packet: &IpPacket<'_>) -> bool {
        let protocol = match self.protocol {
            OtherProtocol::IcmpEcho => echo_type(packet) == Some(EchoType::Request),
            OtherProtocol::Icmp => is_icmp(packet.protocol()),
            OtherProtocol::Ip(number) => packet.protocol() == number,
        };
        protocol
            && self
                .destinations
                .iter()
                .any(|net| net.contains(&packet.dst()))
    }
}

/// The packets an [`OtherProtocolRule`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtherProtocol {
    /// ICMP Echo request (type 8) and `ICMPv6` Echo request (type 128).
    IcmpEcho,
    /// Every ICMP and `ICMPv6` message.
    Icmp,
    /// Every packet with this IP protocol number (TCP and UDP never reach these rules).
    Ip(u8),
}

impl AclFilterScope {
    /// The default scope: no constraint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`outbound_sources`](Self::outbound_sources) to `prefixes`.
    #[must_use]
    pub fn with_outbound_sources(mut self, prefixes: impl IntoIterator<Item = IpNet>) -> Self {
        self.outbound_sources = Some(prefixes.into_iter().collect());
        self
    }

    /// Appends `rule` to [`other_protocols`](Self::other_protocols).
    #[must_use]
    pub fn with_other_protocol(mut self, rule: OtherProtocolRule) -> Self {
        self.other_protocols.push(rule);
        self
    }
}

/// Whether an [`AclFilter`] evaluates IPv6 packets
/// ([`AclFilterConfig::ipv6`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Ipv6Mode {
    /// IPv6 packets are judged like IPv4 packets.
    #[default]
    Evaluate,
    /// Every IPv6 packet, inbound and outbound (fragments, `ICMPv6` and
    /// packets malformed beyond the version included), is accepted
    /// unevaluated and leaves no flow, reply or fragment state.
    Accept,
}

/// How an [`AclFilter`] gates inbound non-first IPv4 fragments, which carry
/// no ports and follow their packet's first fragment.
///
/// IPv6 fragments and outbound fragments (to outbound-restricted peers) are
/// always gated as in [`Outcome`](Self::Outcome).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FragmentMode {
    /// The outcome of each first fragment, accepted or dropped, is recorded
    /// per peer, direction and (source, destination, protocol,
    /// identification); later fragments get the same outcome, the last one
    /// frees the entry, and a later fragment with no recorded first fragment
    /// is dropped with [`reasons::FRAGMENT`]. The table holds
    /// [`AclFilterConfig::fragment_capacity`] entries, evicting the oldest.
    #[default]
    Outcome,
    /// The ns `FragmentAclGate`: only accepted first fragments are recorded,
    /// keyed by (source, destination, protocol, identification) without the
    /// peer, until `ttl` after the first fragment on the engine clock
    /// ([`AclEngine::with_clock`]); the last fragment does not free the
    /// entry. A non-first fragment is judged before anything but the
    /// bypass flags (before the no-policy check): accepted when its entry is
    /// live, else dropped with [`reasons::FRAGMENT`] (an expired entry is
    /// removed). When the table holds `capacity` entries, the expired ones
    /// are removed first and, if it is still full, the new entry is not
    /// recorded (a live entry is never evicted).
    AllowOnly {
        /// How long an accepted first fragment admits its later fragments.
        ttl: Duration,
        /// Maximum number of recorded first fragments.
        capacity: usize,
    },
}

impl FragmentMode {
    /// [`AllowOnly`](Self::AllowOnly) with the values of ns: a TTL of 15 s
    /// and a capacity of 4096.
    pub const ALLOW_ONLY: Self = Self::AllowOnly {
        ttl: Duration::from_secs(15),
        capacity: 4096,
    };
}

/// Counters of an [`AclFilter`], in packets unless stated otherwise.
///
/// Non-first fragments count under the outcome of their first fragment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AclFilterStats {
    /// Inbound packets accepted by the policy (or as another protocol when
    /// [`AclFilterConfig::allow_other_protocols`] is set).
    pub accepted: u64,
    /// Inbound packets accepted through the reply table.
    pub replies: u64,
    /// Inbound packets dropped with [`reasons::DENIED`].
    pub denied: u64,
    /// Inbound packets dropped with [`reasons::NO_POLICY`].
    pub no_policy: u64,
    /// Inbound packets dropped with [`reasons::POLICY_FAILED`].
    pub policy_failed: u64,
    /// Inbound packets dropped with [`reasons::UNKNOWN_PEER`].
    pub unknown_peer: u64,
    /// Inbound packets dropped with [`reasons::PROTOCOL`].
    pub protocol: u64,
    /// Inbound packets dropped with [`reasons::FRAGMENT`].
    pub fragment: u64,
    /// Inbound packets dropped with [`reasons::MALFORMED`].
    pub malformed: u64,
    /// Fragment-table entries evicted because the table was full.
    pub fragment_evictions: u64,
    /// Reply-table entries evicted because the table was full.
    pub reply_evictions: u64,
    /// Reply-table entries found idle past the timeout and removed.
    pub reply_expired: u64,
    /// Inbound packets dropped with [`reasons::CROSS_NAMESPACE`].
    pub cross_namespace: u64,
    /// Outbound packets to outbound-restricted peers dropped with
    /// [`reasons::OUTBOUND`].
    pub outbound_denied: u64,
    /// Outbound packets to outbound-restricted peers accepted as replies to
    /// accepted inbound flows.
    pub outbound_replies: u64,
    /// Reply-table entries removed because what they depended on (a grant or
    /// a pinhole) is gone.
    pub reply_revoked: u64,
    /// Pending-dependency entries (the dependency of an inbound flow accepted
    /// through a grant, a pinhole or a dependent allowance) evicted because
    /// the table was full.
    pub pending_evictions: u64,
    /// Cached flow verdicts flushed to make room in the full flow table (the
    /// flows are evaluated again on their next packet).
    pub verdict_evictions: u64,
    /// Inbound packets accepted without the policy by
    /// [`AclFilterConfig::accept_to_local`] or
    /// [`AclFilterConfig::accept_icmp_echo_reply`].
    pub bypassed: u64,
    /// IPv6 packets, inbound and outbound, accepted unevaluated by
    /// [`Ipv6Mode::Accept`] (not counted in [`accepted`](Self::accepted)).
    pub ipv6_accepted: u64,
    /// Outbound packets dropped with [`reasons::OUTBOUND_SOURCE`].
    pub outbound_source: u64,
    /// Packets, inbound and outbound, dropped with [`reasons::INTERNAL`].
    pub internal: u64,
    /// The engine's [`PolicyState`] when the stats were read.
    pub policy_state: PolicyState,
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    replies: AtomicU64,
    denied: AtomicU64,
    no_policy: AtomicU64,
    policy_failed: AtomicU64,
    unknown_peer: AtomicU64,
    protocol: AtomicU64,
    fragment: AtomicU64,
    malformed: AtomicU64,
    fragment_evictions: AtomicU64,
    reply_evictions: AtomicU64,
    reply_expired: AtomicU64,
    cross_namespace: AtomicU64,
    outbound_denied: AtomicU64,
    outbound_replies: AtomicU64,
    reply_revoked: AtomicU64,
    pending_evictions: AtomicU64,
    verdict_evictions: AtomicU64,
    bypassed: AtomicU64,
    ipv6_accepted: AtomicU64,
    outbound_source: AtomicU64,
    internal: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The decision about one packet, before it becomes a [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Reply,
    /// Accepted by a bypass flag, without the policy.
    Bypassed,
    /// An IPv6 packet accepted unevaluated by [`Ipv6Mode::Accept`].
    Ipv6Accepted,
    Denied,
    CrossNamespace,
    NoPolicy,
    PolicyFailed,
    UnknownPeer,
    Protocol,
    Fragment,
    Malformed,
    /// An outbound packet accepted as today or by an outbound rule (not counted).
    OutboundAccepted,
    OutboundReply,
    OutboundDenied,
    /// An outbound packet whose source is outside [`AclFilterScope::outbound_sources`].
    OutboundSource,
    /// The filter's own tables failed an invariant (fail-closed).
    Internal,
}

impl Outcome {
    const fn verdict(self) -> Verdict {
        let reason = match self {
            Self::Accepted
            | Self::Reply
            | Self::Bypassed
            | Self::Ipv6Accepted
            | Self::OutboundAccepted
            | Self::OutboundReply => {
                return Verdict::Accept;
            }
            Self::Denied => reasons::DENIED,
            Self::CrossNamespace => reasons::CROSS_NAMESPACE,
            Self::NoPolicy => reasons::NO_POLICY,
            Self::PolicyFailed => reasons::POLICY_FAILED,
            Self::UnknownPeer => reasons::UNKNOWN_PEER,
            Self::Protocol => reasons::PROTOCOL,
            Self::Fragment => reasons::FRAGMENT,
            Self::Malformed => reasons::MALFORMED,
            Self::OutboundDenied => reasons::OUTBOUND,
            Self::OutboundSource => reasons::OUTBOUND_SOURCE,
            Self::Internal => reasons::INTERNAL,
        };
        Verdict::Drop { reason }
    }

    fn count(self, counters: &Counters) {
        bump(match self {
            Self::Accepted => &counters.accepted,
            Self::Reply => &counters.replies,
            Self::Bypassed => &counters.bypassed,
            Self::Ipv6Accepted => &counters.ipv6_accepted,
            Self::Denied => &counters.denied,
            Self::CrossNamespace => &counters.cross_namespace,
            Self::NoPolicy => &counters.no_policy,
            Self::PolicyFailed => &counters.policy_failed,
            Self::UnknownPeer => &counters.unknown_peer,
            Self::Protocol => &counters.protocol,
            Self::Fragment => &counters.fragment,
            Self::Malformed => &counters.malformed,
            Self::OutboundAccepted => return,
            Self::OutboundReply => &counters.outbound_replies,
            Self::OutboundDenied => &counters.outbound_denied,
            Self::OutboundSource => &counters.outbound_source,
            Self::Internal => &counters.internal,
        });
    }
}

// ── Bounded tables ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    peer: PeerId,
    outbound: bool,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u16,
}

/// First-fragment outcomes in insertion order; when full, the oldest is
/// evicted (O(1)). `allowed` is the table of [`FragmentMode::AllowOnly`]:
/// the engine-clock time each accepted first fragment was recorded.
#[derive(Debug, Default)]
struct FragmentTable {
    entries: LruMap<FragmentKey, Outcome>,
    allowed: HashMap<AllowedKey, Instant>,
}

/// The key of [`FragmentMode::AllowOnly`]: no peer, no direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AllowedKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    id: u16,
}

/// The fragment fields of a raw IPv4 header (at least 20 bytes, version 4),
/// as ns `ipv4_fragment_meta` reads them: the key, the offset is non-zero,
/// the first fragment of several.
const fn ipv4_fragment(bytes: &[u8]) -> Option<(AllowedKey, bool, bool)> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let flags = u16::from_be_bytes([bytes[6], bytes[7]]);
    let key = AllowedKey {
        src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        id: u16::from_be_bytes([bytes[4], bytes[5]]),
    };
    let offset = flags & 0x1fff;
    Some((key, offset > 0, offset == 0 && flags & 0x2000 != 0))
}

/// ns `is_local_node_packet`: an IPv4 packet addressed to `local`.
fn is_to_local(bytes: &[u8], local: Ipv4Addr) -> bool {
    bytes.len() >= 20 && bytes[0] >> 4 == 4 && bytes[16..20] == local.octets()
}

/// Whether the source address of an IPv4 or IPv6 packet, read from the raw
/// header, lies in one of `prefixes`; `false` when the buffer is too short to
/// hold it or the version is neither 4 nor 6.
fn source_in(bytes: &[u8], prefixes: &[IpNet]) -> bool {
    let source = match bytes.first().map(|b| b >> 4) {
        Some(4) => bytes
            .get(12..16)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(IpAddr::from),
        Some(6) => bytes
            .get(8..24)
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
            .map(IpAddr::from),
        _ => None,
    };
    source.is_some_and(|source| prefixes.iter().any(|net| net.contains(&source)))
}

/// ns `is_icmp_echo_reply`: an IPv4 ICMP echo reply, read from the raw
/// header whatever its fragment offset.
fn is_icmp_echo_reply(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return false;
    }
    let ihl = usize::from(bytes[0] & 0x0f) * 4;
    if ihl < 20 || bytes.len() < ihl + 8 || bytes[9] != protocol::ICMP {
        return false;
    }
    bytes[ihl] == 0
}

/// The flow table, behind one lock: for each peer, direction and tuple
/// ([`EntryKey`]) either a reply allowance or a cached verdict, plus the
/// pending dependencies and the resolved peers.
///
/// Reply allowances: inbound allowances (remote -> local, recorded by
/// outbound packets) and outbound allowances (local -> remote, recorded by
/// accepted inbound packets from outbound-restricted peers).
///
/// Cached verdicts: the decision of a flow's first packet, tagged with the
/// policy and identity generations it was computed under; a hit under other
/// generations (or whose pinhole is gone) is removed and re-evaluated. A
/// verdict and an allowance for the same key never coexist: the allowance
/// wins, as the reply check comes first.
///
/// Bounds: allowances and verdicts share `reply_capacity`. When full, cached
/// verdicts make room first (all of them are flushed, counted in
/// `verdict_evictions`), so an allowance is evicted (the least recently seen,
/// in O(1): the entries are kept in recency order) exactly when the table
/// holds allowances only, as without the cache. A new verdict is not cached when the table is
/// full and fewer than an eighth of it are verdicts.
///
/// `pending` remembers the dependency of inbound flows accepted through a
/// grant, a pinhole or a dependent allowance, keyed by the packet's tuple:
/// the inbound allowance recorded when the flow leaves again (forwarded to
/// another peer, or answered by the local node) inherits it, so it is revoked
/// with the grant or pinhole even towards an unrestricted peer. Same bounds
/// as allowances (evictions counted in `pending_evictions`); an idle entry is
/// dropped silently.
///
/// `peers` caches the resolved peers, bounded by `reply_capacity` too. A
/// peer whose labels depend on the packet's address
/// ([`PeerIdentity::by_source`]) is cached there as a marker, and resolved
/// per remote address in `sources`, bounded by `reply_capacity` as well (when
/// full, the least recently used entry is evicted in O(1); an evicted address
/// is only resolved again).
#[derive(Debug, Default)]
struct FlowTable {
    entries: LruMap<EntryKey, FlowEntry>,
    /// How many of `entries` are cached verdicts.
    verdicts: usize,
    pending: LruMap<FiveTuple, ReplyEntry>,
    peers: HashMap<PeerId, Arc<PeerInfo>, FlowHash>,
    sources: LruMap<(PeerId, IpAddr), Arc<PeerInfo>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EntryKey {
    peer: PeerId,
    outbound: bool,
    tuple: FiveTuple,
}

#[derive(Debug)]
enum FlowEntry {
    Allowance(ReplyEntry),
    Verdict(CachedVerdict),
}

#[derive(Debug, Clone)]
struct ReplyEntry {
    last_seen: Instant,
    /// Revokes the allowance when it is gone from the engine snapshot.
    dependency: Option<ReplyDependency>,
}

/// The decision about a flow and the side effects each of its packets has.
#[derive(Debug, Clone)]
struct FlowVerdict {
    outcome: Outcome,
    /// What an accepted flow depends on: its pending entry, and the outbound
    /// allowance of `restricted`, inherit it.
    dependency: Option<ReplyDependency>,
    /// An accepted inbound flow from an outbound-restricted peer records the
    /// outbound reply allowance.
    restricted: bool,
}

impl FlowVerdict {
    const fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            dependency: None,
            restricted: false,
        }
    }
}

#[derive(Debug)]
struct CachedVerdict {
    generation: u64,
    identity: u64,
    verdict: FlowVerdict,
}

/// What the flow table holds for a packet.
enum Hit {
    /// A live reply allowance (refreshed), with its dependency.
    Allowance(Option<ReplyDependency>),
    /// A verdict cached under the current generations.
    Verdict(FlowVerdict),
}

/// A peer (or a by-source peer and a remote address) resolved under one
/// policy and identity generation.
#[derive(Debug)]
struct PeerInfo {
    generation: u64,
    identity: u64,
    /// A marker: the peer's labels depend on the packet's address and are
    /// resolved per address. Its other fields are those of an unknown peer.
    by_source: bool,
    /// The peer's labels, `None` for an unknown peer.
    labels: Option<LabelSet>,
    /// The peer's namespaces (the union over its labels, computed once
    /// here), `None` when it is in no namespace.
    membership: Option<Arc<Membership>>,
    /// How the policy governs the peer.
    governed: Governed,
    /// Some pinhole belongs to the peer.
    pinholes: bool,
    /// Every new inbound TCP or UDP flow of the peer is accepted without a
    /// dependency or an outbound allowance, so its evaluation is skipped.
    bypass: bool,
}

/// How the policy governs a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Governed {
    /// In no namespace: the default policy.
    Default,
    /// A namespace member, outbound unrestricted.
    Member,
    /// A namespace member, outbound-restricted.
    Restricted,
}

impl PeerInfo {
    /// Resolve `peer` for packets whose remote address is `src`.
    fn resolve(
        identity: &dyn PeerIdentity,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
        generation: u64,
    ) -> Self {
        Self::new(identity.labels_for(peer, src), snapshot, generation, false)
    }

    fn new(
        labels: Option<LabelSet>,
        snapshot: &Snapshot,
        generation: u64,
        by_source: bool,
    ) -> Self {
        let membership = labels
            .as_ref()
            .and_then(|labels| snapshot.membership_of(labels));
        Self {
            generation: snapshot.generation(),
            identity: generation,
            by_source,
            governed: match &membership {
                None => Governed::Default,
                Some(membership) if membership.outbound_restricted() => Governed::Restricted,
                Some(_) => Governed::Member,
            },
            pinholes: labels
                .as_ref()
                .is_some_and(|labels| snapshot.has_pinholes_of(labels)),
            bypass: labels.is_some() && snapshot.bypasses(membership.as_deref()),
            labels,
            membership,
        }
    }
}

/// The flow of a TCP or UDP five-tuple.
const fn tcp_udp_flow(tuple: &FiveTuple, protocol: Protocol) -> Flow {
    let (src_port, dst_port) = (tuple.src_port, tuple.dst_port);
    Flow {
        src: tuple.src,
        dst: tuple.dst,
        transport: match protocol {
            Protocol::Tcp => Transport::Tcp { src_port, dst_port },
            Protocol::Udp => Transport::Udp { src_port, dst_port },
        },
    }
}

/// The transport of a packet that is neither TCP nor UDP: ICMP on IPv4 and
/// `ICMPv6` on IPv6 by message type, any other protocol by number.
fn other_transport(packet: &IpPacket<'_>, protocol: u8) -> Option<Transport> {
    match (packet.src(), protocol) {
        (IpAddr::V4(_), protocol::ICMP) | (IpAddr::V6(_), protocol::ICMPV6) => {
            let (icmp, _) = IcmpHeader::parse(packet.payload()).ok()?;
            Some(Transport::Icmp {
                icmp_type: icmp.icmp_type(),
            })
        }
        (_, number) => Some(Transport::Ip(number)),
    }
}

// ── AclFilter ─────────────────────────────────────────────────────────────────

/// A [`PacketFilter`] enforcing an [`AclEngine`] policy on inbound packets.
///
/// Inbound packets from a peer are evaluated as a new [`Flow`] from the
/// peer's labels (resolved by its [`PeerIdentity`]) unless a reply allowance or
/// a cached verdict holds them, exactly as
/// [`AclEngine::evaluate`] decides; anything the policy does not accept is
/// dropped with a [`reasons`] constant. With nothing loaded every inbound
/// packet is dropped (fail-closed). Outbound packets are accepted,
/// except to outbound-restricted peers (see the crate docs on namespaces) and
/// from sources outside [`AclFilterScope::outbound_sources`] when set.
///
/// **Stateful replies, not a conntrack/NAT**: with
/// [`AclFilterConfig::stateful_replies`] on, an outbound TCP or UDP packet to a
/// peer records an allowance for the reversed tuple from that same peer, so its
/// replies pass even when the policy would not accept them as new inbound
/// traffic. Allowances expire after [`AclFilterConfig::reply_idle_timeout`]
/// without traffic.
///
/// **Per-flow hook**: with a versioned identity
/// ([`PeerIdentity::generation`] non-zero, e.g. a [`PeerLabelMap`]), the
/// filter caches each peer's resolved labels and the verdict of each TCP or
/// UDP flow's first packet from a namespace member, tagged with the engine's
/// [generation](AclEngine::generation) and the identity generation; later
/// packets of the flow reuse it until either changes. Peers whose policy
/// accepts everything skip the evaluation altogether (see the crate docs on
/// the ACL hook). Verdicts and counters are the same as without the cache.
///
/// IPv4 fragments: a first fragment is evaluated and its outcome recorded;
/// later fragments of the same packet follow it, and a later fragment with no
/// recorded first fragment is dropped. [`AclFilterConfig::fragments`] selects
/// how inbound IPv4 fragments are recorded ([`FragmentMode`]).
///
/// Clones share all state, so one clone can go to the engine and another can
/// read [`stats`](Self::stats).
#[derive(Clone)]
pub struct AclFilter {
    inner: Arc<Inner>,
}

struct Inner {
    engine: Arc<AclEngine>,
    identity: Box<dyn PeerIdentity>,
    config: AclFilterConfig,
    /// [`AclFilterScope::outbound_sources`].
    outbound_sources: Option<Box<[IpNet]>>,
    /// [`AclFilterScope::other_protocols`].
    other_protocols: Box<[OtherProtocolRule]>,
    /// Cache peers and verdicts (always, except in the differential tests).
    cache: bool,
    fragments: Mutex<FragmentTable>,
    flows: Mutex<FlowTable>,
    counters: Counters,
}

impl fmt::Debug for AclFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AclFilter")
            .field("engine", &self.inner.engine)
            .field("config", &self.inner.config)
            .field("outbound_sources", &self.inner.outbound_sources)
            .field("other_protocols", &self.inner.other_protocols)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl AclFilter {
    /// A filter with the default [`AclFilterConfig`].
    pub fn new(engine: Arc<AclEngine>, identity: impl PeerIdentity) -> Self {
        Self::with_config(engine, identity, AclFilterConfig::default())
    }

    /// A filter with the given settings.
    pub fn with_config(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
    ) -> Self {
        Self::with_scope(engine, identity, config, AclFilterScope::default())
    }

    /// A filter with the given settings and address scopes.
    pub fn with_scope(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
        scope: AclFilterScope,
    ) -> Self {
        Self::build(engine, Box::new(identity), config, scope, true)
    }

    /// A filter that never caches peers or verdicts: the reference the
    /// differential tests compare the cached filter with.
    #[cfg(test)]
    pub(crate) fn uncached(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
    ) -> Self {
        Self::build(
            engine,
            Box::new(identity),
            config,
            AclFilterScope::default(),
            false,
        )
    }

    fn build(
        engine: Arc<AclEngine>,
        identity: Box<dyn PeerIdentity>,
        config: AclFilterConfig,
        scope: AclFilterScope,
        cache: bool,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                engine,
                identity,
                config,
                outbound_sources: scope.outbound_sources.map(Vec::into_boxed_slice),
                other_protocols: scope.other_protocols.into_boxed_slice(),
                cache,
                fragments: Mutex::default(),
                flows: Mutex::default(),
                counters: Counters::default(),
            }),
        }
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> AclFilterStats {
        let c = &self.inner.counters;
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        AclFilterStats {
            accepted: load(&c.accepted),
            replies: load(&c.replies),
            denied: load(&c.denied),
            no_policy: load(&c.no_policy),
            policy_failed: load(&c.policy_failed),
            unknown_peer: load(&c.unknown_peer),
            protocol: load(&c.protocol),
            fragment: load(&c.fragment),
            malformed: load(&c.malformed),
            fragment_evictions: load(&c.fragment_evictions),
            reply_evictions: load(&c.reply_evictions),
            reply_expired: load(&c.reply_expired),
            cross_namespace: load(&c.cross_namespace),
            outbound_denied: load(&c.outbound_denied),
            outbound_replies: load(&c.outbound_replies),
            reply_revoked: load(&c.reply_revoked),
            pending_evictions: load(&c.pending_evictions),
            verdict_evictions: load(&c.verdict_evictions),
            bypassed: load(&c.bypassed),
            ipv6_accepted: load(&c.ipv6_accepted),
            outbound_source: load(&c.outbound_source),
            internal: load(&c.internal),
            policy_state: self.inner.engine.policy_state(),
        }
    }
}

impl Inner {
    fn table(&self) -> MutexGuard<'_, FlowTable> {
        self.flows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The identity generation; 0 (nothing is cached) when the identity is
    /// not versioned or the cache is off.
    fn identity_generation(&self) -> u64 {
        if self.cache {
            self.identity.generation()
        } else {
            0
        }
    }

    /// Sweep the expired pinholes when a lookup saw one.
    fn sweep_if(&self, sweep: bool) {
        if sweep {
            self.engine.expire_pinholes();
        }
    }

    /// Whether [`Ipv6Mode::Accept`] passes `bytes` unevaluated.
    fn accepts_ipv6(&self, bytes: &[u8]) -> bool {
        self.config.ipv6 == Ipv6Mode::Accept && bytes.first().is_some_and(|b| b >> 4 == 6)
    }

    fn inbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
        if self.accepts_ipv6(bytes) {
            return Outcome::Ipv6Accepted;
        }
        if let Some(local) = self.config.accept_to_local
            && is_to_local(bytes, local)
        {
            return Outcome::Bypassed;
        }
        if self.config.accept_icmp_echo_reply && is_icmp_echo_reply(bytes) {
            return Outcome::Bypassed;
        }
        // `Some` for an IPv4 packet in the allow-only mode.
        let allow_only = match self.config.fragments {
            FragmentMode::AllowOnly { ttl, capacity } => {
                ipv4_fragment(bytes).map(|fragment| (fragment, ttl, capacity))
            }
            FragmentMode::Outcome => None,
        };
        if let Some(((key, true, _), ttl, _)) = allow_only {
            return self.follow_allowed(key, ttl);
        }
        let snapshot = self.engine.snapshot();
        if !snapshot.is_loaded() {
            return match snapshot.policy_state() {
                PolicyState::Failed => Outcome::PolicyFailed,
                PolicyState::NotInstalled | PolicyState::Installed { .. } => Outcome::NoPolicy,
            };
        }
        let Ok(packet) = IpPacket::parse(bytes) else {
            return Outcome::Malformed;
        };
        let Some(((key, _, first_of_many), ttl, capacity)) = allow_only else {
            return self.with_fragments(peer, false, &packet, Outcome::Fragment, |packet| {
                self.evaluate(&snapshot, peer, packet)
            });
        };
        let outcome = self.evaluate(&snapshot, peer, &packet);
        if first_of_many && matches!(outcome, Outcome::Accepted | Outcome::Reply) {
            self.remember_allowed(key, ttl, capacity);
        }
        outcome
    }

    /// [`FragmentMode::AllowOnly`]: whether the first fragment of `key` was
    /// accepted less than `ttl` ago; an expired entry is removed.
    fn follow_allowed(&self, key: AllowedKey, ttl: Duration) -> Outcome {
        let now = self.engine.now();
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match table.allowed.get(&key) {
            Some(&recorded) if now.duration_since(recorded) < ttl => Outcome::Accepted,
            Some(_) => {
                table.allowed.remove(&key);
                Outcome::Fragment
            }
            None => Outcome::Fragment,
        }
    }

    /// [`FragmentMode::AllowOnly`]: record the accepted first fragment of
    /// `key`, removing the expired entries first when the table is full and
    /// recording nothing when it is still full.
    fn remember_allowed(&self, key: AllowedKey, ttl: Duration, capacity: usize) {
        let now = self.engine.now();
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if table.allowed.len() >= capacity {
            table
                .allowed
                .retain(|_, &mut recorded| now.duration_since(recorded) < ttl);
            if table.allowed.len() >= capacity {
                return;
            }
        }
        table.allowed.insert(key, now);
    }

    /// Run `evaluate` on an unfragmented packet or a first fragment, recording
    /// a first fragment's outcome; later fragments follow it, or get `orphan`
    /// when none is recorded.
    fn with_fragments(
        &self,
        peer: PeerId,
        outbound: bool,
        packet: &IpPacket<'_>,
        orphan: Outcome,
        evaluate: impl FnOnce(&IpPacket<'_>) -> Outcome,
    ) -> Outcome {
        let fragment = packet.fragment();
        let key = fragment.map(|f| FragmentKey {
            peer,
            outbound,
            src: packet.src(),
            dst: packet.dst(),
            protocol: packet.protocol(),
            id: f.id,
        });
        match (fragment, key) {
            (Some(f), Some(key)) if !f.is_first() => {
                self.follow_fragment(key, f.is_last()).unwrap_or(orphan)
            }
            (_, key) => {
                let outcome = evaluate(packet);
                if let Some(key) = key {
                    self.record_fragment(key, outcome);
                }
                outcome
            }
        }
    }

    fn evaluate(&self, snapshot: &Snapshot, peer: PeerId, packet: &IpPacket<'_>) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::Malformed;
        };
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            return self.evaluate_other(snapshot, peer, packet, tuple);
        };
        let flow = tcp_udp_flow(&tuple, protocol);
        let identity = self.identity_generation();
        let key = EntryKey {
            peer,
            outbound: false,
            tuple,
        };
        let mut sweep = false;
        let mut table = self.table();
        let info = match self.lookup(&mut table, snapshot, key, identity, &mut sweep) {
            Some(Hit::Allowance(dependency)) => {
                if let Some(dependency) = dependency {
                    self.record_pending(&mut table, tuple, dependency);
                }
                drop(table);
                self.sweep_if(sweep);
                return Outcome::Reply;
            }
            Some(Hit::Verdict(verdict)) => {
                self.replay(&mut table, peer, tuple, &verdict);
                return verdict.outcome;
            }
            None if identity == 0 => None,
            None => {
                let Some(info) =
                    self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity)
                else {
                    drop(table);
                    self.sweep_if(sweep);
                    return Outcome::Internal;
                };
                if info.bypass {
                    drop(table);
                    self.sweep_if(sweep);
                    return Outcome::Accepted;
                }
                if info.governed == Governed::Default {
                    // The default rules: a few rules and no side effects,
                    // cheaper to evaluate under this lock than to cache.
                    let (verdict, _) = self.evaluate_new(snapshot, info, flow);
                    drop(table);
                    self.sweep_if(sweep);
                    return verdict.outcome;
                }
                Some(Arc::clone(info))
            }
        };
        drop(table);
        self.sweep_if(sweep);
        let info = info.unwrap_or_else(|| {
            Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                peer,
                tuple.src,
                0,
            ))
        });
        let (verdict, cacheable) = self.evaluate_new(snapshot, &info, flow);
        let cache = cacheable && identity != 0;
        if cache || verdict.dependency.is_some() || verdict.restricted {
            let mut table = self.table();
            self.replay(&mut table, peer, tuple, &verdict);
            if cache {
                let cached = CachedVerdict {
                    generation: snapshot.generation(),
                    identity,
                    verdict: verdict.clone(),
                };
                self.cache_verdict(&mut table, key, cached);
            }
        }
        verdict.outcome
    }

    /// Evaluate an inbound packet that is neither TCP nor UDP.
    fn evaluate_other(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        packet: &IpPacket<'_>,
        tuple: FiveTuple,
    ) -> Outcome {
        if self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Reply))
        {
            let key = EntryKey {
                peer,
                outbound: false,
                tuple,
            };
            let mut sweep = false;
            let mut table = self.table();
            let reply = match self.lookup(&mut table, snapshot, key, 0, &mut sweep) {
                Some(Hit::Allowance(dependency)) => {
                    if let Some(dependency) = dependency {
                        self.record_pending(&mut table, tuple, dependency);
                    }
                    true
                }
                Some(Hit::Verdict(_)) | None => false,
            };
            drop(table);
            self.sweep_if(sweep);
            if reply {
                return Outcome::Reply;
            }
        }
        if self.config.allow_other_protocols {
            return Outcome::Accepted;
        }
        // An ICMP message other than an echo request records no reply
        // allowance.
        let allows_reply = self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Request));
        if self.other_protocols.iter().any(|rule| rule.accepts(packet)) {
            if allows_reply {
                self.allow_restricted_reply(snapshot, peer, tuple);
            }
            return Outcome::Accepted;
        }
        self.evaluate_other_rules(snapshot, peer, packet, tuple, allows_reply)
    }

    /// The rule step of an inbound packet that is neither TCP nor UDP: the
    /// evaluation of a new flow, without a verdict cache; every denial is
    /// [`Outcome::Protocol`].
    fn evaluate_other_rules(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        packet: &IpPacket<'_>,
        tuple: FiveTuple,
        allows_reply: bool,
    ) -> Outcome {
        let Some(transport) = other_transport(packet, tuple.protocol) else {
            return Outcome::Protocol;
        };
        let flow = Flow {
            src: tuple.src,
            dst: tuple.dst,
            transport,
        };
        let identity = self.identity_generation();
        let mut table = self.table();
        let info = if identity == 0 {
            Arc::new(PeerInfo::resolve(
                &*self.identity,
                snapshot,
                peer,
                tuple.src,
                0,
            ))
        } else {
            let Some(info) =
                self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity)
            else {
                return Outcome::Internal;
            };
            Arc::clone(info)
        };
        drop(table);
        let (verdict, _) = self.evaluate_new(snapshot, &info, flow);
        if verdict.outcome != Outcome::Accepted {
            return Outcome::Protocol;
        }
        if verdict.dependency.is_some() || (verdict.restricted && allows_reply) {
            let mut table = self.table();
            if let Some(dependency) = &verdict.dependency {
                self.record_pending(&mut table, tuple, dependency.clone());
            }
            if verdict.restricted && allows_reply {
                self.record_reply(&mut table, peer, true, reversed(tuple), verdict.dependency);
            }
        }
        Outcome::Accepted
    }

    /// Record the outbound reply allowance of an inbound packet accepted by a
    /// scope rule when `peer` is outbound-restricted.
    fn allow_restricted_reply(&self, snapshot: &Snapshot, peer: PeerId, tuple: FiveTuple) {
        let identity = self.identity_generation();
        if identity == 0 {
            let info = PeerInfo::resolve(&*self.identity, snapshot, peer, tuple.src, 0);
            if info.governed == Governed::Restricted {
                self.record_reply(&mut self.table(), peer, true, reversed(tuple), None);
            }
            return;
        }
        let mut table = self.table();
        let info = self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity);
        // Without the peer no allowance is recorded: its replies stay denied.
        if info.is_some_and(|info| info.governed == Governed::Restricted) {
            self.record_reply(&mut table, peer, true, reversed(tuple), None);
        }
    }

    /// Evaluate a new inbound `flow` from the resolved peer `info`, as
    /// [`AclEngine::evaluate`] does. Returns the verdict and whether it may
    /// be cached.
    fn evaluate_new(
        &self,
        snapshot: &Snapshot,
        info: &PeerInfo,
        flow: Flow,
    ) -> (FlowVerdict, bool) {
        let Some(labels) = &info.labels else {
            return (FlowVerdict::new(Outcome::UnknownPeer), true);
        };
        let membership = info.membership.as_deref();
        let evaluation = snapshot.evaluate(labels, membership, &flow, || self.engine.now());
        let outcome = match evaluation {
            Evaluation::Rule { .. }
            | Evaluation::Grant(_)
            | Evaluation::Pinhole(_)
            | Evaluation::NotInstalled => Outcome::Accepted,
            Evaluation::PinholeExpired => {
                self.engine.expire_pinholes();
                return (FlowVerdict::new(Outcome::Denied), false);
            }
            Evaluation::Deny(reason) => {
                let outcome = match reason {
                    reasons::CROSS_NAMESPACE => Outcome::CrossNamespace,
                    reasons::NO_POLICY => Outcome::NoPolicy,
                    reasons::POLICY_FAILED => Outcome::PolicyFailed,
                    _ => Outcome::Denied,
                };
                return (FlowVerdict::new(outcome), true);
            }
        };
        let verdict = FlowVerdict {
            outcome,
            dependency: evaluation.dependency(),
            restricted: membership.is_some_and(Membership::outbound_restricted),
        };
        (verdict, true)
    }

    /// The side effects of an inbound packet of a flow with `verdict`.
    fn replay(&self, table: &mut FlowTable, peer: PeerId, tuple: FiveTuple, verdict: &FlowVerdict) {
        if let Some(dependency) = &verdict.dependency {
            self.record_pending(table, tuple, dependency.clone());
        }
        if verdict.restricted && self.config.stateful_replies {
            self.record_reply(
                table,
                peer,
                true,
                reversed(tuple),
                verdict.dependency.clone(),
            );
        }
    }

    /// The resolved `peer` for packets whose remote address is `src` under
    /// the snapshot's generation and `identity`, resolving it again when
    /// missing or stale. A by-source peer is resolved per address; with no
    /// address it is unknown. `None` if the cache lost the entry it just
    /// stored (an invariant failure the caller drops the packet on).
    fn cached_peer<'t>(
        &self,
        table: &'t mut FlowTable,
        snapshot: &Snapshot,
        peer: PeerId,
        src: Option<IpAddr>,
        identity: u64,
    ) -> Option<&'t Arc<PeerInfo>> {
        let generation = snapshot.generation();
        let capacity = self.config.reply_capacity.max(1);
        if table.peers.len() >= capacity && !table.peers.contains_key(&peer) {
            table
                .peers
                .retain(|_, info| info.generation == generation && info.identity == identity);
            if table.peers.len() >= capacity {
                table.peers.clear();
            }
        }
        let resolve = || {
            let info = match src {
                _ if self.identity.by_source(peer) => PeerInfo::new(None, snapshot, identity, true),
                Some(src) => PeerInfo::resolve(&*self.identity, snapshot, peer, src, identity),
                None => PeerInfo::new(self.identity.labels(peer), snapshot, identity, false),
            };
            Arc::new(info)
        };
        let info = table.peers.entry(peer).or_insert_with(resolve);
        if info.generation != generation || info.identity != identity {
            *info = resolve();
        }
        match src {
            Some(src) if info.by_source => {
                self.cached_source(&mut table.sources, snapshot, peer, src, identity)
            }
            _ => Some(info),
        }
    }

    /// The resolved by-source `peer` for the remote address `src`, as
    /// [`cached_peer`](Self::cached_peer).
    fn cached_source<'t>(
        &self,
        sources: &'t mut LruMap<(PeerId, IpAddr), Arc<PeerInfo>>,
        snapshot: &Snapshot,
        peer: PeerId,
        src: IpAddr,
        identity: u64,
    ) -> Option<&'t Arc<PeerInfo>> {
        let key = (peer, src);
        let fresh = sources.get(&key).is_some_and(|info| {
            info.generation == snapshot.generation() && info.identity == identity
        });
        if fresh {
            sources.touch(&key);
        } else {
            if !sources.contains_key(&key) && sources.len() >= self.config.reply_capacity.max(1) {
                sources.pop_oldest();
            }
            let info = PeerInfo::resolve(&*self.identity, snapshot, peer, src, identity);
            sources.insert(key, Arc::new(info));
        }
        sources.get(&key)
    }

    /// The live reply allowance (refreshed) or the valid cached verdict for
    /// `key`. Expired and revoked allowances are removed and counted (`sweep`
    /// is set when a pinhole may have expired); stale verdicts are removed.
    fn lookup(
        &self,
        table: &mut FlowTable,
        snapshot: &Snapshot,
        key: EntryKey,
        identity: u64,
        sweep: &mut bool,
    ) -> Option<Hit> {
        match table.entries.get_mut(&key)? {
            FlowEntry::Allowance(allowance) => {
                let now = Instant::now();
                if now.duration_since(allowance.last_seen) > self.config.reply_idle_timeout {
                    table.entries.remove(&key);
                    bump(&self.counters.reply_expired);
                    return None;
                }
                let revoked = allowance
                    .dependency
                    .as_ref()
                    .filter(|dependency| !snapshot.is_live(dependency, || self.engine.now()));
                if let Some(revoked) = revoked {
                    // The pinhole may only have expired: sweep it.
                    *sweep = matches!(revoked, ReplyDependency::Pinhole(_));
                    table.entries.remove(&key);
                    bump(&self.counters.reply_revoked);
                    return None;
                }
                allowance.last_seen = now;
                let dependency = allowance.dependency.clone();
                table.entries.touch(&key);
                Some(Hit::Allowance(dependency))
            }
            FlowEntry::Verdict(cached) => {
                // Only a pinhole can close without a generation change: it
                // expires.
                let valid = identity != 0
                    && cached.generation == snapshot.generation()
                    && cached.identity == identity
                    && cached.verdict.dependency.as_ref().is_none_or(|dependency| {
                        matches!(dependency, ReplyDependency::Grant(_))
                            || snapshot.is_live(dependency, || self.engine.now())
                    });
                if valid {
                    return Some(Hit::Verdict(cached.verdict.clone()));
                }
                table.entries.remove(&key);
                table.verdicts -= 1;
                None
            }
        }
    }

    /// Cache `cached` under `key`, unless an allowance holds it or the table
    /// is full of allowances.
    fn cache_verdict(&self, table: &mut FlowTable, key: EntryKey, cached: CachedVerdict) {
        match table.entries.get_mut(&key) {
            Some(FlowEntry::Allowance(_)) => return,
            Some(FlowEntry::Verdict(old)) => {
                *old = cached;
                return;
            }
            None => {}
        }
        let capacity = self.config.reply_capacity.max(1);
        if table.entries.len() >= capacity {
            if table.verdicts < (capacity / 8).max(1) {
                return;
            }
            self.flush_verdicts(table);
        }
        table.entries.insert(key, FlowEntry::Verdict(cached));
        table.verdicts += 1;
    }

    /// Remove every cached verdict, counting them as evictions.
    fn flush_verdicts(&self, table: &mut FlowTable) {
        table
            .entries
            .retain(|_, entry| matches!(entry, FlowEntry::Allowance(_)));
        self.counters
            .verdict_evictions
            .fetch_add(table.verdicts as u64, Ordering::Relaxed);
        table.verdicts = 0;
    }

    fn follow_fragment(&self, key: FragmentKey, last: bool) -> Option<Outcome> {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last {
            table.entries.remove(&key)
        } else {
            table.entries.get(&key).copied()
        }
    }

    fn record_fragment(&self, key: FragmentKey, outcome: Outcome) {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let capacity = self.config.fragment_capacity.max(1);
        if !table.entries.contains_key(&key)
            && table.entries.len() >= capacity
            && table.entries.pop_oldest().is_some()
        {
            bump(&self.counters.fragment_evictions);
        }
        table.entries.insert(key, outcome);
    }

    fn outbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
        if self.accepts_ipv6(bytes) {
            return Outcome::Ipv6Accepted;
        }
        if let Some(prefixes) = &self.outbound_sources
            && !source_in(bytes, prefixes)
        {
            return Outcome::OutboundSource;
        }
        let snapshot = self.engine.snapshot();
        let identity = self.identity_generation();
        let parsed = IpPacket::parse(bytes);
        // The remote address; a by-source peer is unknown without it.
        let dst = parsed.as_ref().ok().map(IpPacket::dst);
        let mut table = self.table();
        // `None`: an unrestricted peer without pinholes.
        let info = if identity != 0 {
            let Some(info) = self.cached_peer(&mut table, &snapshot, peer, dst, identity) else {
                return Outcome::Internal;
            };
            (info.governed == Governed::Restricted || info.pinholes).then(|| Arc::clone(info))
        } else if snapshot.has_outbound_restrictions() || snapshot.has_pinholes() {
            let labels = dst.map_or_else(
                || self.identity.labels(peer),
                |dst| self.identity.labels_for(peer, dst),
            );
            Some(Arc::new(PeerInfo::new(labels, &snapshot, 0, false)))
        } else {
            None
        };
        let restricted = info
            .as_ref()
            .is_some_and(|info| info.governed == Governed::Restricted);
        let Ok(packet) = parsed else {
            return if restricted {
                Outcome::OutboundDenied
            } else {
                Outcome::OutboundAccepted
            };
        };
        let info = match info {
            Some(info) if restricted => info,
            info => {
                self.outbound_unrestricted(&snapshot, peer, info.as_deref(), &packet, table);
                return Outcome::OutboundAccepted;
            }
        };
        if packet.fragment().is_none() {
            return self.evaluate_outbound(&snapshot, peer, &info, identity, &packet, table);
        }
        drop(table);
        self.with_fragments(peer, true, &packet, Outcome::OutboundDenied, |packet| {
            self.evaluate_outbound(&snapshot, peer, &info, identity, packet, self.table())
        })
    }

    /// An outbound packet to an unrestricted peer (`info`: with pinholes):
    /// accepted anyway; an outbound pinhole still owns the replies.
    fn outbound_unrestricted(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: Option<&PeerInfo>,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) {
        let Some(tuple) = packet.five_tuple() else {
            return;
        };
        let mut sweep = false;
        let dependency = info
            .and_then(|info| info.labels.as_ref())
            .and_then(|labels| self.outbound_pinhole(snapshot, labels, &tuple, &mut sweep));
        self.track_outbound(&mut table, peer, tuple, packet, dependency);
        drop(table);
        self.sweep_if(sweep);
    }

    /// The open outbound pinhole of `labels` for `tuple`, as a reply
    /// dependency. Sets `sweep` when only expired pinholes match.
    fn outbound_pinhole(
        &self,
        snapshot: &Snapshot,
        labels: &LabelSet,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> Option<ReplyDependency> {
        let protocol = Protocol::from_ip_number(tuple.protocol)?;
        match snapshot.match_pinhole(
            labels,
            Direction::Outbound,
            protocol,
            tuple.dst_port,
            || self.engine.now(),
        ) {
            PinholeMatch::Open(id) => Some(ReplyDependency::Pinhole(id)),
            PinholeMatch::Expired => {
                *sweep = true;
                None
            }
            PinholeMatch::Absent => None,
        }
    }

    /// Evaluate an outbound packet to the outbound-restricted peer `info`,
    /// holding the flow table.
    fn evaluate_outbound(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        identity: u64,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::OutboundDenied;
        };
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            if self.config.allow_other_protocols {
                self.track_outbound(&mut table, peer, tuple, packet, None);
                return Outcome::OutboundAccepted;
            }
            return self.outbound_other(snapshot, peer, info, tuple, packet, table);
        };
        let key = EntryKey {
            peer,
            outbound: true,
            tuple,
        };
        let mut sweep = false;
        let verdict = match self.lookup(&mut table, snapshot, key, identity, &mut sweep) {
            Some(Hit::Allowance(dependency)) => FlowVerdict {
                outcome: Outcome::OutboundReply,
                dependency,
                restricted: false,
            },
            Some(Hit::Verdict(verdict)) => verdict,
            None => {
                let (verdict, cacheable) =
                    self.evaluate_new_outbound(snapshot, info, protocol, &tuple, &mut sweep);
                if cacheable && identity != 0 {
                    let cached = CachedVerdict {
                        generation: snapshot.generation(),
                        identity,
                        verdict: verdict.clone(),
                    };
                    self.cache_verdict(&mut table, key, cached);
                }
                verdict
            }
        };
        if verdict.outcome != Outcome::OutboundDenied {
            self.track_outbound(&mut table, peer, tuple, packet, verdict.dependency);
        }
        drop(table);
        self.sweep_if(sweep);
        verdict.outcome
    }

    /// An outbound packet to the outbound-restricted peer `info` that is
    /// neither TCP nor UDP, without `allow_other_protocols`: accepted as the
    /// reply allowed by an accepted inbound packet, or by an outbound rule.
    fn outbound_other(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        info: &PeerInfo,
        tuple: FiveTuple,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) -> Outcome {
        if self.config.stateful_replies
            && (!is_icmp(tuple.protocol) || echo_type(packet) == Some(EchoType::Reply))
        {
            let key = EntryKey {
                peer,
                outbound: true,
                tuple,
            };
            let mut sweep = false;
            let reply = matches!(
                self.lookup(&mut table, snapshot, key, 0, &mut sweep),
                Some(Hit::Allowance(_))
            );
            if reply {
                drop(table);
                self.sweep_if(sweep);
                return Outcome::OutboundReply;
            }
            self.sweep_if(sweep);
        }
        let rule = other_transport(packet, tuple.protocol).is_some_and(|transport| {
            info.membership
                .as_deref()
                .is_some_and(|membership| snapshot.outbound_rule_accepts(membership, transport))
        });
        if !rule {
            return Outcome::OutboundDenied;
        }
        self.track_outbound(&mut table, peer, tuple, packet, None);
        Outcome::OutboundAccepted
    }

    /// Evaluate a new outbound TCP or UDP flow to the outbound-restricted
    /// peer `info`. Returns the verdict and whether it may be cached.
    fn evaluate_new_outbound(
        &self,
        snapshot: &Snapshot,
        info: &PeerInfo,
        protocol: Protocol,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> (FlowVerdict, bool) {
        let transport = tcp_udp_flow(tuple, protocol).transport;
        let rule = info
            .membership
            .as_deref()
            .is_some_and(|membership| snapshot.outbound_rule_accepts(membership, transport));
        if rule {
            return (FlowVerdict::new(Outcome::OutboundAccepted), true);
        }
        let mut expired = false;
        let dependency = info
            .labels
            .as_ref()
            .and_then(|labels| self.outbound_pinhole(snapshot, labels, tuple, &mut expired));
        let outcome = if dependency.is_some() {
            Outcome::OutboundAccepted
        } else {
            Outcome::OutboundDenied
        };
        // Only expired pinholes matched: not cached, the sweep publishes a
        // new generation anyway.
        *sweep |= expired;
        let verdict = FlowVerdict {
            outcome,
            dependency,
            restricted: false,
        };
        (verdict, !expired)
    }

    /// Record the inbound reply allowance of an accepted outbound packet.
    fn track_outbound(
        &self,
        table: &mut FlowTable,
        peer: PeerId,
        tuple: FiveTuple,
        packet: &IpPacket<'_>,
        dependency: Option<ReplyDependency>,
    ) {
        if !self.config.stateful_replies {
            return;
        }
        let tracked = match tuple.protocol {
            protocol::TCP | protocol::UDP => true,
            p if is_icmp(p) => {
                (self.config.allow_other_protocols || !self.other_protocols.is_empty())
                    && echo_type(packet) == Some(EchoType::Request)
            }
            _ => false,
        };
        if tracked {
            self.record_reply(table, peer, false, reversed(tuple), dependency);
        }
    }

    fn record_reply(
        &self,
        table: &mut FlowTable,
        peer: PeerId,
        outbound: bool,
        tuple: FiveTuple,
        dependency: Option<ReplyDependency>,
    ) {
        let now = Instant::now();
        // An inbound allowance inherits the dependency of the inbound flow it
        // continues: the same tuple forwarded to another peer, or the reply of
        // the local node.
        let dependency = match dependency {
            None if !outbound && !table.pending.is_empty() => [tuple, reversed(tuple)]
                .iter()
                .find_map(|tuple| {
                    table.pending.get(tuple).filter(|pending| {
                        now.duration_since(pending.last_seen) <= self.config.reply_idle_timeout
                    })
                })
                .and_then(|pending| pending.dependency.clone()),
            dependency => dependency,
        };
        let key = EntryKey {
            peer,
            outbound,
            tuple,
        };
        let allowance = ReplyEntry {
            last_seen: now,
            dependency,
        };
        let capacity = self.config.reply_capacity.max(1);
        if !table.entries.contains_key(&key) && table.entries.len() >= capacity {
            if table.verdicts > 0 {
                self.flush_verdicts(table);
            }
            // Only allowances are left: the oldest is the least recently seen.
            if table.entries.len() >= capacity && table.entries.pop_oldest().is_some() {
                bump(&self.counters.reply_evictions);
            }
        }
        let old = table.entries.insert(key, FlowEntry::Allowance(allowance));
        if matches!(old, Some(FlowEntry::Verdict(_))) {
            table.verdicts -= 1;
        }
    }

    /// Remember that the inbound flow `tuple` depends on `dependency`.
    fn record_pending(&self, table: &mut FlowTable, tuple: FiveTuple, dependency: ReplyDependency) {
        if !self.config.stateful_replies {
            return;
        }
        let capacity = self.config.reply_capacity.max(1);
        if !table.pending.contains_key(&tuple)
            && table.pending.len() >= capacity
            && table.pending.pop_oldest().is_some()
        {
            bump(&self.counters.pending_evictions);
        }
        table.pending.insert(
            tuple,
            ReplyEntry {
                last_seen: Instant::now(),
                dependency: Some(dependency),
            },
        );
    }
}

const fn is_icmp(protocol: u8) -> bool {
    matches!(protocol, protocol::ICMP | protocol::ICMPV6)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EchoType {
    Request,
    Reply,
}

/// The echo type of an ICMP or `ICMPv6` packet, `None` for other messages.
fn echo_type(packet: &IpPacket<'_>) -> Option<EchoType> {
    let (icmp, _) = IcmpHeader::parse(packet.payload()).ok()?;
    match (packet.protocol(), icmp.icmp_type()) {
        (protocol::ICMP, 8) | (protocol::ICMPV6, 128) => Some(EchoType::Request),
        (protocol::ICMP, 0) | (protocol::ICMPV6, 129) => Some(EchoType::Reply),
        _ => None,
    }
}

/// `tuple` seen from the other end: addresses and ports swapped.
pub(crate) const fn reversed(tuple: FiveTuple) -> FiveTuple {
    FiveTuple {
        src: tuple.dst,
        dst: tuple.src,
        protocol: tuple.protocol,
        src_port: tuple.dst_port,
        dst_port: tuple.src_port,
    }
}

impl PacketFilter for AclFilter {
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let outcome = self.inner.inbound(peer, packet.as_packet());
        outcome.count(&self.inner.counters);
        outcome.verdict()
    }

    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict {
        let outcome = self.inner.outbound(peer, packet.as_packet());
        outcome.count(&self.inner.counters);
        outcome.verdict()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use super::*;
    use crate::namespace::{
        Grant, GrantEnd, NamespaceKind, NamespaceMember, NamespacePolicy, OutboundRule,
    };
    use crate::policy::{AclAction, AclPolicy, AclRule};
    use crate::rules::{Label, NotInstalled, PortSet, ProtocolMatch, Rule, RuleSet};
    use crate::test_packets::{Frag, icmp_echo, ip, ip_frag, tcp, tcp_packet, udp_packet};

    const PEER: PeerId = PeerId::new(1);
    const OTHER_PEER: PeerId = PeerId::new(2);
    const KEY_PEER: PeerId = PeerId::new(3);
    /// The label of the peers judged by their source address.
    const ADDR: &str = "addr";

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    /// The label of `KEY_PEER`.
    fn key_label() -> Label {
        Label::from("key:07")
    }

    fn label_set(labels: &[&str]) -> LabelSet {
        labels.iter().map(|&label| Label::from(label)).collect()
    }

    fn rule(src: &str, dst: &str, proto: &str) -> AclRule {
        AclRule {
            action: AclAction::Accept,
            src: vec![src.to_owned()],
            dst: vec![dst.to_owned()],
            proto: Some(proto.to_owned()),
        }
    }

    fn policy(acls: Vec<AclRule>) -> AclPolicy {
        AclPolicy {
            hosts: HashMap::new(),
            acls,
            tests: Vec::new(),
        }
    }

    /// An `ADDR`-labelled source at `10.0.0.1` (or `fd00::1`) may reach
    /// `10.0.0.2` TCP 80 (or `fd00::2` TCP 443); a `key_label()` source may
    /// reach UDP 53.
    fn test_policy() -> RuleSet {
        RuleSet::new([
            Rule::new("0", vec![ProtocolMatch::Tcp(PortSet::single(80))])
                .with_labels([ADDR.into()])
                .with_sources([net("10.0.0.1/32")])
                .with_destinations([net("10.0.0.2/32")]),
            Rule::new("1", vec![ProtocolMatch::Tcp(PortSet::single(443))])
                .with_labels([ADDR.into()])
                .with_sources([net("fd00::1/128")])
                .with_destinations([net("fd00::2/128")]),
            Rule::new("2", vec![ProtocolMatch::Udp(PortSet::single(53))])
                .with_labels([key_label()]),
        ])
        .unwrap()
    }

    /// `PEER` and `OTHER_PEER` carry `ADDR` and a label of their own,
    /// `KEY_PEER` the key label.
    fn identity() -> Arc<PeerLabelMap> {
        let map = Arc::new(PeerLabelMap::new());
        map.insert(PEER, label_set(&[ADDR, "peer-1"]));
        map.insert(OTHER_PEER, label_set(&[ADDR, "peer-2"]));
        map.insert(KEY_PEER, LabelSet::new([key_label()]));
        map
    }

    fn loaded_engine(policy: AclPolicy) -> Arc<AclEngine> {
        let engine = Arc::new(AclEngine::new());
        engine.load(policy).unwrap();
        engine
    }

    fn rules_engine(rules: RuleSet) -> Arc<AclEngine> {
        let engine = Arc::new(AclEngine::new());
        engine.install(rules);
        engine
    }

    fn filter_with(config: AclFilterConfig) -> AclFilter {
        AclFilter::with_config(rules_engine(test_policy()), identity(), config)
    }

    fn filter() -> AclFilter {
        filter_with(AclFilterConfig::default())
    }

    fn inbound(filter: &AclFilter, peer: PeerId, mut packet: PacketBuf) -> Verdict {
        filter.inbound(peer, &mut packet)
    }

    fn outbound(filter: &AclFilter, peer: PeerId, mut packet: PacketBuf) -> Verdict {
        filter.outbound(peer, &mut packet)
    }

    fn drop(reason: &'static str) -> Verdict {
        Verdict::Drop { reason }
    }

    #[test]
    fn allowed_and_denied_v4() {
        let f = filter();
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 81)),
            drop(reasons::DENIED)
        );
        // The rule is TCP only.
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.denied), (1, 2));
    }

    #[test]
    fn allowed_and_denied_v6() {
        let f = filter();
        let (r, l) = (addr("fd00::1"), addr("fd00::2"));
        let peer6 = PeerId::new(6);
        let map = identity();
        map.insert(peer6, label_set(&[ADDR, "v6"]));
        let f6 = AclFilter::new(rules_engine(test_policy()), map);
        assert_eq!(
            inbound(&f6, peer6, tcp_packet(r, 4000, l, 443)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f6, peer6, tcp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f6, peer6, udp_packet(r, 4000, l, 443)),
            drop(reasons::DENIED)
        );
        // The prefixes read the flow's source address: PEER sending from
        // fd00::1 matches the IPv6 rule too.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 443)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(addr("fd00::9"), 4000, l, 443)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn key_label_and_address_label() {
        let f = filter();
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        // The key label matches regardless of the packet's source address.
        assert_eq!(
            inbound(&f, KEY_PEER, udp_packet(r, 5000, l, 53)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(
                &f,
                KEY_PEER,
                udp_packet(addr("fd00::7"), 5000, addr("fd00::2"), 53)
            ),
            Verdict::Accept
        );
        // Without the address label the prefix rule never matches, even from
        // an allowed address.
        assert_eq!(
            inbound(&f, KEY_PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        // The address label does not match the key rule.
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 5000, l, 53)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn unknown_peer_is_dropped() {
        let f = filter();
        let packet = tcp_packet(addr("10.0.0.1"), 4000, addr("10.0.0.2"), 80);
        assert_eq!(
            inbound(&f, PeerId::new(99), packet),
            drop(reasons::UNKNOWN_PEER)
        );
        assert_eq!(f.stats().unknown_peer, 1);
    }

    #[test]
    fn internal_error_is_a_counted_drop() {
        let f = filter();
        let outcome = Outcome::Internal;
        outcome.count(&f.inner.counters);
        assert_eq!(outcome.verdict(), drop(reasons::INTERNAL));
        assert_eq!(f.stats().internal, 1);
        assert_eq!(f.stats().denied, 0);
    }

    #[test]
    fn closure_identity() {
        let identity = |peer: PeerId| (peer == PEER).then(|| LabelSet::new([key_label()]));
        let f = AclFilter::new(rules_engine(test_policy()), identity);
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 5000, l, 53)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, OTHER_PEER, udp_packet(r, 5000, l, 53)),
            drop(reasons::UNKNOWN_PEER)
        );
    }

    #[test]
    fn identity_map_updates_through_shared_handle() {
        let map = identity();
        let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        map.remove(PEER);
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::UNKNOWN_PEER)
        );
    }

    #[test]
    fn no_policy_is_fail_closed_until_loaded() {
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::new(Arc::clone(&engine), identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::NO_POLICY)
        );
        engine.install(test_policy());
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        engine.uninstall();
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::NO_POLICY)
        );
        let stats = f.stats();
        assert_eq!((stats.no_policy, stats.accepted), (2, 1));
    }

    #[test]
    fn malformed_is_dropped() {
        let f = filter();
        assert_eq!(
            inbound(&f, PEER, PacketBuf::from_packet(&[0x45, 0, 0])),
            drop(reasons::MALFORMED)
        );
        // Truncated TCP header.
        let packet = ip(addr("10.0.0.1"), addr("10.0.0.2"), protocol::TCP, &[0; 4]);
        assert_eq!(inbound(&f, PEER, packet), drop(reasons::MALFORMED));
        assert_eq!(f.stats().malformed, 2);
    }

    #[test]
    fn icmp_needs_allow_other_protocols() {
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let ping = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
        let f = filter();
        assert_eq!(inbound(&f, PEER, ping()), drop(reasons::PROTOCOL));
        assert_eq!(f.stats().protocol, 1);

        let f = filter_with(AclFilterConfig {
            allow_other_protocols: true,
            ..AclFilterConfig::default()
        });
        assert_eq!(inbound(&f, PEER, ping()), Verdict::Accept);
    }

    fn fragment(id: u16, offset_units: u16, more: bool, transport: &[u8]) -> PacketBuf {
        ip_frag(
            addr("10.0.0.1"),
            addr("10.0.0.2"),
            protocol::TCP,
            transport,
            Some(Frag {
                id,
                offset_units,
                more,
            }),
        )
    }

    fn first_fragment(id: u16, dport: u16) -> PacketBuf {
        fragment(id, 0, true, &tcp(4000, dport, &[0; 8]))
    }

    #[test]
    fn fragments_follow_an_allowed_first_fragment() {
        let f = filter();
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        assert_eq!(
            inbound(&f, PEER, fragment(7, 4, true, &[0; 16])),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, fragment(7, 6, false, &[0; 8])),
            Verdict::Accept
        );
        // The entry was freed by the last fragment.
        assert_eq!(
            inbound(&f, PEER, fragment(7, 6, false, &[0; 8])),
            drop(reasons::FRAGMENT)
        );
        // The entry is per peer.
        assert_eq!(inbound(&f, PEER, first_fragment(8, 80)), Verdict::Accept);
        assert_eq!(
            inbound(&f, OTHER_PEER, fragment(8, 4, false, &[0; 8])),
            drop(reasons::FRAGMENT)
        );
        assert_eq!(f.stats().accepted, 4);
    }

    #[test]
    fn fragments_follow_a_denied_first_fragment() {
        let f = filter();
        assert_eq!(
            inbound(&f, PEER, first_fragment(9, 81)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, PEER, fragment(9, 4, true, &[0; 8])),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, PEER, fragment(9, 5, false, &[0; 8])),
            drop(reasons::DENIED)
        );
        assert_eq!(f.stats().denied, 3);
    }

    #[test]
    fn orphan_fragment_is_dropped() {
        let f = filter();
        assert_eq!(
            inbound(&f, PEER, fragment(3, 4, true, &[0; 8])),
            drop(reasons::FRAGMENT)
        );
        assert_eq!(f.stats().fragment, 1);
    }

    #[test]
    fn fragment_table_evicts_oldest() {
        let f = filter_with(AclFilterConfig {
            fragment_capacity: 2,
            ..AclFilterConfig::default()
        });
        for id in 1..=3 {
            assert_eq!(inbound(&f, PEER, first_fragment(id, 80)), Verdict::Accept);
        }
        assert_eq!(f.stats().fragment_evictions, 1);
        assert_eq!(
            inbound(&f, PEER, fragment(1, 4, false, &[0; 8])),
            drop(reasons::FRAGMENT)
        );
        assert_eq!(
            inbound(&f, PEER, fragment(2, 4, false, &[0; 8])),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, fragment(3, 4, false, &[0; 8])),
            Verdict::Accept
        );
    }

    #[test]
    fn outbound_always_accepts() {
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::new(engine, identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, PeerId::new(99), PacketBuf::from_packet(&[1, 2])),
            Verdict::Accept
        );
        assert_eq!(f.stats(), AclFilterStats::default());
    }

    fn deny_all() -> AclPolicy {
        policy(Vec::new())
    }

    #[test]
    fn replies_to_outbound_flows_are_accepted() {
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::new(Arc::clone(&engine), identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, PEER, udp_packet(l, 40001, r, 53)),
            Verdict::Accept
        );

        // Fail-closed wins while no policy is loaded.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
            drop(reasons::NO_POLICY)
        );

        engine.load(deny_all()).unwrap();
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 53, l, 40001)),
            Verdict::Accept
        );
        // Same local port, different remote port.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 23, l, 40000)),
            drop(reasons::DENIED)
        );
        // Same tuple, different peer.
        assert_eq!(
            inbound(&f, OTHER_PEER, tcp_packet(r, 22, l, 40000)),
            drop(reasons::DENIED)
        );
        // The protocol is part of the key.
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 22, l, 40000)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.replies, stats.denied, stats.no_policy), (2, 3, 1));
    }

    #[test]
    fn reply_fragments_follow_the_first_fragment() {
        let f = AclFilter::new(loaded_engine(deny_all()), identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
            Verdict::Accept
        );
        assert_eq!(inbound(&f, PEER, first_fragment(5, 80)), Verdict::Accept);
        assert_eq!(
            inbound(&f, PEER, fragment(5, 4, false, &[0; 8])),
            Verdict::Accept
        );
        assert_eq!(f.stats().replies, 2);
    }

    #[test]
    fn icmp_echo_replies_need_allow_other_protocols() {
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let request = || ip(l, r, protocol::ICMP, &icmp_echo(8, 77));
        let reply = || ip(r, l, protocol::ICMP, &icmp_echo(0, 77));

        let f = AclFilter::new(loaded_engine(deny_all()), identity());
        outbound(&f, PEER, request());
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));

        let f = AclFilter::with_config(
            loaded_engine(deny_all()),
            identity(),
            AclFilterConfig {
                allow_other_protocols: true,
                ..AclFilterConfig::default()
            },
        );
        outbound(&f, PEER, request());
        assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
        assert_eq!(f.stats().replies, 1);
        // An inbound echo request with the same id is not a reply.
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(8, 77))),
            Verdict::Accept
        );
        assert_eq!(f.stats().replies, 1);

        // ICMPv6.
        let (r6, l6) = (addr("fd00::1"), addr("fd00::2"));
        outbound(&f, PEER, ip(l6, r6, protocol::ICMPV6, &icmp_echo(128, 5)));
        assert_eq!(
            inbound(&f, PEER, ip(r6, l6, protocol::ICMPV6, &icmp_echo(129, 5))),
            Verdict::Accept
        );
        assert_eq!(f.stats().replies, 2);
    }

    #[test]
    fn reply_allowances_expire() {
        let f = AclFilter::with_config(
            loaded_engine(deny_all()),
            identity(),
            AclFilterConfig {
                reply_idle_timeout: Duration::from_millis(50),
                ..AclFilterConfig::default()
            },
        );
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        outbound(&f, PEER, udp_packet(l, 40000, r, 53));
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
            Verdict::Accept
        );
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.replies, stats.reply_expired), (1, 1));

        // Outbound traffic refreshes an allowance.
        outbound(&f, PEER, udp_packet(l, 40000, r, 53));
        std::thread::sleep(Duration::from_millis(30));
        outbound(&f, PEER, udp_packet(l, 40000, r, 53));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 53, l, 40000)),
            Verdict::Accept
        );
    }

    #[test]
    fn reply_table_evicts_oldest() {
        let f = AclFilter::with_config(
            loaded_engine(deny_all()),
            identity(),
            AclFilterConfig {
                reply_capacity: 2,
                ..AclFilterConfig::default()
            },
        );
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        for port in [1000, 1001, 1002] {
            outbound(&f, PEER, tcp_packet(l, port, r, 22));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(f.stats().reply_evictions, 1);
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 1000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 1001)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 1002)),
            Verdict::Accept
        );
    }

    #[test]
    fn stateful_replies_can_be_disabled() {
        let f = AclFilter::with_config(
            loaded_engine(deny_all()),
            identity(),
            AclFilterConfig {
                stateful_replies: false,
                ..AclFilterConfig::default()
            },
        );
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        outbound(&f, PEER, tcp_packet(l, 40000, r, 22));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
            drop(reasons::DENIED)
        );
        assert_eq!(f.stats().replies, 0);
    }

    #[test]
    fn clones_share_state() {
        let f = filter();
        let handle = f.clone();
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(handle.stats().accepted, 1);
        outbound(&handle, PEER, tcp_packet(l, 5000, r, 9));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 9, l, 5000)),
            Verdict::Accept
        );
        assert_eq!(handle.stats().replies, 1);
    }

    #[test]
    fn default_config() {
        let config = AclFilterConfig::default();
        assert_eq!(config.fragment_capacity, 1024);
        assert!(!config.allow_other_protocols);
        assert!(config.stateful_replies);
        assert_eq!(config.reply_capacity, 4096);
        assert_eq!(config.reply_idle_timeout, Duration::from_secs(120));
    }

    // ── namespaces ────────────────────────────────────────────────────────

    const A: PeerId = PeerId::new(11);
    const B: PeerId = PeerId::new(12);
    const C: PeerId = PeerId::new(13);
    const D: PeerId = PeerId::new(14);
    const E: PeerId = PeerId::new(15);
    const LOCAL: &str = "fd00::1";

    fn peer_addr(peer: PeerId) -> IpAddr {
        addr(&format!("fd00::{:x}", peer.get()))
    }

    fn label(peer: PeerId) -> Label {
        Label::from(format!("k{}", peer.get()))
    }

    fn members(peers: &[PeerId]) -> Vec<NamespaceMember> {
        peers
            .iter()
            .map(|&peer| NamespaceMember {
                label: label(peer),
                addresses: vec![peer_addr(peer).to_string().parse().unwrap()],
            })
            .collect()
    }

    /// Members of `peers` may reach each other and the local node on TCP 22.
    fn namespace(peers: &[PeerId], outbound: Option<Vec<OutboundRule>>) -> NamespacePolicy {
        NamespacePolicy {
            members: members(peers),
            policy: policy(vec![rule("*", "*:22", "tcp")]),
            outbound,
            ..NamespacePolicy::default()
        }
    }

    fn outbound_rule(proto: Option<&str>, ports: &str) -> OutboundRule {
        OutboundRule {
            proto: proto.map(str::to_owned),
            ports: ports.to_owned(),
        }
    }

    /// Identities: the peers of `identity()` plus `A..=E` by their label.
    fn ns_identity() -> Arc<PeerLabelMap> {
        let map = identity();
        for peer in [A, B, C, D, E] {
            map.insert(peer, LabelSet::new([label(peer)]));
        }
        map
    }

    fn ns_filter(engine: &Arc<AclEngine>, config: AclFilterConfig) -> AclFilter {
        AclFilter::with_config(Arc::clone(engine), ns_identity(), config)
    }

    #[test]
    fn cross_namespace_default_deny_and_directed_grants() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace("nsd:a", namespace(&[A, C], None))
            .unwrap();
        engine
            .store_namespace("nsd:b", namespace(&[B], None))
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, b, c, local) = (peer_addr(A), peer_addr(B), peer_addr(C), addr(LOCAL));

        // Same namespace: peer to peer and peer to local.
        assert_eq!(inbound(&f, A, tcp_packet(a, 4000, c, 22)), Verdict::Accept);
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 23)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, c, 23)),
            drop(reasons::DENIED)
        );
        // Different namespaces: denied even where each namespace's rules accept.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, b, 22)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            inbound(&f, B, tcp_packet(b, 4000, a, 22)),
            drop(reasons::CROSS_NAMESPACE)
        );

        // A grant from nsd:a to B on TCP 443 only, in that direction only.
        engine
            .store_grant(
                "a-to-b",
                Grant {
                    from: GrantEnd::Namespace("nsd:a".into()),
                    to: GrantEnd::Label(label(B)),
                    proto: Some("tcp".to_owned()),
                    ports: Some("443".to_owned()),
                },
            )
            .unwrap();
        assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
        assert_eq!(inbound(&f, C, tcp_packet(c, 4000, b, 443)), Verdict::Accept);
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, b, 22)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            inbound(&f, A, udp_packet(a, 4000, b, 443)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            inbound(&f, B, tcp_packet(b, 4000, a, 443)),
            drop(reasons::CROSS_NAMESPACE)
        );
        // A grant opens nothing towards the local node.
        assert_eq!(
            inbound(&f, B, tcp_packet(b, 4000, local, 443)),
            drop(reasons::DENIED)
        );

        let stats = f.stats();
        assert_eq!(
            (stats.accepted, stats.denied, stats.cross_namespace),
            (4, 3, 5)
        );
    }

    #[test]
    fn grant_revocation_stops_new_flows_and_revokes_replies() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace("nsd:a", namespace(&[A], Some(Vec::new())))
            .unwrap();
        engine
            .store_namespace("nsd:b", namespace(&[B], None))
            .unwrap();
        let grant = Grant {
            from: GrantEnd::Label(label(A)),
            to: GrantEnd::Namespace("nsd:b".into()),
            proto: None,
            ports: Some("443".to_owned()),
        };
        engine.store_grant("g", grant.clone()).unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, b) = (peer_addr(A), peer_addr(B));

        // A is outbound-restricted: the accepted inbound flow records an
        // outbound reply allowance, and the reply records an inbound one.
        assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
        assert_eq!(
            outbound(&f, A, tcp_packet(b, 443, a, 4000)),
            Verdict::Accept
        );
        assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);
        let stats = f.stats();
        assert_eq!(
            (stats.accepted, stats.outbound_replies, stats.replies),
            (1, 1, 1)
        );

        // Replacing the grant under the same id keeps the allowances.
        engine.store_grant("g", grant).unwrap();
        assert_eq!(inbound(&f, A, tcp_packet(a, 4000, b, 443)), Verdict::Accept);

        assert!(engine.remove_grant("g"));
        assert!(!engine.remove_grant("g"));
        // The established flow's allowances are revoked on their next lookup.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, b, 443)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(b, 443, a, 4000)),
            drop(reasons::OUTBOUND)
        );
        // New flows are evaluated from scratch.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4001, b, 443)),
            drop(reasons::CROSS_NAMESPACE)
        );
        let stats = f.stats();
        assert_eq!(stats.reply_revoked, 2);
        assert_eq!(stats.cross_namespace, 2);
        assert_eq!(stats.outbound_denied, 1);
    }

    #[test]
    fn outbound_restricted_only_when_every_namespace_opts_in() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A, D], Some(vec![outbound_rule(None, "80")])),
            )
            .unwrap();
        engine
            .store_namespace("nsd:b", namespace(&[D], None))
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, d, local) = (peer_addr(A), peer_addr(D), addr(LOCAL));

        // D is also in nsd:b, which does not restrict outbound.
        assert_eq!(
            outbound(&f, D, tcp_packet(local, 5000, d, 9999)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 9999)),
            drop(reasons::OUTBOUND)
        );
        // A peer in no namespace is unrestricted.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(local, 5000, addr("fd00::99"), 9999)),
            Verdict::Accept
        );

        engine
            .store_namespace("nsd:b", namespace(&[D], Some(Vec::new())))
            .unwrap();
        assert_eq!(
            outbound(&f, D, tcp_packet(local, 5000, d, 9999)),
            drop(reasons::OUTBOUND)
        );
        // The union of the outbound rules of D's namespaces.
        assert_eq!(
            outbound(&f, D, tcp_packet(local, 5000, d, 80)),
            Verdict::Accept
        );
        assert_eq!(f.stats().outbound_denied, 2);
    }

    #[test]
    fn outbound_rules_and_replies() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A], Some(vec![outbound_rule(Some("tcp"), "80,443")])),
            )
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, local) = (peer_addr(A), addr(LOCAL));

        // Outbound rules.
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 443)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, A, udp_packet(local, 5000, a, 443)),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 22)),
            drop(reasons::OUTBOUND)
        );
        // The accepted outbound flow's replies come back as today.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 443, local, 5000)),
            Verdict::Accept
        );

        // Replies to an accepted inbound flow.
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 22, a, 4000)),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 22, a, 4000)),
            Verdict::Accept
        );
        // Not to another port of the same peer.
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 22, a, 4001)),
            drop(reasons::OUTBOUND)
        );
        // A denied inbound packet records nothing.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 23)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 23, a, 4000)),
            drop(reasons::OUTBOUND)
        );

        // Other protocols need allow_other_protocols.
        let ping = || ip(local, a, protocol::ICMPV6, &icmp_echo(128, 1));
        assert_eq!(outbound(&f, A, ping()), drop(reasons::OUTBOUND));
        let stats = f.stats();
        assert_eq!(
            (stats.outbound_denied, stats.outbound_replies, stats.replies),
            (6, 1, 1)
        );

        let f = ns_filter(
            &engine,
            AclFilterConfig {
                allow_other_protocols: true,
                ..AclFilterConfig::default()
            },
        );
        assert_eq!(outbound(&f, A, ping()), Verdict::Accept);
    }

    #[test]
    fn outbound_fragments_to_a_restricted_peer_follow_the_first() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A], Some(vec![outbound_rule(None, "80")])),
            )
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (local, a) = (addr("10.0.0.2"), addr("10.0.0.1"));
        let frag = |id, offset_units, more, transport: &[u8]| {
            ip_frag(
                local,
                a,
                protocol::TCP,
                transport,
                Some(Frag {
                    id,
                    offset_units,
                    more,
                }),
            )
        };
        assert_eq!(
            outbound(&f, A, frag(1, 0, true, &tcp(5000, 80, &[0; 8]))),
            Verdict::Accept
        );
        // Inbound fragments with the same addresses and id are tracked apart.
        let inbound_frag = ip_frag(
            local,
            a,
            protocol::TCP,
            &[0; 8],
            Some(Frag {
                id: 1,
                offset_units: 4,
                more: false,
            }),
        );
        assert_eq!(inbound(&f, A, inbound_frag), drop(reasons::FRAGMENT));
        assert_eq!(outbound(&f, A, frag(1, 4, false, &[0; 8])), Verdict::Accept);
        assert_eq!(
            outbound(&f, A, frag(2, 0, true, &tcp(5000, 81, &[0; 8]))),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            outbound(&f, A, frag(2, 4, false, &[0; 8])),
            drop(reasons::OUTBOUND)
        );
        // Orphan fragment.
        assert_eq!(
            outbound(&f, A, frag(3, 4, false, &[0; 8])),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(f.stats().outbound_denied, 3);
    }

    #[test]
    fn pinhole_namespace_member_gets_nothing_inbound() {
        let engine = loaded_engine(policy(vec![rule("*", "*:*", "tcp")]));
        engine
            .store_namespace(
                "s1",
                NamespacePolicy {
                    kind: NamespaceKind::Pinholes,
                    members: members(&[E]),
                    outbound: Some(Vec::new()),
                    ..NamespacePolicy::default()
                },
            )
            .unwrap();
        engine
            .store_namespace("nsd:a", namespace(&[A], None))
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (e, a, local) = (peer_addr(E), peer_addr(A), addr(LOCAL));
        // The permissive default policy does not apply to a namespace member.
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 22)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, a, 22)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, e, 22)),
            drop(reasons::CROSS_NAMESPACE)
        );
        // Its outbound is restricted by the pinhole namespace.
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 22, e, 4000)),
            drop(reasons::OUTBOUND)
        );
    }

    #[test]
    fn sources_in_no_namespace_use_the_default_policy() {
        let engine = rules_engine(test_policy());
        engine
            .store_namespace("nsd:a", namespace(&[A], Some(Vec::new())))
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 22)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, KEY_PEER, udp_packet(r, 5000, l, 53)),
            Verdict::Accept
        );
        // Even towards a namespace member's address.
        assert_eq!(
            inbound(
                &f,
                PEER,
                tcp_packet(addr("fd00::99"), 4000, peer_addr(A), 22)
            ),
            drop(reasons::DENIED)
        );
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 40000)),
            Verdict::Accept
        );

        // Without a default policy they are fail-closed while namespaces exist.
        engine.uninstall();
        assert!(engine.is_loaded());
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::NO_POLICY)
        );
        let stats = f.stats();
        assert_eq!(
            (stats.accepted, stats.denied, stats.replies, stats.no_policy),
            (2, 2, 1, 1)
        );
    }

    #[test]
    fn grant_revocation_covers_replies_through_unrestricted_peers() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace("nsd:a", namespace(&[A], None))
            .unwrap();
        engine
            .store_namespace("nsd:c", namespace(&[C], None))
            .unwrap();
        engine
            .store_grant(
                "a-to-c",
                Grant {
                    from: GrantEnd::Label(label(A)),
                    to: GrantEnd::Namespace("nsd:c".into()),
                    proto: Some("tcp".to_owned()),
                    ports: Some("443".to_owned()),
                },
            )
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, c) = (peer_addr(A), peer_addr(C));
        let request = || tcp_packet(a, 4000, c, 443);
        let reply = || tcp_packet(c, 443, a, 4000);

        // A hub forwards A -> C under the grant and C's replies back to A.
        assert_eq!(inbound(&f, A, request()), Verdict::Accept);
        assert_eq!(outbound(&f, C, request()), Verdict::Accept);
        assert_eq!(inbound(&f, C, reply()), Verdict::Accept);
        assert_eq!(outbound(&f, A, reply()), Verdict::Accept);
        assert_eq!(inbound(&f, A, request()), Verdict::Accept);
        assert_eq!((f.stats().accepted, f.stats().replies), (1, 2));

        // The replies in both directions depend on the grant.
        assert!(engine.remove_grant("a-to-c"));
        assert_eq!(inbound(&f, C, reply()), drop(reasons::CROSS_NAMESPACE));
        assert_eq!(inbound(&f, A, request()), drop(reasons::CROSS_NAMESPACE));
        assert_eq!(f.stats().reply_revoked, 2);
    }

    // ── pinholes ──────────────────────────────────────────────────────────

    use crate::pinhole::{Direction, PinholeGuard, PinholeSpec};
    use std::time::Instant;

    /// Sessions and kinds: the pinhole namespace `s1` holds `E` (only there)
    /// and `A`; `A` is also in the rule namespace `quick`, which permits
    /// "transfer" pinholes.
    fn pinhole_engine(
        app_outbound: Option<Vec<OutboundRule>>,
    ) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&clock);
        let engine = Arc::new(AclEngine::with_clock(move || *handle.lock().unwrap()));
        let mut quick = namespace(&[A], None);
        quick.pinhole_kinds.insert("transfer".to_owned());
        engine.store_namespace("quick", quick).unwrap();
        engine
            .store_namespace(
                "s1",
                NamespacePolicy {
                    kind: NamespaceKind::Pinholes,
                    members: members(&[A, E]),
                    outbound: app_outbound,
                    ..NamespacePolicy::default()
                },
            )
            .unwrap();
        (engine, clock)
    }

    fn open(
        engine: &Arc<AclEngine>,
        clock: &Mutex<Instant>,
        peer: PeerId,
        direction: Direction,
        dst_port: u16,
    ) -> PinholeGuard {
        let expires_at = *clock.lock().unwrap() + Duration::from_secs(60);
        engine
            .open_pinhole(
                "s1",
                PinholeSpec {
                    label: label(peer),
                    kind: "transfer".to_owned(),
                    protocol: Protocol::Tcp,
                    direction,
                    dst_port,
                    expires_at,
                },
            )
            .unwrap()
    }

    #[test]
    fn session_only_peer_works_only_through_its_inbound_pinhole() {
        let (engine, clock) = pinhole_engine(Some(Vec::new()));
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (e, a, local) = (peer_addr(E), peer_addr(A), addr(LOCAL));
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            drop(reasons::DENIED)
        );

        let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            Verdict::Accept
        );
        // Only that protocol, port, direction and the local node.
        assert_eq!(
            inbound(&f, E, udp_packet(e, 4000, local, 9000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9001)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, a, 9000)),
            drop(reasons::CROSS_NAMESPACE)
        );
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 5000, e, 9000)),
            drop(reasons::OUTBOUND)
        );
        // The reply of the opened flow, and the flow continuing.
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            Verdict::Accept
        );

        std::mem::drop(guard);
        assert_eq!(engine.pinhole_stats().closed, 1);
        // New flows are dropped, the opened flow's allowances are revoked.
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4001, local, 9000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
            drop(reasons::OUTBOUND)
        );
        let stats = f.stats();
        assert_eq!(
            (stats.accepted, stats.replies, stats.outbound_replies),
            (1, 1, 1)
        );
        assert_eq!(stats.reply_revoked, 2);
    }

    #[test]
    fn outbound_pinhole_to_a_restricted_peer() {
        let (engine, clock) = pinhole_engine(Some(Vec::new()));
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (e, local) = (peer_addr(E), addr(LOCAL));
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
            drop(reasons::OUTBOUND)
        );

        let guard = open(&engine, &clock, E, Direction::Outbound, 7000);
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, E, udp_packet(local, 5000, e, 7000)),
            drop(reasons::OUTBOUND)
        );
        // No reverse rule: the peer cannot open flows to the local port 7000.
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 7000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
            Verdict::Accept
        );

        guard.close();
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 5001, e, 7000)),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.replies, stats.reply_revoked), (1, 1));
        assert_eq!(stats.outbound_denied, 3);
    }

    #[test]
    fn pinhole_revocation_covers_replies_through_unrestricted_peers() {
        let (engine, clock) = pinhole_engine(None);
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (e, local) = (peer_addr(E), addr(LOCAL));

        // Outbound pinhole: outbound is accepted anyway, the replies depend
        // on the pinhole.
        let out = open(&engine, &clock, E, Direction::Outbound, 7000);
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 5000, e, 7000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
            Verdict::Accept
        );
        // Inbound pinhole: the local node's replies are accepted anyway, and
        // the flow continuing depends on the pinhole.
        let into = open(&engine, &clock, E, Direction::Inbound, 9000);
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            Verdict::Accept
        );
        assert_eq!((f.stats().accepted, f.stats().replies), (1, 2));

        std::mem::drop((out, into));
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 7000, local, 5000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            drop(reasons::DENIED)
        );
        assert_eq!(f.stats().reply_revoked, 2);
        assert_eq!(engine.pinhole_stats().closed, 2);
    }

    #[test]
    fn source_member_keeps_its_rules_around_a_pinhole() {
        let (engine, clock) = pinhole_engine(None);
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, local) = (peer_addr(A), addr(LOCAL));
        let ssh = || tcp_packet(a, 4000, local, 22);
        let transfer = || tcp_packet(a, 4000, local, 9000);
        assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
        assert_eq!(inbound(&f, A, transfer()), drop(reasons::DENIED));

        let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
        assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
        assert_eq!(inbound(&f, A, transfer()), Verdict::Accept);
        std::mem::drop(guard);
        assert_eq!(inbound(&f, A, ssh()), Verdict::Accept);
        assert_eq!(inbound(&f, A, transfer()), drop(reasons::DENIED));
        // Outbound stays unrestricted throughout.
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 9999)),
            Verdict::Accept
        );
    }

    #[test]
    fn permission_revoked_mid_session_closes_the_pinhole() {
        let (engine, clock) = pinhole_engine(None);
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, local) = (peer_addr(A), addr(LOCAL));
        let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 9000)),
            Verdict::Accept
        );
        // quick stops allowing "transfer".
        engine
            .store_namespace("quick", namespace(&[A], None))
            .unwrap();
        assert!(!guard.is_open());
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4001, local, 9000)),
            drop(reasons::DENIED)
        );
        assert_eq!(engine.pinhole_stats().revoked, 1);
        std::mem::drop(guard);
        assert_eq!(engine.pinhole_stats().closed, 0);
    }

    #[test]
    fn expired_pinholes_stop_flows_without_sleeping() {
        let (engine, clock) = pinhole_engine(Some(Vec::new()));
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (e, local) = (peer_addr(E), addr(LOCAL));
        let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4000, local, 9000)),
            Verdict::Accept
        );

        *clock.lock().unwrap() += Duration::from_secs(60);
        // The established flow's reply allowance is revoked, the pinhole is
        // swept once and new flows are dropped.
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
            drop(reasons::OUTBOUND)
        );
        assert_eq!(
            inbound(&f, E, tcp_packet(e, 4001, local, 9000)),
            drop(reasons::DENIED)
        );
        assert!(!guard.is_open());
        std::mem::drop(guard);
        let stats = engine.pinhole_stats();
        assert_eq!((stats.expired, stats.closed), (1, 0));
        assert_eq!(f.stats().reply_revoked, 1);
    }

    #[test]
    fn namespace_removal_closes_pinholes() {
        let (engine, clock) = pinhole_engine(None);
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, local) = (peer_addr(A), addr(LOCAL));
        let guard = open(&engine, &clock, A, Direction::Inbound, 9000);
        assert!(engine.remove_namespace("s1"));
        assert!(!guard.is_open());
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 9000)),
            drop(reasons::DENIED)
        );
        // Other namespaces are unaffected.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
        assert_eq!(engine.pinhole_stats().namespace_removed, 1);
    }

    #[test]
    fn clear_all_is_an_emergency_stop() {
        let (engine, clock) = pinhole_engine(Some(Vec::new()));
        engine.install(test_policy());
        engine
            .store_namespace("nsd:b", namespace(&[B], None))
            .unwrap();
        engine
            .store_grant(
                "a-to-b",
                Grant {
                    from: GrantEnd::Label(label(A)),
                    to: GrantEnd::Label(label(B)),
                    proto: Some("tcp".to_owned()),
                    ports: Some("443".to_owned()),
                },
            )
            .unwrap();
        let f = ns_filter(&engine, AclFilterConfig::default());
        let (a, b, e, local) = (peer_addr(A), peer_addr(B), peer_addr(E), addr(LOCAL));
        let (remote, v4_local) = (addr("10.0.0.1"), addr("10.0.0.2"));

        // A reply allowance of a flow the local side opened.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(v4_local, 40000, remote, 9999)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(remote, 9999, v4_local, 40000)),
            Verdict::Accept
        );
        // A flow through a pinhole and one through a grant.
        let guard = open(&engine, &clock, E, Direction::Inbound, 9000);
        let pinholed = || tcp_packet(e, 4000, local, 9000);
        assert_eq!(inbound(&f, E, pinholed()), Verdict::Accept);
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 9000, e, 4000)),
            Verdict::Accept
        );
        let granted = || tcp_packet(a, 4000, b, 443);
        assert_eq!(inbound(&f, A, granted()), Verdict::Accept);
        assert_eq!(outbound(&f, B, granted()), Verdict::Accept);

        engine.clear_all();
        assert!(!engine.is_loaded());
        assert_eq!(engine.policy_state(), PolicyState::Failed);
        assert!(engine.namespaces().is_empty() && engine.grants().is_empty());
        assert!(!guard.is_open());
        for (peer, packet) in [
            (PEER, tcp_packet(remote, 9999, v4_local, 40000)),
            (E, pinholed()),
            (A, granted()),
            (B, tcp_packet(b, 443, a, 4000)),
            (A, tcp_packet(a, 4000, local, 22)),
        ] {
            assert_eq!(inbound(&f, peer, packet), drop(reasons::POLICY_FAILED));
        }
        let stats = f.stats();
        assert_eq!((stats.policy_failed, stats.no_policy), (5, 0));
        assert_eq!(stats.policy_state, PolicyState::Failed);

        // Dropping the guard afterwards is a no-op.
        std::mem::drop(guard);
        assert_eq!(
            engine.pinhole_stats(),
            crate::PinholeStats {
                opened: 1,
                cleared: 1,
                ..crate::PinholeStats::default()
            }
        );

        // Later updates work as usual.
        engine
            .store_namespace("nsd:b", namespace(&[B], None))
            .unwrap();
        assert_eq!(
            inbound(&f, B, tcp_packet(b, 4000, local, 22)),
            Verdict::Accept
        );
        engine.install(test_policy());
        assert_eq!(
            inbound(&f, PEER, tcp_packet(remote, 4000, v4_local, 80)),
            Verdict::Accept
        );
    }

    // ── Labels per source address ──

    const GATEWAY: PeerId = PeerId::new(20);

    /// The host prefix of `ip`.
    fn host(ip: IpAddr) -> IpNet {
        ip.to_string().parse().unwrap()
    }

    /// The member label of the source address `ip`.
    fn address_label(ip: IpAddr) -> Label {
        Label::from(format!("addr:{ip}"))
    }

    /// The ns identities plus [`GATEWAY`] labelled per source address:
    /// `peer_addr(A)` carries `ADDR` and its own member label, every other
    /// address `ADDR`.
    fn by_source_identity() -> Arc<PeerLabelMap> {
        let map = ns_identity();
        let member = peer_addr(A);
        map.insert_by_source(
            GATEWAY,
            vec![
                (net("0.0.0.0/0"), label_set(&[ADDR])),
                (net("::/0"), label_set(&[ADDR])),
                (
                    host(member),
                    LabelSet::new([ADDR.into(), address_label(member)]),
                ),
            ],
        );
        map
    }

    /// A namespace whose only member is the label of the source address
    /// `member`, with `acls` and the given outbound rules.
    fn address_namespace(
        member: IpAddr,
        acls: Vec<AclRule>,
        outbound: Option<Vec<OutboundRule>>,
    ) -> NamespacePolicy {
        NamespacePolicy {
            members: vec![NamespaceMember {
                label: address_label(member),
                addresses: vec![host(member)],
            }],
            policy: policy(acls),
            outbound,
            ..NamespacePolicy::default()
        }
    }

    #[test]
    fn insert_by_source_takes_the_longest_prefix() {
        let map = PeerLabelMap::new();
        let generation = map.generation();
        map.insert_by_source(
            GATEWAY,
            vec![
                (net("10.0.0.0/8"), label_set(&["wide"])),
                (net("10.1.0.0/16"), label_set(&["narrow"])),
                (net("10.1.2.3/32"), label_set(&["host", "narrow"])),
                (net("10.1.0.0/16"), label_set(&["second"])),
            ],
        );
        assert!(map.generation() > generation);
        assert!(map.by_source(GATEWAY));
        assert_eq!(map.labels(GATEWAY), None);
        let labels = |ip| map.labels_for(GATEWAY, addr(ip));
        assert_eq!(labels("10.1.2.3"), Some(label_set(&["host", "narrow"])));
        // Equally long prefixes: the first listed wins.
        assert_eq!(labels("10.1.2.4"), Some(label_set(&["narrow"])));
        assert_eq!(labels("10.2.0.1"), Some(label_set(&["wide"])));
        // Outside every prefix (another family included): unknown.
        assert_eq!(labels("11.0.0.1"), None);
        assert_eq!(labels("fd00::1"), None);
        // An empty table makes every address unknown.
        map.insert_by_source(GATEWAY, Vec::new());
        assert_eq!(labels("10.1.2.3"), None);
        // `insert` replaces the table.
        map.insert(GATEWAY, label_set(&["fixed"]));
        assert!(!map.by_source(GATEWAY));
        assert_eq!(labels("11.0.0.1"), Some(label_set(&["fixed"])));
    }

    #[test]
    fn by_source_peer_outside_its_prefixes_is_unknown() {
        let map = Arc::new(PeerLabelMap::new());
        map.insert_by_source(GATEWAY, vec![(net("10.0.0.0/30"), label_set(&[ADDR]))]);
        let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
        let l = addr("10.0.0.2");
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(addr("10.0.0.1"), 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(addr("10.0.0.5"), 4000, l, 80)),
            drop(reasons::UNKNOWN_PEER)
        );
        assert_eq!(f.stats().unknown_peer, 1);
    }

    #[test]
    fn by_source_peer_is_judged_by_each_source() {
        let map = by_source_identity();
        let (r, other, l) = (addr("10.0.0.1"), addr("10.0.0.5"), addr("10.0.0.2"));
        assert!(map.by_source(GATEWAY) && !map.by_source(KEY_PEER));

        let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(other, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        // Each source keeps its own verdict on later packets.
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(r, 4001, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(other, 4001, l, 80)),
            drop(reasons::DENIED)
        );
        // A peer with a fixed label set in the same map keeps it.
        assert_eq!(
            inbound(&f, KEY_PEER, udp_packet(other, 5000, l, 53)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, KEY_PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn by_source_cache_is_bounded() {
        let config = AclFilterConfig {
            reply_capacity: 2,
            ..AclFilterConfig::default()
        };
        let f = AclFilter::with_config(rules_engine(test_policy()), by_source_identity(), config);
        let l = addr("10.0.0.2");
        for round in 0..3 {
            for last in [1, 5, 6, 7] {
                let src = addr(&format!("10.0.0.{last}"));
                let expected = if last == 1 {
                    Verdict::Accept
                } else {
                    drop(reasons::DENIED)
                };
                assert_eq!(
                    inbound(&f, GATEWAY, tcp_packet(src, 4000 + round, l, 80)),
                    expected
                );
            }
        }
        let table = f.inner.table();
        assert!(table.sources.len() <= 2);
    }

    #[test]
    fn closure_identity_uses_the_default_labels_for() {
        let identity = |peer: PeerId| (peer == PEER).then(|| LabelSet::new([key_label()]));
        let any = addr("10.0.0.9");
        assert_eq!(
            identity.labels_for(PEER, any),
            Some(LabelSet::new([key_label()]))
        );
        assert!(!identity.by_source(PEER));
        assert_eq!(identity.generation(), 0);
        let f = AclFilter::new(rules_engine(test_policy()), identity);
        assert_eq!(
            inbound(&f, PEER, udp_packet(any, 5000, addr("10.0.0.2"), 53)),
            Verdict::Accept
        );
    }

    #[test]
    fn switching_between_by_source_and_by_key_applies_to_the_next_packet() {
        let engine = Arc::new(AclEngine::new());
        let member = peer_addr(A);
        engine
            .store_namespace(
                "nsd:a",
                address_namespace(member, vec![rule("*", "*:22", "tcp")], None),
            )
            .unwrap();
        let map = by_source_identity();
        let f = AclFilter::new(Arc::clone(&engine), Arc::clone(&map));
        let local = addr(LOCAL);
        let packet = || tcp_packet(member, 4000, local, 22);

        // The member source's flow verdict is cached.
        assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
        assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
        // Another source of the same peer is in no namespace.
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(addr("fd00::77"), 4000, local, 22)),
            drop(reasons::NO_POLICY)
        );

        // A fixed label set: `label(A)` is in no namespace either.
        map.insert(GATEWAY, LabelSet::new([label(A)]));
        assert_eq!(inbound(&f, GATEWAY, packet()), drop(reasons::NO_POLICY));
        let table = vec![(host(member), LabelSet::new([address_label(member)]))];
        map.insert_by_source(GATEWAY, table);
        assert_eq!(inbound(&f, GATEWAY, packet()), Verdict::Accept);
        map.remove(GATEWAY);
        assert_eq!(inbound(&f, GATEWAY, packet()), drop(reasons::UNKNOWN_PEER));
    }

    #[test]
    fn bypass_is_never_shared_across_sources() {
        let engine = Arc::new(AclEngine::new());
        let open = addr("fd00::b");
        let accept_all = AclRule {
            action: AclAction::Accept,
            src: vec!["*".to_owned()],
            dst: vec!["*:*".to_owned()],
            proto: None,
        };
        engine
            .store_namespace("nsd:a", address_namespace(open, vec![accept_all], None))
            .unwrap();
        let f = AclFilter::new(Arc::clone(&engine), by_source_identity());
        let local = addr(LOCAL);
        assert_eq!(
            inbound(&f, GATEWAY, udp_packet(open, 4000, local, 9999)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
            drop(reasons::NO_POLICY)
        );

        // A default policy that accepts everything bypasses every source in no namespace.
        engine.load(policy(vec![rule("*", "*:*", "udp")])).unwrap();
        assert_eq!(
            inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
            Verdict::Accept
        );
        // A partial default policy bypasses nothing.
        engine.install(
            RuleSet::new([Rule::new("d", vec![ProtocolMatch::Udp(PortSet::Any)])
                .with_labels([ADDR.into()])
                .with_sources([net("fd00::d/128")])])
            .unwrap(),
        );
        assert_eq!(
            inbound(&f, GATEWAY, udp_packet(addr("fd00::d"), 4000, local, 9999)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, udp_packet(addr("fd00::c"), 4000, local, 9999)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn outbound_restriction_follows_the_destination_address() {
        let engine = Arc::new(AclEngine::new());
        let restricted = peer_addr(A);
        engine
            .store_namespace(
                "nsd:a",
                address_namespace(
                    restricted,
                    vec![rule("*", "*:22", "tcp")],
                    Some(vec![outbound_rule(Some("tcp"), "80")]),
                ),
            )
            .unwrap();
        let local = addr(LOCAL);
        for f in [
            AclFilter::new(Arc::clone(&engine), by_source_identity()),
            AclFilter::uncached(
                Arc::clone(&engine),
                by_source_identity(),
                AclFilterConfig::default(),
            ),
        ] {
            assert_eq!(
                outbound(&f, GATEWAY, tcp_packet(local, 5000, restricted, 9999)),
                drop(reasons::OUTBOUND)
            );
            assert_eq!(
                outbound(&f, GATEWAY, tcp_packet(local, 5000, restricted, 80)),
                Verdict::Accept
            );
            // Another destination behind the same peer is unrestricted.
            assert_eq!(
                outbound(&f, GATEWAY, tcp_packet(local, 5000, addr("fd00::c"), 9999)),
                Verdict::Accept
            );
            // The restricted source's accepted inbound flow allows its reply.
            assert_eq!(
                inbound(&f, GATEWAY, tcp_packet(restricted, 4000, local, 22)),
                Verdict::Accept
            );
            assert_eq!(
                outbound(&f, GATEWAY, tcp_packet(local, 22, restricted, 4000)),
                Verdict::Accept
            );
            let stats = f.stats();
            assert_eq!((stats.outbound_denied, stats.outbound_replies), (1, 1));
        }
    }

    // ── crates/acl mode: allow-only fragments, bypass flags ───────────────

    /// An engine with `rules` installed whose clock is moved by hand.
    fn clocked_engine(rules: RuleSet) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&clock);
        let engine = AclEngine::with_clock(move || *handle.lock().unwrap());
        engine.install(rules);
        (Arc::new(engine), clock)
    }

    fn advance(clock: &Mutex<Instant>, by: Duration) {
        *clock.lock().unwrap() += by;
    }

    fn allow_only(capacity: usize) -> AclFilterConfig {
        AclFilterConfig {
            fragments: FragmentMode::AllowOnly {
                ttl: Duration::from_secs(15),
                capacity,
            },
            ..AclFilterConfig::default()
        }
    }

    fn allowed_len(f: &AclFilter) -> usize {
        f.inner.fragments.lock().unwrap().allowed.len()
    }

    /// The middle fragment of datagram `id`.
    fn continuation(id: u16) -> PacketBuf {
        fragment(id, 4, true, &[0; 8])
    }

    #[test]
    fn allow_only_constants_are_those_of_ns() {
        assert_eq!(FragmentMode::default(), FragmentMode::Outcome);
        assert_eq!(
            FragmentMode::ALLOW_ONLY,
            FragmentMode::AllowOnly {
                ttl: Duration::from_secs(15),
                capacity: 4096,
            }
        );
        let config = AclFilterConfig::default();
        assert_eq!(config.fragments, FragmentMode::Outcome);
        assert_eq!(config.accept_to_local, None);
        assert!(!config.accept_icmp_echo_reply);
    }

    /// ns `fragment_gate_remembers_until_ttl_then_expires`.
    #[test]
    fn allow_only_remembers_until_ttl_then_expires() {
        let (engine, clock) = clocked_engine(test_policy());
        let f = AclFilter::with_config(engine, identity(), allow_only(4096));
        assert_eq!(
            inbound(&f, PEER, continuation(7)),
            drop(reasons::FRAGMENT),
            "empty gate denies"
        );
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        advance(&clock, Duration::from_secs(1));
        assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
        // Still valid just before the TTL boundary...
        advance(&clock, Duration::from_millis(13_999));
        assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
        // ...and gone at it (expiry is exclusive), removed on lookup.
        advance(&clock, Duration::from_millis(1));
        assert_eq!(inbound(&f, PEER, continuation(7)), drop(reasons::FRAGMENT));
        assert_eq!(allowed_len(&f), 0, "expired entry removed on lookup");
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.fragment), (3, 2));
    }

    /// ns `fragment_gate_is_bounded_and_prunes_expired_under_pressure`, with
    /// a small capacity.
    #[test]
    fn allow_only_is_bounded_and_prunes_expired_under_pressure() {
        let (engine, clock) = clocked_engine(test_policy());
        let f = AclFilter::with_config(engine, identity(), allow_only(2));
        for id in 1..=3 {
            assert_eq!(inbound(&f, PEER, first_fragment(id, 80)), Verdict::Accept);
        }
        assert_eq!(allowed_len(&f), 2, "table must stay bounded");
        // Live entries are never evicted: the third one was not recorded.
        assert_eq!(inbound(&f, PEER, continuation(1)), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, continuation(2)), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, continuation(3)), drop(reasons::FRAGMENT));
        assert_eq!(f.stats().fragment_evictions, 0);

        // Once the live entries have expired, a new one prunes and succeeds.
        advance(&clock, Duration::from_secs(16));
        assert_eq!(inbound(&f, PEER, first_fragment(4, 80)), Verdict::Accept);
        assert_eq!(allowed_len(&f), 1);
        assert_eq!(inbound(&f, PEER, continuation(4)), Verdict::Accept);
    }

    #[test]
    fn allow_only_key_has_no_peer() {
        let f = filter_with(allow_only(4096));
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        assert_eq!(inbound(&f, OTHER_PEER, continuation(7)), Verdict::Accept);
    }

    #[test]
    fn allow_only_records_no_denied_first_fragment() {
        let f = filter_with(allow_only(4096));
        assert_eq!(
            inbound(&f, PEER, first_fragment(9, 81)),
            drop(reasons::DENIED)
        );
        assert_eq!(allowed_len(&f), 0);
        assert_eq!(inbound(&f, PEER, continuation(9)), drop(reasons::FRAGMENT));
        let stats = f.stats();
        assert_eq!((stats.denied, stats.fragment), (1, 1));
    }

    #[test]
    fn allow_only_drops_out_of_order_continuations() {
        let f = filter_with(allow_only(4096));
        assert_eq!(inbound(&f, PEER, continuation(5)), drop(reasons::FRAGMENT));
        assert_eq!(inbound(&f, PEER, first_fragment(5, 80)), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, continuation(5)), Verdict::Accept);
    }

    #[test]
    fn allow_only_last_fragment_keeps_the_entry() {
        let f = filter_with(allow_only(4096));
        let last = || fragment(6, 6, false, &[0; 8]);
        assert_eq!(inbound(&f, PEER, first_fragment(6, 80)), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, last()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, last()), Verdict::Accept);
        assert_eq!(allowed_len(&f), 1);
    }

    #[test]
    fn allow_only_records_first_fragments_of_several_only() {
        let f = filter_with(allow_only(4096));
        let r = addr("10.0.0.1");
        let l = addr("10.0.0.2");
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(allowed_len(&f), 0);
    }

    #[test]
    fn allow_only_judges_continuations_before_the_policy_check() {
        let engine = rules_engine(test_policy());
        let f = AclFilter::with_config(Arc::clone(&engine), identity(), allow_only(4096));
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        engine.uninstall();
        assert_eq!(inbound(&f, PEER, continuation(7)), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, continuation(8)), drop(reasons::FRAGMENT));
        assert_eq!(
            inbound(&f, PEER, first_fragment(9, 80)),
            drop(reasons::NO_POLICY)
        );
        // The outcome mode checks the policy first.
        let f = AclFilter::with_config(engine, identity(), AclFilterConfig::default());
        assert_eq!(inbound(&f, PEER, continuation(7)), drop(reasons::NO_POLICY));
    }

    #[test]
    fn allow_only_leaves_ipv6_fragments_alone() {
        let (r, l) = (addr("fd00::1"), addr("fd00::2"));
        // A fragment header: next header TCP, offset 8 bytes, id 1.
        let frag = ip(r, l, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0]);
        let first = ip(r, l, 44, &[protocol::TCP, 0, 0, 1, 0, 0, 0, 1, 0, 0]);
        for config in [AclFilterConfig::default(), allow_only(4096)] {
            let f = filter_with(config);
            assert_eq!(inbound(&f, PEER, first.clone()), drop(reasons::PROTOCOL));
            assert_eq!(inbound(&f, PEER, frag.clone()), drop(reasons::PROTOCOL));
            assert_eq!(allowed_len(&f), 0);
        }
    }

    #[test]
    fn accept_to_local_bypasses_the_policy() {
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::with_config(Arc::clone(&engine), identity(), AclFilterConfig::default());
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 9)),
            drop(reasons::NO_POLICY)
        );

        let f = AclFilter::with_config(
            engine,
            identity(),
            AclFilterConfig {
                accept_to_local: Some("10.0.0.2".parse().unwrap()),
                fragments: FragmentMode::ALLOW_ONLY,
                ..AclFilterConfig::default()
            },
        );
        // No policy, any port, an orphan fragment, another protocol.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 9)),
            Verdict::Accept
        );
        assert_eq!(inbound(&f, PEER, continuation(3)), Verdict::Accept);
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(8, 1))),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, addr("10.0.0.3"), 9)),
            drop(reasons::NO_POLICY)
        );
        // IPv6 is never bypassed.
        assert_eq!(
            inbound(
                &f,
                PEER,
                tcp_packet(addr("fd00::1"), 4000, addr("fd00::2"), 9)
            ),
            drop(reasons::NO_POLICY)
        );
        let stats = f.stats();
        assert_eq!((stats.bypassed, stats.accepted, stats.no_policy), (3, 0, 2));
        // Outbound is unaffected.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 9, r, 4000)),
            Verdict::Accept
        );
    }

    #[test]
    fn accept_icmp_echo_reply_bypasses_the_policy() {
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let reply = || ip(r, l, protocol::ICMP, &icmp_echo(0, 1));
        let request = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
        let f = filter();
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));

        let f = AclFilter::with_config(
            Arc::new(AclEngine::new()),
            identity(),
            AclFilterConfig {
                accept_icmp_echo_reply: true,
                fragments: FragmentMode::ALLOW_ONLY,
                ..AclFilterConfig::default()
            },
        );
        assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, request()), drop(reasons::NO_POLICY));
        // As ns: the type byte of a non-first fragment is read too.
        let tail = ip_frag(
            r,
            l,
            protocol::ICMP,
            &[0; 8],
            Some(Frag {
                id: 1,
                offset_units: 4,
                more: false,
            }),
        );
        assert_eq!(inbound(&f, PEER, tail), Verdict::Accept);
        // Too short for an ICMP header.
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &[0; 4])),
            drop(reasons::NO_POLICY)
        );
        // An ICMPv6 echo reply is not bypassed.
        let v6 = ip(
            addr("fd00::1"),
            addr("fd00::2"),
            protocol::ICMPV6,
            &icmp_echo(129, 1),
        );
        assert_eq!(inbound(&f, PEER, v6), drop(reasons::NO_POLICY));
        assert_eq!(f.stats().bypassed, 2);
    }

    #[test]
    fn stateless_replies_are_judged_by_the_policy_only() {
        let f = AclFilter::with_config(
            rules_engine(test_policy()),
            identity(),
            AclFilterConfig {
                stateful_replies: false,
                allow_other_protocols: false,
                ..AclFilterConfig::default()
            },
        );
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        assert_eq!(
            outbound(&f, PEER, udp_packet(l, 5000, r, 9)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, udp_packet(r, 9, l, 5000)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            outbound(&f, PEER, ip(l, r, protocol::ICMP, &icmp_echo(8, 1))),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(0, 1))),
            drop(reasons::PROTOCOL)
        );
        // A reply the policy accepts is accepted as new traffic.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 80, r, 4000)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        let stats = f.stats();
        assert_eq!((stats.replies, stats.accepted), (0, 1));
        let table = f.inner.table();
        assert_eq!(table.entries.len(), 0);
        assert!(table.pending.is_empty());
    }

    #[test]
    fn stateless_replies_record_nothing_for_restricted_peers() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A], Some(vec![outbound_rule(Some("tcp"), "80")])),
            )
            .unwrap();
        let config = AclFilterConfig {
            stateful_replies: false,
            ..AclFilterConfig::default()
        };
        let f = ns_filter(&engine, config);
        let (a, local) = (peer_addr(A), addr(LOCAL));
        for _ in 0..2 {
            assert_eq!(
                inbound(&f, A, tcp_packet(a, 4000, local, 22)),
                Verdict::Accept
            );
            assert_eq!(
                outbound(&f, A, tcp_packet(local, 22, a, 4000)),
                drop(reasons::OUTBOUND)
            );
        }
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 80, local, 5000)),
            drop(reasons::DENIED)
        );
        let stats = f.stats();
        assert_eq!((stats.outbound_replies, stats.replies), (0, 0));
        let table = f.inner.table();
        assert_eq!(table.entries.len(), table.verdicts, "only cached verdicts");
        assert!(table.pending.is_empty());
    }

    /// The identities of an ns account: the address label for the peers
    /// judged by source address, the key label for relay clients.
    fn crates_acl_identity() -> Arc<PeerLabelMap> {
        let map = Arc::new(PeerLabelMap::new());
        map.insert(PEER, label_set(&[ADDR]));
        map.insert(KEY_PEER, LabelSet::new([key_label()]));
        map
    }

    #[test]
    fn crates_acl_preset() {
        let local = "10.0.0.2".parse().unwrap();
        let config = AclFilterConfig::crates_acl(Some(local));
        assert_eq!(
            config,
            AclFilterConfig {
                allow_other_protocols: false,
                stateful_replies: false,
                fragments: FragmentMode::ALLOW_ONLY,
                accept_to_local: Some(local),
                accept_icmp_echo_reply: true,
                ipv6: Ipv6Mode::Accept,
                ..AclFilterConfig::default()
            }
        );
        assert_eq!(AclFilterConfig::crates_acl(None).accept_to_local, None);
    }

    /// ns `acl_check_packet` (with `is_icmp_echo_reply` before it) through the
    /// preset; ns has no unit tests of it, so these follow its code.
    #[test]
    fn crates_acl_matches_acl_check_packet() {
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::with_config(
            Arc::clone(&engine),
            crates_acl_identity(),
            AclFilterConfig::crates_acl(None),
        );
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        // No policy: fail closed, except echo replies.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::NO_POLICY)
        );
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(0, 1))),
            Verdict::Accept
        );
        engine.install(test_policy());
        // By source address.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 81)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(addr("10.0.0.7"), 4000, l, 80)),
            drop(reasons::DENIED)
        );
        // A relay client by its key.
        assert_eq!(
            inbound(&f, KEY_PEER, udp_packet(addr("10.0.0.7"), 4000, l, 53)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, udp_packet(addr("10.0.0.7"), 4000, l, 53)),
            drop(reasons::DENIED)
        );
        // Not TCP or UDP.
        assert_eq!(
            inbound(&f, PEER, ip(r, l, protocol::ICMP, &icmp_echo(8, 1))),
            drop(reasons::PROTOCOL)
        );
        // No reply allowances.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 5000, r, 22)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 22, l, 5000)),
            drop(reasons::DENIED)
        );
        // Fragments through the allow-only gate.
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        assert_eq!(inbound(&f, OTHER_PEER, continuation(7)), Verdict::Accept);
        assert_eq!(
            inbound(&f, PEER, first_fragment(8, 81)),
            drop(reasons::DENIED)
        );
        assert_eq!(inbound(&f, PEER, continuation(8)), drop(reasons::FRAGMENT));
    }

    fn ipv6_accept() -> AclFilterConfig {
        AclFilterConfig {
            ipv6: Ipv6Mode::Accept,
            ..AclFilterConfig::default()
        }
    }

    #[test]
    fn ipv6_is_evaluated_by_default() {
        assert_eq!(AclFilterConfig::default().ipv6, Ipv6Mode::Evaluate);
        let f = filter();
        let (r, l) = (addr("fd00::1"), addr("fd00::2"));
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
            drop(reasons::DENIED)
        );
        assert_eq!(f.stats().ipv6_accepted, 0);
    }

    #[test]
    fn ipv6_accept_passes_inbound_ipv6_unevaluated() {
        let (r, l) = (addr("fd00::1"), addr("fd00::2"));
        let frag = ip(r, l, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0]);
        let echo = ip(r, l, protocol::ICMPV6, &icmp_echo(128, 1));
        let truncated = || PacketBuf::from_packet(&[0x60, 0, 0]);
        for config in [ipv6_accept(), AclFilterConfig::crates_acl(None)] {
            // No policy loaded.
            let engine = Arc::new(AclEngine::new());
            let f = AclFilter::with_config(Arc::clone(&engine), identity(), config);
            assert_eq!(
                inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
                Verdict::Accept
            );
            assert_eq!(
                inbound(
                    &f,
                    PEER,
                    tcp_packet(addr("10.0.0.1"), 4000, addr("10.0.0.2"), 80)
                ),
                drop(reasons::NO_POLICY)
            );
            engine.install(test_policy());
            // A denied port, a fragment, ICMPv6 and a truncated packet.
            assert_eq!(
                inbound(&f, PEER, tcp_packet(r, 4000, l, 444)),
                Verdict::Accept
            );
            assert_eq!(inbound(&f, PEER, frag.clone()), Verdict::Accept);
            assert_eq!(inbound(&f, PEER, echo.clone()), Verdict::Accept);
            assert_eq!(inbound(&f, PEER, truncated()), Verdict::Accept);
            let stats = f.stats();
            assert_eq!((stats.ipv6_accepted, stats.accepted), (5, 0));
            assert_eq!(f.inner.table().entries.len(), 0);
            assert_eq!(allowed_len(&f), 0);
            assert_eq!(f.inner.fragments.lock().unwrap().entries.len(), 0);
            // IPv4 is unaffected.
            let (r4, l4) = (addr("10.0.0.1"), addr("10.0.0.2"));
            assert_eq!(
                inbound(&f, PEER, tcp_packet(r4, 4000, l4, 80)),
                Verdict::Accept
            );
            assert_eq!(
                inbound(&f, PEER, tcp_packet(r4, 4000, l4, 81)),
                drop(reasons::DENIED)
            );
            let stats = f.stats();
            assert_eq!((stats.ipv6_accepted, stats.accepted), (5, 1));
        }
    }

    #[test]
    fn ipv6_accept_passes_outbound_ipv6_unevaluated() {
        let engine = Arc::new(AclEngine::new());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A], Some(vec![outbound_rule(Some("tcp"), "80")])),
            )
            .unwrap();
        let (a, local) = (peer_addr(A), addr(LOCAL));
        let evaluate = ns_filter(&engine, AclFilterConfig::default());
        assert_eq!(
            outbound(&evaluate, A, tcp_packet(local, 5000, a, 22)),
            drop(reasons::OUTBOUND)
        );

        let f = ns_filter(&engine, ipv6_accept());
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 22)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(
                &f,
                A,
                ip(local, a, 44, &[protocol::TCP, 0, 0, 8, 0, 0, 0, 1, 0, 0])
            ),
            Verdict::Accept
        );
        // The reply passes unevaluated too; no allowance was recorded.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 22, local, 5000)),
            Verdict::Accept
        );
        let stats = f.stats();
        assert_eq!(
            (stats.ipv6_accepted, stats.outbound_denied, stats.replies),
            (3, 0, 0)
        );
        assert_eq!(f.inner.table().entries.len(), 0);
    }

    // ── outbound source scope ─────────────────────────────────────────────

    /// The local IPv4 address of the scope tests.
    const LOCAL4: &str = "10.0.0.2";

    /// A filter whose outbound sources are `LOCAL4/32` and `LOCAL/128`.
    fn scoped(engine: &Arc<AclEngine>, config: AclFilterConfig) -> AclFilter {
        let scope = AclFilterScope::new().with_outbound_sources([
            format!("{LOCAL4}/32").parse().unwrap(),
            format!("{LOCAL}/128").parse().unwrap(),
        ]);
        AclFilter::with_scope(Arc::clone(engine), ns_identity(), config, scope)
    }

    /// `A` restricted to outbound TCP 80, in one namespace with `C`.
    fn scope_engine() -> Arc<AclEngine> {
        let engine = rules_engine(test_policy());
        engine
            .store_namespace(
                "nsd:a",
                namespace(&[A, C], Some(vec![outbound_rule(Some("tcp"), "80")])),
            )
            .unwrap();
        engine
    }

    #[test]
    fn default_scope_accepts_a_foreign_outbound_source() {
        assert_eq!(AclFilterScope::new(), AclFilterScope::default());
        assert_eq!(AclFilterScope::default().outbound_sources, None);
        let f = filter();
        let foreign = tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 80);
        assert_eq!(outbound(&f, PEER, foreign), Verdict::Accept);
        let foreign = tcp_packet(addr("fd00::99"), 5000, addr("fd00::9"), 80);
        assert_eq!(outbound(&f, PEER, foreign), Verdict::Accept);
        assert_eq!(f.stats().outbound_source, 0);
    }

    #[test]
    fn outbound_source_scope_passes_own_addresses_to_the_destination_rules() {
        let engine = scope_engine();
        let f = scoped(&engine, AclFilterConfig::default());
        let (a, local, local4) = (peer_addr(A), addr(LOCAL), addr(LOCAL4));
        let foreign = addr("fd00::99");

        // An unrestricted peer: own sources pass, foreign ones are dropped.
        assert_eq!(
            outbound(&f, PEER, tcp_packet(local4, 5000, addr("10.0.0.1"), 9)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, PEER, udp_packet(local, 5000, addr("fd00::9"), 9)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(
                &f,
                PEER,
                tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 9)
            ),
            drop(reasons::OUTBOUND_SOURCE)
        );
        // The ns evidence: an IPv6 SYN from fd00::99 into the tunnel.
        assert_eq!(
            outbound(&f, A, tcp_packet(foreign, 40000, a, 22)),
            drop(reasons::OUTBOUND_SOURCE)
        );

        // A restricted peer: own sources are still judged by its outbound rules.
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 80)),
            Verdict::Accept
        );
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 22)),
            drop(reasons::OUTBOUND)
        );
        // Every protocol is checked.
        let ping = ip(foreign, a, protocol::ICMPV6, &icmp_echo(128, 1));
        assert_eq!(outbound(&f, A, ping), drop(reasons::OUTBOUND_SOURCE));

        let stats = f.stats();
        assert_eq!((stats.outbound_source, stats.outbound_denied), (3, 1));
        // Inbound handling is unchanged.
        assert_eq!(
            inbound(&f, A, tcp_packet(a, 4000, local, 22)),
            Verdict::Accept
        );
    }

    #[test]
    fn outbound_source_is_checked_before_rules_pinholes_and_replies() {
        let engine = scope_engine();
        let (a, c, foreign) = (peer_addr(A), peer_addr(C), addr("fd00::99"));
        let unscoped = ns_filter(&engine, AclFilterConfig::default());
        let f = scoped(&engine, AclFilterConfig::default());

        // A matching outbound rule.
        let to_rule = || tcp_packet(foreign, 5000, a, 80);
        assert_eq!(outbound(&unscoped, A, to_rule()), Verdict::Accept);
        assert_eq!(outbound(&f, A, to_rule()), drop(reasons::OUTBOUND_SOURCE));

        // A reply allowance: `A` reaches `C` on TCP 22 and `C` answers from its own address.
        let reply = || tcp_packet(c, 22, a, 4000);
        for filter in [&unscoped, &f] {
            assert_eq!(
                inbound(filter, A, tcp_packet(a, 4000, c, 22)),
                Verdict::Accept
            );
        }
        assert_eq!(outbound(&unscoped, A, reply()), Verdict::Accept);
        assert_eq!(outbound(&f, A, reply()), drop(reasons::OUTBOUND_SOURCE));
        assert_eq!(unscoped.stats().outbound_replies, 1);
        assert_eq!(f.stats().outbound_replies, 0);

        // An open outbound pinhole.
        let (engine, clock) = pinhole_engine(Some(Vec::new()));
        let unscoped = ns_filter(&engine, AclFilterConfig::default());
        let f = scoped(&engine, AclFilterConfig::default());
        let _guard = open(&engine, &clock, E, Direction::Outbound, 7000);
        let to_pinhole = || tcp_packet(foreign, 5000, peer_addr(E), 7000);
        assert_eq!(outbound(&unscoped, E, to_pinhole()), Verdict::Accept);
        assert_eq!(
            outbound(&f, E, to_pinhole()),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(f.stats().outbound_source, 1);

        // A dropped packet to an unrestricted peer records no reply allowance.
        let f = scoped(&engine, AclFilterConfig::default());
        assert_eq!(
            outbound(&f, PEER, udp_packet(foreign, 5000, addr("fd00::9"), 53)),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(f.inner.table().entries.len(), 0);
    }

    #[test]
    fn outbound_source_scope_drops_truncated_and_foreign_fragments() {
        let engine = scope_engine();
        let f = scoped(&engine, AclFilterConfig::default());
        // Too short to hold the source address, or no IP version at all.
        let mut v4 = vec![0x45; 15];
        let mut v6 = vec![0x60; 23];
        assert_eq!(
            outbound(&f, PEER, PacketBuf::from_packet(&v4)),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(
            outbound(&f, PEER, PacketBuf::from_packet(&v6)),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(
            outbound(&f, PEER, PacketBuf::from_packet(&[])),
            drop(reasons::OUTBOUND_SOURCE)
        );
        // Long enough for the source, but not a valid packet: judged as before.
        v4.push(0x45);
        v4[12..16].copy_from_slice(&[10, 0, 0, 2]);
        assert_eq!(
            outbound(&f, PEER, PacketBuf::from_packet(&v4)),
            Verdict::Accept
        );
        v6.push(0x60);
        v6[8..24].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        assert_eq!(
            outbound(&f, PEER, PacketBuf::from_packet(&v6)),
            Verdict::Accept
        );

        // Each fragment carries the source: a non-first one from a foreign address is dropped.
        let (local4, remote) = (addr(LOCAL4), addr("10.0.0.1"));
        let frag = |src, offset_units| {
            ip_frag(
                src,
                remote,
                protocol::UDP,
                &[0; 8],
                Some(Frag {
                    id: 9,
                    offset_units,
                    more: true,
                }),
            )
        };
        assert_eq!(outbound(&f, PEER, frag(local4, 0)), Verdict::Accept);
        assert_eq!(outbound(&f, PEER, frag(local4, 1)), Verdict::Accept);
        assert_eq!(
            outbound(&f, PEER, frag(addr("10.0.0.99"), 1)),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(f.stats().outbound_source, 4);
    }

    #[test]
    fn empty_outbound_sources_drop_every_outbound_packet() {
        let engine = scope_engine();
        let scope = AclFilterScope::new().with_outbound_sources(Vec::new());
        assert_eq!(scope.outbound_sources, Some(Vec::new()));
        let f = AclFilter::with_scope(engine, ns_identity(), AclFilterConfig::default(), scope);
        let (local, a) = (addr(LOCAL), peer_addr(A));
        assert_eq!(
            outbound(&f, A, tcp_packet(local, 5000, a, 80)),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(
            outbound(
                &f,
                PEER,
                tcp_packet(addr(LOCAL4), 5000, addr("10.0.0.1"), 80)
            ),
            drop(reasons::OUTBOUND_SOURCE)
        );
        assert_eq!(f.stats().outbound_source, 2);
    }

    #[test]
    fn ipv6_accept_passes_outbound_ipv6_before_the_source_scope() {
        let engine = scope_engine();
        let f = scoped(&engine, ipv6_accept());
        let foreign = addr("fd00::99");
        assert_eq!(
            outbound(&f, A, tcp_packet(foreign, 5000, peer_addr(A), 22)),
            Verdict::Accept
        );
        // IPv4 is still checked.
        assert_eq!(
            outbound(
                &f,
                PEER,
                tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 80)
            ),
            drop(reasons::OUTBOUND_SOURCE)
        );
        let stats = f.stats();
        assert_eq!((stats.ipv6_accepted, stats.outbound_source), (1, 1));
    }

    // ── other-protocol scope rules ────────────────────────────────────────

    /// The local addresses `LOCAL4/32` and `LOCAL/128`.
    fn own_addresses() -> [IpNet; 2] {
        [
            format!("{LOCAL4}/32").parse().unwrap(),
            format!("{LOCAL}/128").parse().unwrap(),
        ]
    }

    /// A filter of `engine` accepting `protocol` to [`own_addresses`].
    fn other_scoped(
        engine: &Arc<AclEngine>,
        config: AclFilterConfig,
        protocol: OtherProtocol,
    ) -> AclFilter {
        let rule = OtherProtocolRule::new(protocol, own_addresses());
        let scope = AclFilterScope::new().with_other_protocol(rule);
        AclFilter::with_scope(Arc::clone(engine), ns_identity(), config, scope)
    }

    fn icmp_message(icmp_type: u8) -> Vec<u8> {
        vec![icmp_type, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn default_scope_has_no_other_protocol_rules() {
        assert_eq!(AclFilterScope::default().other_protocols, Vec::new());
        let f = AclFilter::with_scope(
            scope_engine(),
            ns_identity(),
            AclFilterConfig::default(),
            AclFilterScope::default(),
        );
        let ping = ip(
            peer_addr(A),
            addr(LOCAL),
            protocol::ICMPV6,
            &icmp_echo(128, 1),
        );
        assert_eq!(inbound(&f, A, ping), drop(reasons::PROTOCOL));
        assert_eq!(f.stats().protocol, 1);
    }

    #[test]
    fn icmp_echo_rule_accepts_echo_to_own_addresses_only() {
        let engine = scope_engine();
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
        let (a, local, local4) = (peer_addr(A), addr(LOCAL), addr(LOCAL4));
        let r4 = addr("10.0.0.1");

        // The ns evidence (`acl_passes_icmpv6_echo_to_n6_self`), flipped: an echo to
        // N6(self) passes, an echo to another peer's address is dropped.
        let ping = |dst| ip(a, dst, protocol::ICMPV6, &icmp_echo(128, 1));
        assert_eq!(inbound(&f, A, ping(local)), Verdict::Accept);
        assert_eq!(inbound(&f, A, ping(peer_addr(C))), drop(reasons::PROTOCOL));
        let ping4 = |dst| ip(r4, dst, protocol::ICMP, &icmp_echo(8, 1));
        assert_eq!(inbound(&f, PEER, ping4(local4)), Verdict::Accept);
        assert_eq!(
            inbound(&f, PEER, ping4(addr("10.0.0.9"))),
            drop(reasons::PROTOCOL)
        );

        // Other ICMP messages to an own address are not echo requests.
        let timestamp = || ip(r4, local4, protocol::ICMP, &icmp_message(13));
        let unreachable = || ip(a, local, protocol::ICMPV6, &icmp_message(1));
        assert_eq!(inbound(&f, PEER, timestamp()), drop(reasons::PROTOCOL));
        assert_eq!(inbound(&f, A, unreachable()), drop(reasons::PROTOCOL));
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.protocol), (2, 4));

        // Every ICMP message under `Icmp`, still to own addresses only.
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Icmp);
        assert_eq!(inbound(&f, PEER, timestamp()), Verdict::Accept);
        assert_eq!(inbound(&f, A, unreachable()), Verdict::Accept);
        assert_eq!(inbound(&f, A, ping(local)), Verdict::Accept);
        assert_eq!(inbound(&f, A, ping(peer_addr(C))), drop(reasons::PROTOCOL));
        // Neither TCP nor UDP is affected.
        assert_eq!(
            inbound(&f, PEER, udp_packet(r4, 4000, local4, 9)),
            drop(reasons::DENIED)
        );
        assert_eq!(f.stats().accepted, 3);

        // No policy loaded: still dropped.
        let f = other_scoped(
            &Arc::new(AclEngine::new()),
            AclFilterConfig::default(),
            OtherProtocol::Icmp,
        );
        assert_eq!(inbound(&f, A, ping(local)), drop(reasons::NO_POLICY));
    }

    #[test]
    fn ip_protocol_rule_matches_the_protocol_number() {
        const GRE: u8 = 47;
        let engine = scope_engine();
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Ip(GRE));
        let (r, local4) = (addr("10.0.0.1"), addr(LOCAL4));
        assert_eq!(
            inbound(&f, PEER, ip(r, local4, GRE, &[0; 4])),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, ip(r, addr("10.0.0.9"), GRE, &[0; 4])),
            drop(reasons::PROTOCOL)
        );
        assert_eq!(
            inbound(&f, PEER, ip(r, local4, protocol::ICMP, &icmp_echo(8, 1))),
            drop(reasons::PROTOCOL)
        );
    }

    #[test]
    fn allow_other_protocols_still_accepts_everything() {
        let engine = scope_engine();
        let config = AclFilterConfig {
            allow_other_protocols: true,
            ..AclFilterConfig::default()
        };
        let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
        let a = peer_addr(A);
        for packet in [
            ip(a, peer_addr(C), protocol::ICMPV6, &icmp_echo(128, 1)),
            ip(a, addr(LOCAL), protocol::ICMPV6, &icmp_message(1)),
            ip(a, addr("fd00::99"), 47, &[0; 4]),
        ] {
            assert_eq!(inbound(&f, A, packet), Verdict::Accept);
        }
        assert_eq!(f.stats().accepted, 3);
    }

    #[test]
    fn restricted_peer_echo_is_answered_through_the_reply_table() {
        let engine = scope_engine();
        let (a, local) = (peer_addr(A), addr(LOCAL));
        let request = || ip(a, local, protocol::ICMPV6, &icmp_echo(128, 7));
        let reply = |id| ip(local, a, protocol::ICMPV6, &icmp_echo(129, id));

        // Without a scope rule the restricted peer's reply is denied as today.
        let unscoped = ns_filter(&engine, AclFilterConfig::default());
        assert_eq!(outbound(&unscoped, A, reply(7)), drop(reasons::OUTBOUND));

        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
        // An unsolicited reply is denied.
        assert_eq!(outbound(&f, A, reply(7)), drop(reasons::OUTBOUND));
        assert_eq!(inbound(&f, A, request()), Verdict::Accept);
        assert_eq!(outbound(&f, A, reply(7)), Verdict::Accept);
        // A reply with another identifier, or another message, is not.
        assert_eq!(outbound(&f, A, reply(8)), drop(reasons::OUTBOUND));
        assert_eq!(
            outbound(&f, A, ip(local, a, protocol::ICMPV6, &icmp_echo(128, 7))),
            drop(reasons::OUTBOUND)
        );
        let stats = f.stats();
        assert_eq!((stats.outbound_replies, stats.outbound_denied), (1, 3));

        // Another protocol from the restricted peer is answered the same way.
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::Ip(47));
        assert_eq!(inbound(&f, A, ip(a, local, 47, &[0; 4])), Verdict::Accept);
        assert_eq!(outbound(&f, A, ip(local, a, 47, &[0; 4])), Verdict::Accept);
        assert_eq!(f.stats().outbound_replies, 1);

        // An unversioned identity resolves the peer on each packet.
        let identities = ns_identity();
        let identity = move |peer: PeerId| identities.labels(peer);
        let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, own_addresses());
        let f = AclFilter::with_scope(
            Arc::clone(&engine),
            identity,
            AclFilterConfig::default(),
            AclFilterScope::new().with_other_protocol(rule),
        );
        assert_eq!(inbound(&f, A, request()), Verdict::Accept);
        assert_eq!(outbound(&f, A, reply(7)), Verdict::Accept);

        // No allowance without stateful replies.
        let config = AclFilterConfig {
            stateful_replies: false,
            ..AclFilterConfig::default()
        };
        let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
        assert_eq!(inbound(&f, A, request()), Verdict::Accept);
        assert_eq!(outbound(&f, A, reply(7)), drop(reasons::OUTBOUND));
        assert_eq!(f.inner.table().entries.len(), 0);

        // An unrestricted peer records no outbound allowance.
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
        let ping = ip(
            addr("10.0.0.1"),
            addr(LOCAL4),
            protocol::ICMP,
            &icmp_echo(8, 1),
        );
        assert_eq!(inbound(&f, PEER, ping), Verdict::Accept);
        assert_eq!(f.inner.table().entries.len(), 0);
    }

    #[test]
    fn own_pings_are_answered_with_a_scope_rule() {
        let engine = scope_engine();
        let (r, local4) = (addr("10.0.0.1"), addr(LOCAL4));
        let (r6, local) = (addr("fd00::6"), addr(LOCAL));
        let request = || ip(local4, r, protocol::ICMP, &icmp_echo(8, 9));
        let reply = || ip(r, local4, protocol::ICMP, &icmp_echo(0, 9));
        let request6 = || ip(local, r6, protocol::ICMPV6, &icmp_echo(128, 9));
        let reply6 = || ip(r6, local, protocol::ICMPV6, &icmp_echo(129, 9));

        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
        assert_eq!(outbound(&f, PEER, request()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
        // IPv6, to an unrestricted key peer.
        let map = ns_identity();
        let peer6 = PeerId::new(6);
        map.insert(peer6, label_set(&["k6"]));
        let rule = OtherProtocolRule::new(OtherProtocol::IcmpEcho, own_addresses());
        let f6 = AclFilter::with_scope(
            Arc::clone(&engine),
            map,
            AclFilterConfig::default(),
            AclFilterScope::new().with_other_protocol(rule),
        );
        assert_eq!(outbound(&f6, peer6, request6()), Verdict::Accept);
        assert_eq!(inbound(&f6, peer6, reply6()), Verdict::Accept);
        assert_eq!((f.stats().replies, f6.stats().replies), (1, 1));

        // Without stateful replies the reply is judged as new traffic.
        let config = AclFilterConfig {
            stateful_replies: false,
            ..AclFilterConfig::default()
        };
        let f = other_scoped(&engine, config, OtherProtocol::IcmpEcho);
        assert_eq!(outbound(&f, PEER, request()), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::PROTOCOL));
    }

    #[test]
    fn fragments_of_an_accepted_icmp_packet_follow_the_first_fragment() {
        let engine = scope_engine();
        let f = other_scoped(&engine, AclFilterConfig::default(), OtherProtocol::IcmpEcho);
        let r = addr("10.0.0.1");
        let frag = |dst, offset_units, more, transport: &[u8]| {
            ip_frag(
                r,
                dst,
                protocol::ICMP,
                transport,
                Some(Frag {
                    id: 3,
                    offset_units,
                    more,
                }),
            )
        };
        let (own, other) = (addr(LOCAL4), addr("10.0.0.9"));
        assert_eq!(
            inbound(&f, PEER, frag(own, 0, true, &icmp_echo(8, 1))),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, frag(own, 1, false, &[0; 8])),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, PEER, frag(other, 0, true, &icmp_echo(8, 1))),
            drop(reasons::PROTOCOL)
        );
        assert_eq!(
            inbound(&f, PEER, frag(other, 1, false, &[0; 8])),
            drop(reasons::PROTOCOL)
        );
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.protocol), (2, 2));
    }

    // ── Policy states and typed rules ──

    #[test]
    fn policy_states_decide_sources_in_no_namespace() {
        let engine = Arc::new(AclEngine::new());
        let f = AclFilter::new(Arc::clone(&engine), identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let new_flow = |port| tcp_packet(r, 4000, l, port);
        assert_eq!(f.stats().policy_state, PolicyState::NotInstalled);

        // Installed and empty: new flows denied, replies still pass.
        engine.install(RuleSet::empty());
        assert_eq!(inbound(&f, PEER, new_flow(80)), drop(reasons::DENIED));
        assert_eq!(
            outbound(&f, PEER, tcp_packet(l, 40000, r, 22)),
            Verdict::Accept
        );
        let reply = || tcp_packet(r, 22, l, 40000);
        assert_eq!(inbound(&f, PEER, reply()), Verdict::Accept);
        assert_eq!(f.stats().policy_state, PolicyState::Installed { rules: 0 });

        // Failed with nothing else loaded: everything dropped, replies too.
        engine.fail();
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::POLICY_FAILED));
        assert_eq!(
            inbound(&f, PEER, new_flow(80)),
            drop(reasons::POLICY_FAILED)
        );
        let ping = ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
        assert_eq!(inbound(&f, PEER, ping), drop(reasons::POLICY_FAILED));
        assert_eq!(f.stats().policy_state, PolicyState::Failed);

        // Not installed, deny: as before any policy was loaded.
        engine.uninstall();
        assert_eq!(inbound(&f, PEER, reply()), drop(reasons::NO_POLICY));
        let stats = f.stats();
        assert_eq!(
            (
                stats.denied,
                stats.replies,
                stats.policy_failed,
                stats.no_policy
            ),
            (1, 1, 3, 1)
        );
    }

    #[test]
    fn not_installed_accept_lets_every_known_peer_in() {
        let engine = Arc::new(AclEngine::new().with_not_installed(NotInstalled::Accept));
        let f = AclFilter::new(Arc::clone(&engine), identity());
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        for packet in [
            tcp_packet(r, 4000, l, 80),
            udp_packet(r, 4000, l, 9),
            ip(r, l, protocol::ICMP, &icmp_echo(8, 1)),
            ip(r, l, 47, &[0; 8]),
        ] {
            assert_eq!(inbound(&f, PEER, packet), Verdict::Accept);
        }
        // An unknown peer is still unknown; the protocol step reports it.
        let unknown = PeerId::new(99);
        assert_eq!(
            inbound(&f, unknown, tcp_packet(r, 4000, l, 80)),
            drop(reasons::UNKNOWN_PEER)
        );
        assert_eq!(
            inbound(&f, unknown, ip(r, l, 47, &[0; 8])),
            drop(reasons::PROTOCOL)
        );
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.bypassed), (4, 0));
        // Namespace members are governed by their namespaces.
        engine
            .store_namespace(
                "nsd:a",
                NamespacePolicy {
                    members: vec![NamespaceMember {
                        label: "peer-1".into(),
                        addresses: Vec::new(),
                    }],
                    ..NamespacePolicy::default()
                },
            )
            .unwrap();
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4001, l, 80)),
            drop(reasons::DENIED)
        );
        assert_eq!(
            inbound(&f, OTHER_PEER, tcp_packet(addr("10.0.0.9"), 4000, l, 80)),
            Verdict::Accept
        );
    }

    fn typed_rules(rules: impl IntoIterator<Item = crate::Rule>) -> Arc<AclEngine> {
        let engine = Arc::new(AclEngine::new());
        engine.install(RuleSet::new(rules).unwrap());
        engine
    }

    #[test]
    fn other_protocols_reach_the_rules() {
        use crate::{IcmpTypes, ProtocolMatch, Rule};
        let engine = typed_rules([
            Rule::new(
                "ping",
                vec![ProtocolMatch::Icmp(IcmpTypes::Only(vec![8, 128]))],
            )
            .with_destinations(["10.0.0.2/32".parse().unwrap(), "fd00::/64".parse().unwrap()]),
            Rule::new("gre", vec![ProtocolMatch::Ip(47)]).with_labels(["peer-1".into()]),
        ]);
        let f = AclFilter::new(Arc::clone(&engine), identity());
        let (r, l, other) = (addr("10.0.0.1"), addr("10.0.0.2"), addr("10.0.0.3"));
        let icmp = |dst, icmp_type| ip(r, dst, protocol::ICMP, &icmp_echo(icmp_type, 1));
        assert_eq!(inbound(&f, PEER, icmp(l, 8)), Verdict::Accept);
        // Another type, another destination.
        assert_eq!(inbound(&f, PEER, icmp(l, 13)), drop(reasons::PROTOCOL));
        assert_eq!(inbound(&f, PEER, icmp(other, 8)), drop(reasons::PROTOCOL));
        // ICMPv6 by its own type numbers.
        let (r6, l6) = (addr("fd00::1"), addr("fd00::2"));
        let ping6 = ip(r6, l6, protocol::ICMPV6, &icmp_echo(128, 1));
        assert_eq!(inbound(&f, KEY_PEER, ping6), Verdict::Accept);
        // A labelled rule: only the labelled peer.
        let gre = |src| ip(src, l, 47, &[0; 8]);
        assert_eq!(inbound(&f, PEER, gre(r)), Verdict::Accept);
        assert_eq!(
            inbound(&f, OTHER_PEER, gre(addr("10.0.0.9"))),
            drop(reasons::PROTOCOL)
        );
        assert_eq!(inbound(&f, KEY_PEER, gre(r)), drop(reasons::PROTOCOL));
        assert_eq!(
            inbound(&f, PeerId::new(99), gre(r)),
            drop(reasons::PROTOCOL)
        );
        // A non-first fragment follows its first fragment.
        let first = ip_frag(
            r,
            l,
            47,
            &[0; 16],
            Some(Frag {
                id: 3,
                offset_units: 0,
                more: true,
            }),
        );
        let later = ip_frag(
            r,
            l,
            47,
            &[0; 8],
            Some(Frag {
                id: 3,
                offset_units: 2,
                more: false,
            }),
        );
        assert_eq!(inbound(&f, PEER, first), Verdict::Accept);
        assert_eq!(inbound(&f, PEER, later), Verdict::Accept);
        let stats = f.stats();
        assert_eq!((stats.accepted, stats.protocol, stats.denied), (5, 5, 0));

        // TCP and UDP are unaffected by such rules.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn other_protocol_steps_come_first() {
        use crate::{ProtocolMatch, Rule};
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        let ping = || ip(r, l, protocol::ICMP, &icmp_echo(8, 1));
        // Without a matching rule a scope rule or `allow_other_protocols`
        // still accepts.
        let engine = typed_rules([Rule::new("gre", vec![ProtocolMatch::Ip(47)])]);
        let scope = AclFilterScope::new().with_other_protocol(OtherProtocolRule::new(
            OtherProtocol::IcmpEcho,
            ["10.0.0.0/24".parse().unwrap()],
        ));
        let f = AclFilter::with_scope(
            Arc::clone(&engine),
            identity(),
            AclFilterConfig::default(),
            scope,
        );
        assert_eq!(inbound(&f, PEER, ping()), Verdict::Accept);
        let open = AclFilter::with_config(
            Arc::clone(&engine),
            identity(),
            AclFilterConfig {
                allow_other_protocols: true,
                ..AclFilterConfig::default()
            },
        );
        assert_eq!(inbound(&open, PEER, ping()), Verdict::Accept);
        // A rule set without ICMP entries leaves ICMP dropped.
        let plain = AclFilter::new(engine, identity());
        assert_eq!(inbound(&plain, PEER, ping()), drop(reasons::PROTOCOL));
    }

    #[test]
    fn a_rule_with_labels_and_prefixes_needs_both() {
        use crate::{PortSet, ProtocolMatch, Rule};
        let engine = typed_rules([Rule::new("both", vec![ProtocolMatch::Tcp(PortSet::Any)])
            .with_labels([key_label()])
            .with_sources(["fd00::/64".parse().unwrap()])]);
        let f = AclFilter::new(engine, identity());
        let l = addr("fd00::2");
        assert_eq!(
            inbound(&f, KEY_PEER, tcp_packet(addr("fd00::7"), 4000, l, 80)),
            Verdict::Accept
        );
        // The labelled peer outside the prefix, another peer inside it.
        assert_eq!(
            inbound(&f, KEY_PEER, tcp_packet(addr("fd01::7"), 4000, l, 80)),
            drop(reasons::DENIED)
        );
        let map = identity();
        map.insert(PeerId::new(8), label_set(&["other"]));
        let f = AclFilter::new(
            typed_rules([Rule::new("any", vec![ProtocolMatch::Any])
                .with_sources(["fd00::/64".parse().unwrap()])]),
            map,
        );
        assert_eq!(
            inbound(&f, PeerId::new(8), tcp_packet(addr("fd00::7"), 4000, l, 80)),
            Verdict::Accept
        );
    }
}
