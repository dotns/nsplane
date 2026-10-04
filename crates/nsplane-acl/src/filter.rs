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

use crate::engine::{
    AccessRequest, AclEngine, MemberVerdict, PinholeMatch, ReplyDependency, Snapshot,
    SourceAssertion,
};
use crate::lru::{FlowHash, LruMap};
use crate::net::Protocol;
use crate::pinhole::Direction;
use crate::reasons;

// ── Peer identity ─────────────────────────────────────────────────────────────

/// Resolves the [`SourceAssertion`] (the ACL principal) of a peer.
///
/// Implemented by closures `Fn(PeerId) -> Option<SourceAssertion>`, by
/// [`PeerIdentityMap`] and by `Arc<T>` of any implementation, so a caller can
/// keep a handle to update the identities while the filter uses them.
pub trait PeerIdentity: Send + Sync + 'static {
    /// The source assertion of `peer`, or `None` when the peer is unknown or
    /// has no principal independent of the packet's address (see
    /// [`by_source`](Self::by_source)).
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion>;

    /// The source assertion of `peer` for a packet whose remote address is
    /// `src`: the IP source of an inbound packet, the IP destination of an
    /// outbound one. [`AclFilter`] resolves every principal through this
    /// method.
    ///
    /// The default ignores `src` and returns [`assertion`](Self::assertion).
    fn assertion_for(&self, peer: PeerId, src: IpAddr) -> Option<SourceAssertion> {
        let _ = src;
        self.assertion(peer)
    }

    /// Whether the [`assertion_for`](Self::assertion_for) of `peer` depends
    /// on the address. [`AclFilter`] asks once per peer and identity
    /// generation, then caches the principal of such a peer per address, and
    /// of any other peer per peer; so a versioned implementation must return
    /// `true` for every peer whose assertion depends on the address. Default
    /// `false`.
    fn by_source(&self, peer: PeerId) -> bool {
        let _ = peer;
        false
    }

    /// The identity generation: a non-zero value that changes whenever an
    /// assertion may have changed (bumped once the change is visible to
    /// [`assertion_for`](Self::assertion_for) and
    /// [`by_source`](Self::by_source)). [`AclFilter`] caches the resolved
    /// peers and the flow verdicts under it.
    ///
    /// The default, 0, means "not versioned": the filter then resolves the
    /// peer and evaluates the policy on every packet (no principal cache, no
    /// flow verdict cache, no bypass), so correctness never depends on it.
    /// Closures keep the default; [`PeerIdentityMap`] is versioned.
    fn generation(&self) -> u64 {
        0
    }
}

impl<F> PeerIdentity for F
where
    F: Fn(PeerId) -> Option<SourceAssertion> + Send + Sync + 'static,
{
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion> {
        self(peer)
    }
}

impl<T: PeerIdentity + ?Sized> PeerIdentity for Arc<T> {
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion> {
        (**self).assertion(peer)
    }

    fn assertion_for(&self, peer: PeerId, src: IpAddr) -> Option<SourceAssertion> {
        (**self).assertion_for(peer, src)
    }

    fn by_source(&self, peer: PeerId) -> bool {
        (**self).by_source(peer)
    }

    fn generation(&self) -> u64 {
        (**self).generation()
    }
}

/// A concurrent map from peers to their source assertions.
///
/// Wrap it in an `Arc` and hand a clone to the filter to update it at runtime.
/// Every [`insert`](Self::insert), [`insert_by_source`](Self::insert_by_source)
/// and [`remove`](Self::remove) bumps its
/// [generation](PeerIdentity::generation), so the filter's cached principals
/// and verdicts never outlive an identity change.
#[derive(Debug)]
pub struct PeerIdentityMap {
    map: RwLock<HashMap<PeerId, Identity>>,
    generation: AtomicU64,
}

/// The identity of a peer in a [`PeerIdentityMap`].
#[derive(Debug)]
enum Identity {
    Assertion(SourceAssertion),
    /// The principal of each packet is its remote address.
    BySource,
}

impl Default for PeerIdentityMap {
    fn default() -> Self {
        Self {
            map: RwLock::default(),
            generation: AtomicU64::new(1),
        }
    }
}

impl PeerIdentityMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the assertion of `peer`, replacing any previous one. A relayed
    /// client is inserted with its [`SourceAssertion::WgPeerKey`].
    pub fn insert(&self, peer: PeerId, assertion: SourceAssertion) {
        self.set(peer, Identity::Assertion(assertion));
    }

    /// Make `peer` terminate by source address, replacing any previous
    /// assertion: the principal of each of its packets is the packet's
    /// remote address (see [`PeerIdentity::assertion_for`]), a
    /// [`SourceAssertion::Terminate`] binding of that address as
    /// [`AccessRequest::from_ip`] builds it. For a gateway whose packets
    /// carry several source addresses. [`assertion`](PeerIdentity::assertion)
    /// of such a peer is `None`.
    pub fn insert_by_source(&self, peer: PeerId) {
        self.set(peer, Identity::BySource);
    }

    fn set(&self, peer: PeerId, identity: Identity) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        map.insert(peer, identity);
        // Still under the write lock: a reader seeing the new generation
        // also sees the new assertion.
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn read(&self) -> RwLockReadGuard<'_, HashMap<PeerId, Identity>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remove the assertion (or the by-source mark) of `peer`; the peer
    /// becomes unknown.
    pub fn remove(&self, peer: PeerId) {
        let mut map = self.map.write().unwrap_or_else(PoisonError::into_inner);
        map.remove(&peer);
        self.generation.fetch_add(1, Ordering::Release);
    }
}

impl PeerIdentity for PeerIdentityMap {
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion> {
        match self.read().get(&peer)? {
            Identity::Assertion(assertion) => Some(assertion.clone()),
            Identity::BySource => None,
        }
    }

    fn assertion_for(&self, peer: PeerId, src: IpAddr) -> Option<SourceAssertion> {
        match self.read().get(&peer)? {
            Identity::Assertion(assertion) => Some(assertion.clone()),
            Identity::BySource => Some(SourceAssertion::from_ip(src)),
        }
    }

    fn by_source(&self, peer: PeerId) -> bool {
        matches!(self.read().get(&peer), Some(Identity::BySource))
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
        }
    }
}

impl AclFilterConfig {
    /// The settings of the ACL step of an ns account: for inbound IPv4
    /// packets the filter equals ns `is_local_node_packet(pkt, local) ||
    /// is_icmp_echo_reply(pkt) || acl_check_packet(..)` (the first term only
    /// when `local` is set), with the principals of a [`PeerIdentityMap`]
    /// holding the relay clients under [`insert`](PeerIdentityMap::insert)
    /// with their [`SourceAssertion::WgPeerKey`] and every other peer under
    /// [`insert_by_source`](PeerIdentityMap::insert_by_source).
    ///
    /// That is: no reply allowances ([`stateful_replies`](Self::stateful_replies)
    /// off), protocols other than TCP and UDP dropped, IPv4 fragments gated by
    /// [`FragmentMode::ALLOW_ONLY`], `local` in
    /// [`accept_to_local`](Self::accept_to_local) and
    /// [`accept_icmp_echo_reply`](Self::accept_icmp_echo_reply) on. Drop
    /// reasons follow this filter (a packet ns drops is dropped here, possibly
    /// with another reason), and IPv6 and outbound packets keep this filter's
    /// handling.
    pub fn crates_acl(local: Option<Ipv4Addr>) -> Self {
        Self {
            allow_other_protocols: false,
            stateful_replies: false,
            fragments: FragmentMode::ALLOW_ONLY,
            accept_to_local: local,
            accept_icmp_echo_reply: true,
            ..Self::default()
        }
    }
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
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    replies: AtomicU64,
    denied: AtomicU64,
    no_policy: AtomicU64,
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
    Denied,
    CrossNamespace,
    NoPolicy,
    UnknownPeer,
    Protocol,
    Fragment,
    Malformed,
    /// An outbound packet accepted as today or by an outbound rule (not counted).
    OutboundAccepted,
    OutboundReply,
    OutboundDenied,
}

impl Outcome {
    const fn verdict(self) -> Verdict {
        let reason = match self {
            Self::Accepted
            | Self::Reply
            | Self::Bypassed
            | Self::OutboundAccepted
            | Self::OutboundReply => {
                return Verdict::Accept;
            }
            Self::Denied => reasons::DENIED,
            Self::CrossNamespace => reasons::CROSS_NAMESPACE,
            Self::NoPolicy => reasons::NO_POLICY,
            Self::UnknownPeer => reasons::UNKNOWN_PEER,
            Self::Protocol => reasons::PROTOCOL,
            Self::Fragment => reasons::FRAGMENT,
            Self::Malformed => reasons::MALFORMED,
            Self::OutboundDenied => reasons::OUTBOUND,
        };
        Verdict::Drop { reason }
    }

    fn count(self, counters: &Counters) {
        bump(match self {
            Self::Accepted => &counters.accepted,
            Self::Reply => &counters.replies,
            Self::Bypassed => &counters.bypassed,
            Self::Denied => &counters.denied,
            Self::CrossNamespace => &counters.cross_namespace,
            Self::NoPolicy => &counters.no_policy,
            Self::UnknownPeer => &counters.unknown_peer,
            Self::Protocol => &counters.protocol,
            Self::Fragment => &counters.fragment,
            Self::Malformed => &counters.malformed,
            Self::OutboundAccepted => return,
            Self::OutboundReply => &counters.outbound_replies,
            Self::OutboundDenied => &counters.outbound_denied,
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
/// peer whose principal depends on the packet's address
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
    /// A marker: the peer's principal depends on the packet's address and is
    /// resolved per address. Its other fields are those of an unknown peer.
    by_source: bool,
    /// `None` for an unknown peer.
    source: Option<SourceAssertion>,
    /// The source anchor of `source`.
    principal: Option<Arc<str>>,
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
        Self::new(
            identity.assertion_for(peer, src),
            snapshot,
            generation,
            false,
        )
    }

    fn new(
        source: Option<SourceAssertion>,
        snapshot: &Snapshot,
        generation: u64,
        by_source: bool,
    ) -> Self {
        let principal: Option<Arc<str>> = source.as_ref().map(|s| s.source_anchor().into());
        let principal_str = principal.as_deref();
        let membership = principal_str.and_then(|principal| snapshot.membership(principal));
        Self {
            generation: snapshot.generation(),
            identity: generation,
            by_source,
            governed: match membership {
                None => Governed::Default,
                Some(membership) if membership.outbound_restricted() => Governed::Restricted,
                Some(_) => Governed::Member,
            },
            pinholes: principal_str.is_some_and(|principal| snapshot.has_pinholes_of(principal)),
            bypass: source.is_some() && snapshot.bypasses(principal_str),
            source,
            principal,
        }
    }
}

// ── AclFilter ─────────────────────────────────────────────────────────────────

/// A [`PacketFilter`] enforcing an [`AclEngine`] policy on inbound packets.
///
/// Inbound packets from a peer are evaluated as an [`AccessRequest`] whose
/// principal comes from a [`PeerIdentity`]; anything the policy does not
/// accept is dropped with a [`reasons`] constant. With no policy loaded every
/// inbound packet is dropped (fail-closed). Outbound packets are accepted,
/// except to outbound-restricted peers (see the crate docs on namespaces).
///
/// **Stateful replies, not a conntrack/NAT**: with
/// [`AclFilterConfig::stateful_replies`] on, an outbound TCP or UDP packet to a
/// peer records an allowance for the reversed tuple from that same peer, so its
/// replies pass even when the policy would not accept them as new inbound
/// traffic. Allowances expire after [`AclFilterConfig::reply_idle_timeout`]
/// without traffic.
///
/// **Per-flow hook**: with a versioned identity
/// ([`PeerIdentity::generation`] non-zero, e.g. a [`PeerIdentityMap`]), the
/// filter caches each peer's resolved principal and the verdict of each TCP or
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
        Self::build(engine, Box::new(identity), config, true)
    }

    /// A filter that never caches peers or verdicts: the reference the
    /// differential tests compare the cached filter with.
    #[cfg(test)]
    pub(crate) fn uncached(
        engine: Arc<AclEngine>,
        identity: impl PeerIdentity,
        config: AclFilterConfig,
    ) -> Self {
        Self::build(engine, Box::new(identity), config, false)
    }

    fn build(
        engine: Arc<AclEngine>,
        identity: Box<dyn PeerIdentity>,
        config: AclFilterConfig,
        cache: bool,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                engine,
                identity,
                config,
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

    fn inbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
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
            return Outcome::NoPolicy;
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
                let info = self.cached_peer(&mut table, snapshot, peer, Some(tuple.src), identity);
                if info.bypass {
                    drop(table);
                    self.sweep_if(sweep);
                    return Outcome::Accepted;
                }
                if info.governed == Governed::Default {
                    // The default policy: a few rules and no side effects,
                    // cheaper to evaluate under this lock than to cache.
                    let (verdict, _) =
                        self.evaluate_new(snapshot, info.source.clone(), None, tuple, protocol);
                    drop(table);
                    self.sweep_if(sweep);
                    return verdict.outcome;
                }
                Some(Arc::clone(info))
            }
        };
        drop(table);
        self.sweep_if(sweep);
        let (verdict, cacheable) = info.map_or_else(
            || {
                let source = self.identity.assertion_for(peer, tuple.src);
                let principal = source
                    .as_ref()
                    .filter(|_| snapshot.has_members())
                    .map(SourceAssertion::source_anchor);
                self.evaluate_new(snapshot, source, principal.as_deref(), tuple, protocol)
            },
            |info| {
                let principal = info.principal.as_deref();
                self.evaluate_new(snapshot, info.source.clone(), principal, tuple, protocol)
            },
        );
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
            Outcome::Accepted
        } else {
            Outcome::Protocol
        }
    }

    /// Evaluate a new inbound TCP or UDP flow from `source`, whose principal
    /// is `principal` (`None` when there are no namespace members). Returns
    /// the verdict and whether it may be cached.
    fn evaluate_new(
        &self,
        snapshot: &Snapshot,
        source: Option<SourceAssertion>,
        principal: Option<&str>,
        tuple: FiveTuple,
        protocol: Protocol,
    ) -> (FlowVerdict, bool) {
        let Some(source) = source else {
            return (FlowVerdict::new(Outcome::UnknownPeer), true);
        };
        let request = AccessRequest {
            src_ip: tuple.src,
            source,
            dst_ip: tuple.dst,
            dst_port: tuple.dst_port,
            protocol,
        };
        let member =
            principal.and_then(|principal| Some((principal, snapshot.membership(principal)?)));
        let Some((principal, membership)) = member else {
            // A principal in no namespace: the default policy.
            let outcome = match snapshot.default_policy() {
                None => Outcome::NoPolicy,
                Some(policy) if policy.matched_rule(&request).is_some() => Outcome::Accepted,
                Some(_) => Outcome::Denied,
            };
            return (FlowVerdict::new(outcome), true);
        };
        let verdict =
            snapshot.evaluate_member(&request, principal, membership, || self.engine.now());
        let dependency = match verdict {
            MemberVerdict::Rule { .. } => None,
            MemberVerdict::Grant(id) => Some(ReplyDependency::Grant(id)),
            MemberVerdict::Pinhole(id) => Some(ReplyDependency::Pinhole(id)),
            MemberVerdict::PinholeExpired => {
                self.engine.expire_pinholes();
                return (FlowVerdict::new(Outcome::Denied), false);
            }
            MemberVerdict::Denied => return (FlowVerdict::new(Outcome::Denied), true),
            MemberVerdict::CrossNamespace => {
                return (FlowVerdict::new(Outcome::CrossNamespace), true);
            }
        };
        let verdict = FlowVerdict {
            outcome: Outcome::Accepted,
            dependency,
            restricted: membership.outbound_restricted(),
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
    /// address it is unknown.
    fn cached_peer<'t>(
        &self,
        table: &'t mut FlowTable,
        snapshot: &Snapshot,
        peer: PeerId,
        src: Option<IpAddr>,
        identity: u64,
    ) -> &'t Arc<PeerInfo> {
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
                None => PeerInfo::new(self.identity.assertion(peer), snapshot, identity, false),
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
            _ => info,
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
    ) -> &'t Arc<PeerInfo> {
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
        sources
            .get(&key)
            .unwrap_or_else(|| unreachable!("the entry was just touched or inserted"))
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
        let snapshot = self.engine.snapshot();
        let identity = self.identity_generation();
        let parsed = IpPacket::parse(bytes);
        // The remote address; a by-source peer is unknown without it.
        let dst = parsed.as_ref().ok().map(IpPacket::dst);
        let mut table = self.table();
        // `None`: an unrestricted peer without pinholes.
        let info = if identity != 0 {
            let info = self.cached_peer(&mut table, &snapshot, peer, dst, identity);
            (info.governed == Governed::Restricted || info.pinholes).then(|| Arc::clone(info))
        } else if snapshot.has_outbound_restrictions() || snapshot.has_pinholes() {
            let source = dst.map_or_else(
                || self.identity.assertion(peer),
                |dst| self.identity.assertion_for(peer, dst),
            );
            Some(Arc::new(PeerInfo::new(source, &snapshot, 0, false)))
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
        let principal = info.as_ref().and_then(|info| info.principal.as_deref());
        let Some(principal) = principal.filter(|_| restricted) else {
            if let Some(tuple) = packet.five_tuple() {
                // Accepted anyway; an outbound pinhole still owns the replies.
                let mut sweep = false;
                let dependency = principal.and_then(|principal| {
                    self.outbound_pinhole(&snapshot, principal, &tuple, &mut sweep)
                });
                self.track_outbound(&mut table, peer, tuple, &packet, dependency);
                drop(table);
                self.sweep_if(sweep);
            }
            return Outcome::OutboundAccepted;
        };
        if packet.fragment().is_none() {
            return self.evaluate_outbound(&snapshot, peer, principal, identity, &packet, table);
        }
        drop(table);
        self.with_fragments(peer, true, &packet, Outcome::OutboundDenied, |packet| {
            self.evaluate_outbound(&snapshot, peer, principal, identity, packet, self.table())
        })
    }

    /// The open outbound pinhole of `principal` for `tuple`, as a reply
    /// dependency. Sets `sweep` when only expired pinholes match.
    fn outbound_pinhole(
        &self,
        snapshot: &Snapshot,
        principal: &str,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> Option<ReplyDependency> {
        let protocol = Protocol::from_ip_number(tuple.protocol)?;
        match snapshot.match_pinhole(
            principal,
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

    /// Evaluate an outbound packet to an outbound-restricted peer, holding
    /// the flow table.
    fn evaluate_outbound(
        &self,
        snapshot: &Snapshot,
        peer: PeerId,
        principal: &str,
        identity: u64,
        packet: &IpPacket<'_>,
        mut table: MutexGuard<'_, FlowTable>,
    ) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::OutboundDenied;
        };
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            if !self.config.allow_other_protocols {
                return Outcome::OutboundDenied;
            }
            self.track_outbound(&mut table, peer, tuple, packet, None);
            return Outcome::OutboundAccepted;
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
                    self.evaluate_new_outbound(snapshot, principal, protocol, &tuple, &mut sweep);
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

    /// Evaluate a new outbound TCP or UDP flow to the outbound-restricted
    /// `principal`. Returns the verdict and whether it may be cached.
    fn evaluate_new_outbound(
        &self,
        snapshot: &Snapshot,
        principal: &str,
        protocol: Protocol,
        tuple: &FiveTuple,
        sweep: &mut bool,
    ) -> (FlowVerdict, bool) {
        let rule = snapshot.membership(principal).is_some_and(|membership| {
            snapshot.outbound_rule_accepts(membership, protocol, tuple.dst_port)
        });
        if rule {
            return (FlowVerdict::new(Outcome::OutboundAccepted), true);
        }
        let mut expired = false;
        let dependency = self.outbound_pinhole(snapshot, principal, tuple, &mut expired);
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
                self.config.allow_other_protocols && echo_type(packet) == Some(EchoType::Request)
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
    use crate::engine::{TerminateBinding, wg_peer_anchor};
    use crate::namespace::{Grant, GrantEnd, NamespaceMember, NamespacePolicy, OutboundRule};
    use crate::policy::{AclAction, AclPolicy, AclRule};
    use crate::test_packets::{Frag, icmp_echo, ip, ip_frag, tcp, tcp_packet, udp_packet};

    const PEER: PeerId = PeerId::new(1);
    const OTHER_PEER: PeerId = PeerId::new(2);
    const KEY_PEER: PeerId = PeerId::new(3);
    const KEY: [u8; 32] = [7; 32];

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
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

    /// Remote `10.0.0.1` (or `fd00::1`) may reach local TCP 80 (or 443); the key
    /// principal may reach UDP 53.
    fn test_policy() -> AclPolicy {
        policy(vec![
            rule("10.0.0.1/32", "10.0.0.2:80", "tcp"),
            rule("fd00::1/128", "fd00::2:443", "tcp"),
            rule(&wg_peer_anchor(&KEY), "*:53", "udp"),
        ])
    }

    fn identity() -> Arc<PeerIdentityMap> {
        let map = Arc::new(PeerIdentityMap::new());
        for (peer, ip) in [(PEER, "10.0.0.1"), (OTHER_PEER, "10.0.0.9")] {
            map.insert(
                peer,
                SourceAssertion::Terminate {
                    binding: TerminateBinding {
                        ip: Some(addr(ip)),
                        anchor: ip.to_owned(),
                    },
                },
            );
        }
        map.insert(KEY_PEER, SourceAssertion::WgPeerKey { pubkey: KEY });
        map
    }

    fn loaded_engine(policy: AclPolicy) -> Arc<AclEngine> {
        let engine = Arc::new(AclEngine::new());
        engine.load(policy).unwrap();
        engine
    }

    fn filter_with(config: AclFilterConfig) -> AclFilter {
        AclFilter::with_config(loaded_engine(test_policy()), identity(), config)
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
        map.insert(
            peer6,
            SourceAssertion::Terminate {
                binding: TerminateBinding {
                    ip: Some(r),
                    anchor: "v6".to_owned(),
                },
            },
        );
        let f6 = AclFilter::new(loaded_engine(test_policy()), map);
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
        // PEER's binding is the IPv4 address, so the IPv6 CIDR rule never matches it.
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 443)),
            drop(reasons::DENIED)
        );
    }

    #[test]
    fn key_principal_and_cidr_principal() {
        let f = filter();
        let (r, l) = (addr("10.0.0.1"), addr("10.0.0.2"));
        // The key principal matches by key regardless of the packet's source address.
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
        // A key assertion never matches a CIDR rule, even from an allowed address.
        assert_eq!(
            inbound(&f, KEY_PEER, tcp_packet(r, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        // A terminate binding does not match the key rule.
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
    fn closure_identity() {
        let identity =
            |peer: PeerId| (peer == PEER).then_some(SourceAssertion::WgPeerKey { pubkey: KEY });
        let f = AclFilter::new(loaded_engine(test_policy()), identity);
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
        let f = AclFilter::new(loaded_engine(test_policy()), Arc::clone(&map));
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
        engine.load(test_policy()).unwrap();
        assert_eq!(
            inbound(&f, PEER, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        engine.clear();
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

    fn peer_key(peer: PeerId) -> [u8; 32] {
        [u8::try_from(peer.get()).unwrap(); 32]
    }

    fn peer_addr(peer: PeerId) -> IpAddr {
        addr(&format!("fd00::{:x}", peer.get()))
    }

    fn principal(peer: PeerId) -> String {
        wg_peer_anchor(&peer_key(peer))
    }

    fn members(peers: &[PeerId]) -> Vec<NamespaceMember> {
        peers
            .iter()
            .map(|&peer| NamespaceMember {
                principal: principal(peer),
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

    /// Identities: the legacy peers plus `A..=E` by key.
    fn ns_identity() -> Arc<PeerIdentityMap> {
        let map = identity();
        for peer in [A, B, C, D, E] {
            map.insert(
                peer,
                SourceAssertion::WgPeerKey {
                    pubkey: peer_key(peer),
                },
            );
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
                    to: GrantEnd::Peer(principal(B)),
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
            from: GrantEnd::Peer(principal(A)),
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
    fn app_namespace_member_gets_nothing_inbound() {
        let engine = loaded_engine(policy(vec![rule("*", "*:*", "tcp")]));
        engine
            .store_namespace(
                "app:s1",
                NamespacePolicy {
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
        // Its outbound is restricted by the app namespace.
        assert_eq!(
            outbound(&f, E, tcp_packet(local, 22, e, 4000)),
            drop(reasons::OUTBOUND)
        );
    }

    #[test]
    fn principals_in_no_namespace_use_the_default_policy() {
        let engine = loaded_engine(test_policy());
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
        engine.clear();
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
                    from: GrantEnd::Peer(principal(A)),
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

    /// Sessions and kinds: `app:s1` holds `E` (session-only) and `A`; `A` is
    /// also in `quick`, which allows "transfer" pinholes.
    fn pinhole_engine(
        app_outbound: Option<Vec<OutboundRule>>,
    ) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&clock);
        let engine = Arc::new(AclEngine::with_clock(move || *handle.lock().unwrap()));
        let mut quick = namespace(&[A], None);
        quick.allow_app_pinholes.insert("transfer".to_owned());
        engine.store_namespace("quick", quick).unwrap();
        engine
            .store_namespace(
                "app:s1",
                NamespacePolicy {
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
                "app:s1",
                PinholeSpec {
                    peer: principal(peer),
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
        assert!(engine.remove_namespace("app:s1"));
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
        engine.load(test_policy()).unwrap();
        engine
            .store_namespace("nsd:b", namespace(&[B], None))
            .unwrap();
        engine
            .store_grant(
                "a-to-b",
                Grant {
                    from: GrantEnd::Peer(principal(A)),
                    to: GrantEnd::Peer(principal(B)),
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
        assert!(engine.namespaces().is_empty() && engine.grants().is_empty());
        assert!(!guard.is_open());
        for (peer, packet) in [
            (PEER, tcp_packet(remote, 9999, v4_local, 40000)),
            (E, pinholed()),
            (A, granted()),
            (B, tcp_packet(b, 443, a, 4000)),
            (A, tcp_packet(a, 4000, local, 22)),
        ] {
            assert_eq!(inbound(&f, peer, packet), drop(reasons::NO_POLICY));
        }
        assert_eq!(f.stats().no_policy, 5);

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
        engine.load(test_policy()).unwrap();
        assert_eq!(
            inbound(&f, PEER, tcp_packet(remote, 4000, v4_local, 80)),
            Verdict::Accept
        );
    }

    // ── Per-source principals ──

    const GATEWAY: PeerId = PeerId::new(20);

    /// The ns identities plus [`GATEWAY`] terminating by source address.
    fn by_source_identity() -> Arc<PeerIdentityMap> {
        let map = ns_identity();
        map.insert_by_source(GATEWAY);
        map
    }

    /// A namespace whose only member is the source address `member`, with
    /// `acls` and the given outbound rules.
    fn address_namespace(
        member: IpAddr,
        acls: Vec<AclRule>,
        outbound: Option<Vec<OutboundRule>>,
    ) -> NamespacePolicy {
        NamespacePolicy {
            members: vec![NamespaceMember {
                principal: member.to_string(),
                addresses: vec![member.to_string().parse().unwrap()],
            }],
            policy: policy(acls),
            outbound,
            ..NamespacePolicy::default()
        }
    }

    #[test]
    fn by_source_peer_is_judged_by_each_source() {
        let map = by_source_identity();
        let (r, other, l) = (addr("10.0.0.1"), addr("10.0.0.5"), addr("10.0.0.2"));
        // The principal of `AccessRequest::from_ip`, and no address-independent one.
        assert!(map.assertion(GATEWAY).is_none());
        let source = map.assertion_for(GATEWAY, r).unwrap();
        let expected = AccessRequest::from_ip(r, l, 80, Protocol::Tcp).source;
        assert_eq!(source.source_anchor(), expected.source_anchor());
        assert_eq!(source.ip(), expected.ip());
        assert_eq!(source.source_class(), "terminate-binding");
        assert!(map.by_source(GATEWAY) && !map.by_source(KEY_PEER));

        let f = AclFilter::new(loaded_engine(test_policy()), Arc::clone(&map));
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(r, 4000, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(other, 4000, l, 80)),
            drop(reasons::DENIED)
        );
        // Each source keeps its own principal on later packets.
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(r, 4001, l, 80)),
            Verdict::Accept
        );
        assert_eq!(
            inbound(&f, GATEWAY, tcp_packet(other, 4001, l, 80)),
            drop(reasons::DENIED)
        );
        // A relayed client in the same map keeps its key principal.
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
        let f = AclFilter::with_config(loaded_engine(test_policy()), by_source_identity(), config);
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
    fn closure_identity_uses_the_default_assertion_for() {
        let identity =
            |peer: PeerId| (peer == PEER).then_some(SourceAssertion::WgPeerKey { pubkey: KEY });
        let any = addr("10.0.0.9");
        assert_eq!(
            identity.assertion_for(PEER, any).map(|s| s.source_anchor()),
            Some(wg_peer_anchor(&KEY))
        );
        assert!(!identity.by_source(PEER));
        let f = AclFilter::new(loaded_engine(test_policy()), identity);
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

        // By key: the key principal is in no namespace either.
        map.insert(
            GATEWAY,
            SourceAssertion::WgPeerKey {
                pubkey: peer_key(A),
            },
        );
        assert_eq!(inbound(&f, GATEWAY, packet()), drop(reasons::NO_POLICY));
        map.insert_by_source(GATEWAY);
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
        engine
            .load(policy(vec![rule("fd00::d/128", "*:*", "udp")]))
            .unwrap();
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

    /// An engine with `policy` loaded whose clock is moved by hand.
    fn clocked_engine(policy: AclPolicy) -> (Arc<AclEngine>, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let handle = Arc::clone(&clock);
        let engine = AclEngine::with_clock(move || *handle.lock().unwrap());
        engine.load(policy).unwrap();
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
        let engine = loaded_engine(test_policy());
        let f = AclFilter::with_config(Arc::clone(&engine), identity(), allow_only(4096));
        assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
        engine.clear();
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
            loaded_engine(test_policy()),
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

    /// The identities of an ns account: gateways by source, relay clients
    /// by key.
    fn crates_acl_identity() -> Arc<PeerIdentityMap> {
        let map = Arc::new(PeerIdentityMap::new());
        map.insert_by_source(PEER);
        map.insert(KEY_PEER, SourceAssertion::WgPeerKey { pubkey: KEY });
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
        engine.load(test_policy()).unwrap();
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
}
