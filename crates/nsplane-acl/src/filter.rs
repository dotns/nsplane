//! [`AclFilter`]: a sans-I/O [`PacketFilter`] enforcing the ACL policy on inbound packets.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use nsplane_core::{PacketFilter, Verdict};
use nsplane_packet::{FiveTuple, IcmpHeader, IpPacket, PacketBuf, PeerId, protocol};

use crate::engine::{AccessRequest, AclEngine, SourceAssertion};
use crate::net::Protocol;
use crate::reasons;

// ── Peer identity ─────────────────────────────────────────────────────────────

/// Resolves the [`SourceAssertion`] (the ACL principal) of a peer.
///
/// Implemented by closures `Fn(PeerId) -> Option<SourceAssertion>`, by
/// [`PeerIdentityMap`] and by `Arc<T>` of any implementation, so a caller can
/// keep a handle to update the identities while the filter uses them.
pub trait PeerIdentity: Send + Sync + 'static {
    /// The source assertion of `peer`, or `None` when the peer is unknown.
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion>;
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
}

/// A concurrent map from peers to their source assertions.
///
/// Wrap it in an `Arc` and hand a clone to the filter to update it at runtime.
#[derive(Debug, Default)]
pub struct PeerIdentityMap {
    map: RwLock<HashMap<PeerId, SourceAssertion>>,
}

impl PeerIdentityMap {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the assertion of `peer`, replacing any previous one.
    pub fn insert(&self, peer: PeerId, assertion: SourceAssertion) {
        self.map
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(peer, assertion);
    }

    /// Remove the assertion of `peer`; the peer becomes unknown.
    pub fn remove(&self, peer: PeerId) {
        self.map
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&peer);
    }
}

impl PeerIdentity for PeerIdentityMap {
    fn assertion(&self, peer: PeerId) -> Option<SourceAssertion> {
        self.map
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&peer)
            .cloned()
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
    pub stateful_replies: bool,
    /// Maximum number of reply allowances (at least 1). When full, the least
    /// recently seen entry is evicted. Default 4096.
    pub reply_capacity: usize,
    /// How long a reply allowance lives without traffic. Default 120 s.
    pub reply_idle_timeout: Duration,
}

impl Default for AclFilterConfig {
    fn default() -> Self {
        Self {
            fragment_capacity: 1024,
            allow_other_protocols: false,
            stateful_replies: true,
            reply_capacity: 4096,
            reply_idle_timeout: Duration::from_secs(120),
        }
    }
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
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The decision about one inbound packet, before it becomes a [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Reply,
    Denied,
    NoPolicy,
    UnknownPeer,
    Protocol,
    Fragment,
    Malformed,
}

impl Outcome {
    const fn verdict(self) -> Verdict {
        let reason = match self {
            Self::Accepted | Self::Reply => return Verdict::Accept,
            Self::Denied => reasons::DENIED,
            Self::NoPolicy => reasons::NO_POLICY,
            Self::UnknownPeer => reasons::UNKNOWN_PEER,
            Self::Protocol => reasons::PROTOCOL,
            Self::Fragment => reasons::FRAGMENT,
            Self::Malformed => reasons::MALFORMED,
        };
        Verdict::Drop { reason }
    }

    fn count(self, counters: &Counters) {
        bump(match self {
            Self::Accepted => &counters.accepted,
            Self::Reply => &counters.replies,
            Self::Denied => &counters.denied,
            Self::NoPolicy => &counters.no_policy,
            Self::UnknownPeer => &counters.unknown_peer,
            Self::Protocol => &counters.protocol,
            Self::Fragment => &counters.fragment,
            Self::Malformed => &counters.malformed,
        });
    }
}

// ── Bounded tables ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragmentKey {
    peer: PeerId,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u16,
}

/// First-fragment outcomes in insertion order (`seq`); eviction scans for the
/// smallest sequence, which is O(capacity) but only happens when full.
#[derive(Debug, Default)]
struct FragmentTable {
    entries: HashMap<FragmentKey, (Outcome, u64)>,
    next_seq: u64,
}

/// Reply allowances keyed by the inbound (remote -> local) tuple. Eviction
/// scans for the least recently seen entry, O(capacity) and only when full.
#[derive(Debug, Default)]
struct ReplyTable {
    entries: HashMap<(PeerId, FiveTuple), Instant>,
}

// ── AclFilter ─────────────────────────────────────────────────────────────────

/// A [`PacketFilter`] enforcing an [`AclEngine`] policy on inbound packets.
///
/// Inbound packets from a peer are evaluated as an [`AccessRequest`] whose
/// principal comes from a [`PeerIdentity`]; anything the policy does not
/// accept is dropped with a [`reasons`] constant. With no policy loaded every
/// inbound packet is dropped (fail-closed). Outbound packets are always
/// accepted.
///
/// **Stateful replies, not a conntrack/NAT**: with
/// [`AclFilterConfig::stateful_replies`] on, an outbound TCP or UDP packet to a
/// peer records an allowance for the reversed tuple from that same peer, so its
/// replies pass even when the policy would not accept them as new inbound
/// traffic. Allowances expire after [`AclFilterConfig::reply_idle_timeout`]
/// without traffic.
///
/// IPv4 fragments: a first fragment is evaluated and its outcome recorded;
/// later fragments of the same packet follow it, and a later fragment with no
/// recorded first fragment is dropped.
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
    fragments: Mutex<FragmentTable>,
    replies: Mutex<ReplyTable>,
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
        Self {
            inner: Arc::new(Inner {
                engine,
                identity: Box::new(identity),
                config,
                fragments: Mutex::default(),
                replies: Mutex::default(),
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
        }
    }
}

impl Inner {
    fn inbound(&self, peer: PeerId, bytes: &[u8]) -> Outcome {
        if !self.engine.is_loaded() {
            return Outcome::NoPolicy;
        }
        let Ok(packet) = IpPacket::parse(bytes) else {
            return Outcome::Malformed;
        };
        let fragment = packet.fragment();
        let key = fragment.map(|f| FragmentKey {
            peer,
            src: packet.src(),
            dst: packet.dst(),
            protocol: packet.protocol(),
            id: f.id,
        });
        match (fragment, key) {
            (Some(f), Some(key)) if !f.is_first() => self.follow_fragment(key, f.is_last()),
            (_, key) => {
                let outcome = self.evaluate(peer, &packet);
                if let Some(key) = key {
                    self.record_fragment(key, outcome);
                }
                outcome
            }
        }
    }

    fn evaluate(&self, peer: PeerId, packet: &IpPacket<'_>) -> Outcome {
        let Some(tuple) = packet.five_tuple() else {
            return Outcome::Malformed;
        };
        if self.config.stateful_replies && self.reply_match(peer, &tuple, packet) {
            return Outcome::Reply;
        }
        let Some(protocol) = Protocol::from_ip_number(tuple.protocol) else {
            return if self.config.allow_other_protocols {
                Outcome::Accepted
            } else {
                Outcome::Protocol
            };
        };
        let Some(source) = self.identity.assertion(peer) else {
            return Outcome::UnknownPeer;
        };
        let Some(policy) = self.engine.policy() else {
            return Outcome::NoPolicy;
        };
        let request = AccessRequest {
            src_ip: tuple.src,
            source,
            dst_ip: tuple.dst,
            dst_port: tuple.dst_port,
            protocol,
        };
        if policy.is_allowed(&request).allowed {
            Outcome::Accepted
        } else {
            Outcome::Denied
        }
    }

    fn follow_fragment(&self, key: FragmentKey, last: bool) -> Outcome {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let outcome = if last {
            table.entries.remove(&key)
        } else {
            table.entries.get(&key).copied()
        };
        outcome.map_or(Outcome::Fragment, |(outcome, _)| outcome)
    }

    fn record_fragment(&self, key: FragmentKey, outcome: Outcome) {
        let mut table = self
            .fragments
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let capacity = self.config.fragment_capacity.max(1);
        if !table.entries.contains_key(&key) && table.entries.len() >= capacity {
            let oldest = table
                .entries
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                table.entries.remove(&oldest);
                bump(&self.counters.fragment_evictions);
            }
        }
        let seq = table.next_seq;
        table.next_seq += 1;
        table.entries.insert(key, (outcome, seq));
    }

    /// Whether `tuple` from `peer` matches a live reply allowance, refreshing it.
    fn reply_match(&self, peer: PeerId, tuple: &FiveTuple, packet: &IpPacket<'_>) -> bool {
        if is_icmp(tuple.protocol) && echo_type(packet) != Some(EchoType::Reply) {
            return false;
        }
        let mut table = self.replies.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (peer, *tuple);
        let Some(last_seen) = table.entries.get_mut(&key) else {
            return false;
        };
        let now = Instant::now();
        if now.duration_since(*last_seen) > self.config.reply_idle_timeout {
            table.entries.remove(&key);
            bump(&self.counters.reply_expired);
            return false;
        }
        *last_seen = now;
        true
    }

    fn outbound(&self, peer: PeerId, bytes: &[u8]) {
        if !self.config.stateful_replies {
            return;
        }
        let Ok(packet) = IpPacket::parse(bytes) else {
            return;
        };
        let Some(tuple) = packet.five_tuple() else {
            return;
        };
        let tracked = match tuple.protocol {
            protocol::TCP | protocol::UDP => true,
            p if is_icmp(p) => {
                self.config.allow_other_protocols && echo_type(&packet) == Some(EchoType::Request)
            }
            _ => false,
        };
        if tracked {
            self.record_reply(peer, reversed(tuple));
        }
    }

    fn record_reply(&self, peer: PeerId, tuple: FiveTuple) {
        let mut table = self.replies.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (peer, tuple);
        let capacity = self.config.reply_capacity.max(1);
        if !table.entries.contains_key(&key) && table.entries.len() >= capacity {
            let oldest = table
                .entries
                .iter()
                .min_by_key(|(_, last_seen)| **last_seen)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                table.entries.remove(&oldest);
                bump(&self.counters.reply_evictions);
            }
        }
        table.entries.insert(key, Instant::now());
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
        self.inner.outbound(peer, packet.as_packet());
        Verdict::Accept
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use super::*;
    use crate::engine::{TerminateBinding, wg_peer_anchor};
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
}
