//! Filter settings and counters.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::rules::PolicyState;

#[cfg(doc)]
use super::AclFilter;
#[cfg(doc)]
use crate::engine::AclEngine;
#[cfg(doc)]
use crate::reasons;

/// Settings of an [`AclFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclFilterConfig {
    /// Maximum number of fragmented packets whose first-fragment verdict is
    /// remembered (at least 1). When full, the oldest entry is evicted.
    /// Default 1024.
    pub fragment_capacity: usize,
    /// Accept inbound packets that are neither TCP nor UDP (ICMP, IPv6
    /// fragments, ...) without consulting the policy. Default `false`: such
    /// packets are dropped unless a reply allowance, a scope rule or a rule
    /// accepts them.
    pub allow_other_protocols: bool,
    /// Accept inbound replies to flows the local side opened (stateful
    /// replies, not a conntrack/NAT): every accepted outbound TCP or UDP
    /// packet, and every accepted outbound ICMP or `ICMPv6` echo request,
    /// records an allowance for the reversed tuple (an echo reply needs the
    /// request's identifier); no other ICMP message and no unsolicited echo
    /// reply passes through it. Default `true`.
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
    /// state (counted in [`AclFilterStats::ipv6_accepted`]). Where an
    /// inbound IPv6 packet may be addressed can still be checked in the core
    /// with a peer's `inbound_destinations` (`nsplane-core` `PeerConfig`).
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
    /// Allow-only gating: only accepted first fragments are recorded,
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
    /// Flow continuations removed because their grant, pinhole, rule or default-accept
    /// decision no longer admits them.
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
