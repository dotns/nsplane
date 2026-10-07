//! A generic stateful flow gate for IPv4 packets.
//!
//! A [`FlowGate`] judges decrypted inbound and plaintext outbound IPv4
//! packets against one [`GatePolicy`] snapshot, replaced atomically as a
//! whole with [`FlowGate::replace`]:
//!
//! - **Scopes** ([`GateScope`]): each governs a set of local addresses in a
//!   [`GateMode`]. A packet belongs to a scope only through the exact pair
//!   `(PeerId, remote address)` of one of its [`GateBinding`]s, where the
//!   remote address is the IP source inbound and the IP destination
//!   outbound, and the scope governs the packet's other address. The binding
//!   gives the source its [`LabelSet`](crate::LabelSet).
//! - **Grants** ([`GateGrant`]): accept-only, directional, by remote label,
//!   destination prefix and [`ProtocolMatch`](crate::ProtocolMatch). The
//!   first matching grant that is not suspended admits a new flow and its
//!   [`RuleId`] is reported.
//! - **State**: admitted flows create bounded state ([`GateLimits`]) with
//!   per-protocol idle timeouts ([`GateTimeouts`]). Replies, later fragments
//!   and ICMP errors are admitted only through that state; a full table
//!   fails closed and never evicts a live entry.
//! - **Holds** ([`GateHolds`]): packets held fail closed in every mode before
//!   any scope is consulted.
//! - **Unbound rules** ([`UnboundRule`]): what happens to inbound packets of
//!   designated peers that bind to no scope: passed on, or offered to a
//!   [`GateDivert`] by the [`GateFilter`].
//!
//! # Evaluation
//!
//! The gate handles IPv4 only: every other packet is [`GateDecision::Pass`],
//! and [`FlowGate::replace`] rejects IPv6 entries in a policy
//! ([`GatePolicyError::Ipv6`]). Inbound, with `local` the destination and
//! `remote` the source:
//!
//! 1. **Inert**: no scope with a mode other than [`GateMode::Off`] and no
//!    hold rule: [`GateDecision::Pass`], without parsing the packet or
//!    reading the clock.
//! 2. **Malformed**: an unparsable packet whose addresses are readable is
//!    held when a hold matches; otherwise the scopes governing `local` decide
//!    [`GateReason::Malformed`] under their mode, or it passes when there is
//!    none. An unreadable packet passes.
//! 3. **Holds**: `(peer, remote)` in [`GateHolds::release`] skips the
//!    inbound holds; otherwise a matching [`HoldRule`] gives
//!    [`GateReason::Held`] (always enforced).
//! 4. **Binding**: the scopes governing `local` that bind `(peer, remote)`.
//!    More than one: [`GateReason::Ambiguous`], enforced when any of them
//!    enforces. None: when exactly one scope governs `local` and it
//!    enforces, a matching [`UnboundAction::Pass`] rule of that scope passes
//!    the packet (a first fragment remembers that disposition; a later
//!    fragment of a peer named by an unbound rule follows it or is denied
//!    [`GateReason::OrphanFragment`]); otherwise [`GateReason::Unbound`]
//!    under the mode of the scopes governing `local`, or a pass when there
//!    is none.
//! 5. **Bound** in one scope: a later fragment follows its first fragment's
//!    state ([`GateReason::ValidState`]) or is denied
//!    [`GateReason::OrphanFragment`]. An ICMP error (types 3, 4, 11, 12)
//!    refreshes the quoted flow or is denied [`GateReason::ReverseNewFlow`]
//!    (an unreadable quote is [`GateReason::Malformed`]). A packet of a live
//!    flow is [`GateReason::ValidState`], except a TCP SYN without ACK from
//!    the responder or on a closing flow. A reverse-only packet (TCP without
//!    SYN or with ACK; ICMP types 0, 3, 4, 5, 11, 12) without state is
//!    [`GateReason::ReverseNewFlow`]. TCP or UDP with a port 0 is
//!    [`GateReason::Malformed`].
//! 6. **New flow**: the first matching grant that is not suspended admits it
//!    ([`GateReason::Granted`] with the grant's id), and its state is
//!    recorded in [`GateMode::Observe`] too. When only suspended grants
//!    match the flow is denied [`GateReason::Suspended`], when none does
//!    [`GateReason::NoGrant`], and when the limits refuse it
//!    [`GateReason::StateCapacity`].
//!
//! Outbound, with `local` the source and `remote` the destination, follows
//! the same steps, with the outbound holds and without
//! [`GateHolds::release`]; grants of [`Direction::Outbound`](crate::Direction)
//! check `destinations` against `remote`; there are no unbound rules; and an
//! unbound or malformed packet takes the mode of the scopes holding `remote`
//! as a binding address (a packet to another destination passes).
//!
//! Decisions take each scope's mode: [`GateMode::Observe`] gives
//! [`GateDecision::Observe`] and [`GateMode::Enforce`] gives
//! [`GateDecision::Enforce`]; holds always give [`GateDecision::Enforce`].
//!
//! # Replace and state migration
//!
//! [`FlowGate::replace`] validates the whole policy, then publishes it with
//! every state shard locked and migrates the state:
//!
//! - flows and fragments of a scope whose content is unchanged are kept
//!   untouched;
//! - those of a removed scope, or of one that is now [`GateMode::Off`], are
//!   dropped;
//! - each flow of a changed scope is re-authorized as a new flow by its
//!   initiator (its binding still in the scope, its local address still
//!   governed, a grant that is not suspended still matching the packet that
//!   opened it); it keeps its five-tuple and its idle deadline and takes the
//!   grant's id and the scope's mode, or is dropped;
//! - the fragments of a changed scope are dropped.
//!
//! A packet never sees a policy together with the state of another policy.
//! A holds-only change revalidates nothing.
//!
//! The gate is inert unless constructed with a policy. Packet paths read one
//! immutable snapshot and lock only the state shard of their peer; writers
//! serialize on one mutex. Established flows allocate nothing.

use std::cell::OnceCell;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use arc_swap::ArcSwap;
use nsplane_packet::PeerId;

use crate::net::Protocol;
use crate::rules::RuleId;

mod clock;
mod config;
mod decisions;
mod divert;
mod filter;
mod hash;
mod migrate;
mod packet;
mod policy;
mod snapshot;
mod state;
#[cfg(test)]
mod tests;

pub use config::{
    GateBinding, GateConfig, GateGrant, GateHolds, GateLimits, GateMode, GatePolicy,
    GatePolicyError, GateScope, GateTimeouts, HoldRule, ScopeId, UnboundAction, UnboundRule,
};
pub use divert::DivertedPacket;
pub use filter::{GateDivert, GateFilter, GateFilterStats};

use snapshot::Snapshot;
use state::StateTable;

/// Why the gate decided as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GateReason {
    /// The packet matches existing flow or fragment state.
    ValidState,
    /// A grant admits the new flow.
    Granted,
    /// The packet binds to no scope.
    Unbound,
    /// A reply-only or reverse packet without matching state.
    ReverseNewFlow,
    /// No grant admits the new flow.
    NoGrant,
    /// Only suspended grants match the new flow.
    Suspended,
    /// A hold matches the packet.
    Held,
    /// A later fragment without an admitted first fragment.
    OrphanFragment,
    /// The flow or fragment table is full.
    StateCapacity,
    /// More than one scope binds the packet.
    Ambiguous,
    /// The packet cannot be parsed.
    Malformed,
}

impl GateReason {
    /// Stable snake-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidState => "valid_state",
            Self::Granted => "granted",
            Self::Unbound => "unbound",
            Self::ReverseNewFlow => "reverse_new_flow",
            Self::NoGrant => "no_grant",
            Self::Suspended => "suspended",
            Self::Held => "held",
            Self::OrphanFragment => "orphan_fragment",
            Self::StateCapacity => "state_capacity",
            Self::Ambiguous => "ambiguous",
            Self::Malformed => "malformed",
        }
    }

    /// Drop reason reported for an enforced denial with this reason.
    #[must_use]
    pub const fn drop_reason(self) -> &'static str {
        match self {
            Self::ValidState => "flow gate: valid state",
            Self::Granted => "flow gate: granted",
            Self::Unbound => "flow gate: unbound",
            Self::ReverseNewFlow => "flow gate: reverse new flow",
            Self::NoGrant => "flow gate: no grant",
            Self::Suspended => "flow gate: suspended",
            Self::Held => "flow gate: held",
            Self::OrphanFragment => "flow gate: orphan fragment",
            Self::StateCapacity => "flow gate: state capacity",
            Self::Ambiguous => "flow gate: ambiguous",
            Self::Malformed => "flow gate: malformed",
        }
    }
}

/// The gate's decision for one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// No scope or hold applies (or an unbound rule passes the packet): the
    /// packet goes on unchanged.
    Pass,
    /// A scope in [`GateMode::Observe`] decided: reported and counted, but
    /// the packet goes on.
    Observe {
        /// Whether enforcement would allow the packet.
        allow: bool,
        /// Why.
        reason: GateReason,
        /// The admitting grant ([`GateReason::Granted`]) or the first
        /// matching suspended grant ([`GateReason::Suspended`]).
        rule: Option<RuleId>,
    },
    /// An authoritative decision (a scope in [`GateMode::Enforce`], or a
    /// hold).
    Enforce {
        /// Whether the packet is allowed.
        allow: bool,
        /// Why.
        reason: GateReason,
        /// The admitting grant ([`GateReason::Granted`]) or the first
        /// matching suspended grant ([`GateReason::Suspended`]).
        rule: Option<RuleId>,
    },
}

impl GateDecision {
    /// The authoritative verdict, if the decision is enforced.
    #[must_use]
    pub const fn enforced_verdict(&self) -> Option<bool> {
        match self {
            Self::Enforce { allow, .. } => Some(*allow),
            Self::Pass | Self::Observe { .. } => None,
        }
    }
}

/// Monotonic decision counters of a [`FlowGate`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateCounters {
    /// Enforced allows.
    pub enforced_allowed: u64,
    /// Enforced denials.
    pub enforced_denied: u64,
    /// Observe-mode denials.
    pub observed_denied: u64,
    /// Enforced [`GateReason::Unbound`] denials.
    pub unbound_denied: u64,
    /// Enforced [`GateReason::StateCapacity`] denials.
    pub state_capacity_denied: u64,
}

/// A live flow found by [`FlowGate::find_flow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFlow {
    /// The scope holding the flow.
    pub scope: ScopeId,
    /// The grant that admitted (or last re-authorized) the flow.
    pub rule: RuleId,
    /// Whether the flow was admitted in [`GateMode::Enforce`].
    pub enforced: bool,
}

#[derive(Debug, Default)]
struct RuntimeCounters {
    enforced_allowed: AtomicU64,
    enforced_denied: AtomicU64,
    observed_denied: AtomicU64,
    unbound_denied: AtomicU64,
    state_capacity_denied: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PacketDirection {
    Inbound,
    Outbound,
}

type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// The flow gate: an immutable policy snapshot swapped atomically plus
/// bounded flow state sharded by peer.
pub struct FlowGate {
    snapshot: ArcSwap<Snapshot>,
    /// The published snapshot is inert, so every packet passes. Read before
    /// the snapshot, without the clock.
    inert: AtomicBool,
    writer: Mutex<()>,
    state: StateTable,
    counters: RuntimeCounters,
    clock: Clock,
}

impl fmt::Debug for FlowGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowGate")
            .field("generation", &self.generation())
            .field("counters", &self.counters())
            .finish_non_exhaustive()
    }
}

impl FlowGate {
    /// A gate with no policy: every packet [`GateDecision::Pass`] without
    /// parsing. Its clock is the coarse monotonic clock on Linux and Android
    /// (a resolution of one scheduler tick, 1 to 4 ms) and
    /// [`Instant::now`] elsewhere.
    #[must_use]
    pub fn new(config: GateConfig) -> Arc<Self> {
        Self::with_clock(config, clock::coarse())
    }

    /// A gate whose flow and fragment expiry follows `clock` (e.g. a manual
    /// clock in tests and benches).
    #[must_use]
    pub fn with_clock(
        config: GateConfig,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            snapshot: ArcSwap::default(),
            inert: AtomicBool::new(true),
            writer: Mutex::new(()),
            state: StateTable::new(&config),
            counters: RuntimeCounters::default(),
            clock: Box::new(clock),
        })
    }

    /// Validate `policy`, publish it atomically and migrate the state;
    /// returns the new gate generation. A rejected policy changes nothing.
    pub fn replace(&self, policy: GatePolicy) -> Result<u64, GatePolicyError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.snapshot.load_full();
        let compiled = policy::compile(policy, &current.slots)?;
        let snapshot = Arc::new(Snapshot::build(current.generation + 1, compiled));
        let mut shards = self.state.lock_all();
        self.snapshot.store(Arc::clone(&snapshot));
        // A packet still reading the previous value is ordered before this
        // publication, as if it had loaded the previous snapshot.
        self.inert.store(snapshot.inert, Ordering::Release);
        migrate::migrate(&mut shards, &current, &snapshot, &self.state.counts);
        for shard in &mut shards {
            shard.epoch = snapshot.generation;
        }
        Ok(snapshot.generation)
    }

    /// The generation of the published policy: 0 before the first
    /// [`replace`](Self::replace), then increased by every one.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.snapshot.load().generation
    }

    /// Evaluate a packet received from `peer`.
    #[must_use]
    pub fn evaluate_inbound(&self, peer: PeerId, packet: &[u8]) -> GateDecision {
        self.evaluate(PacketDirection::Inbound, peer, packet)
    }

    /// Evaluate a packet to be sent to `peer`.
    #[must_use]
    pub fn evaluate_outbound(&self, peer: PeerId, packet: &[u8]) -> GateDecision {
        self.evaluate(PacketDirection::Outbound, peer, packet)
    }

    /// Evaluate and count one packet. An inert gate passes it without
    /// parsing, loading the snapshot or reading the clock; otherwise the
    /// clock is read only once the packet reaches the state.
    fn evaluate(&self, direction: PacketDirection, peer: PeerId, packet: &[u8]) -> GateDecision {
        if self.inert.load(Ordering::Acquire) {
            return GateDecision::Pass;
        }
        let decision = self.evaluate_with(direction, peer, packet, OnceCell::new());
        self.record_decision(&decision);
        decision
    }

    /// The live flow between `remote` and `local` of `protocol`, refreshed,
    /// preferring an enforced one; `None` for IPv6 addresses.
    #[must_use]
    pub fn find_flow(
        &self,
        remote: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
    ) -> Option<LiveFlow> {
        let (SocketAddr::V4(remote), SocketAddr::V4(local)) = (remote, local) else {
            return None;
        };
        let protocol = match protocol {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        };
        let now = (self.clock)();
        // With every shard held no writer can publish, so the snapshot and
        // the state are consistent.
        let mut shards = self.state.lock_all();
        let snapshot = self.snapshot.load();
        let counts = &self.state.counts;
        let mut found: Option<LiveFlow> = None;
        for shard in &mut shards {
            shard.retain_flows(counts, |key, flow| {
                if key.remote_ip != *remote.ip()
                    || key.local_ip != *local.ip()
                    || key.remote_port != remote.port()
                    || key.local_port != local.port()
                    || key.protocol != protocol
                {
                    return true;
                }
                if flow.expires_at <= now {
                    return false;
                }
                flow.touch(key.protocol, now, &counts.timeouts);
                if found.as_ref().is_none_or(|live| !live.enforced)
                    && let Some(scope) = snapshot.scope_of_slot(key.slot)
                {
                    found = Some(LiveFlow {
                        scope: scope.id.clone(),
                        rule: flow.rule.clone(),
                        enforced: flow.enforced,
                    });
                }
                true
            });
        }
        found
    }

    /// The decision counters.
    #[must_use]
    pub fn counters(&self) -> GateCounters {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        GateCounters {
            enforced_allowed: load(&self.counters.enforced_allowed),
            enforced_denied: load(&self.counters.enforced_denied),
            observed_denied: load(&self.counters.observed_denied),
            unbound_denied: load(&self.counters.unbound_denied),
            state_capacity_denied: load(&self.counters.state_capacity_denied),
        }
    }
}

const fn mode_decision(
    enforce: bool,
    allow: bool,
    reason: GateReason,
    rule: Option<RuleId>,
) -> GateDecision {
    if enforce {
        GateDecision::Enforce {
            allow,
            reason,
            rule,
        }
    } else {
        GateDecision::Observe {
            allow,
            reason,
            rule,
        }
    }
}
