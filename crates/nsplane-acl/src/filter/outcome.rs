//! The decision about one packet and the counters it bumps.

use std::sync::atomic::{AtomicU64, Ordering};

use nsplane_core::Verdict;

use crate::reasons;

#[cfg(doc)]
use super::config::Ipv6Mode;
#[cfg(doc)]
use super::scope::AclFilterScope;

#[derive(Debug, Default)]
pub(super) struct Counters {
    pub(super) accepted: AtomicU64,
    pub(super) replies: AtomicU64,
    pub(super) denied: AtomicU64,
    pub(super) no_policy: AtomicU64,
    pub(super) policy_failed: AtomicU64,
    pub(super) unknown_peer: AtomicU64,
    pub(super) protocol: AtomicU64,
    pub(super) fragment: AtomicU64,
    pub(super) malformed: AtomicU64,
    pub(super) fragment_evictions: AtomicU64,
    pub(super) reply_evictions: AtomicU64,
    pub(super) reply_expired: AtomicU64,
    pub(super) cross_namespace: AtomicU64,
    pub(super) outbound_denied: AtomicU64,
    pub(super) outbound_replies: AtomicU64,
    pub(super) reply_revoked: AtomicU64,
    pub(super) pending_evictions: AtomicU64,
    pub(super) verdict_evictions: AtomicU64,
    pub(super) bypassed: AtomicU64,
    pub(super) ipv6_accepted: AtomicU64,
    pub(super) outbound_source: AtomicU64,
    pub(super) internal: AtomicU64,
}

pub(super) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// The decision about one packet, before it becomes a [`Verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
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
    pub(super) const fn verdict(self) -> Verdict {
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

    pub(super) fn count(self, counters: &Counters) {
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
