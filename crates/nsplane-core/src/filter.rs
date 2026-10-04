//! Synchronous packet filters run by the core on the plaintext side.

use nsplane_packet::{PacketBuf, Path, PeerId};

/// What a [`PacketFilter`] decided about a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the packet on.
    Accept,
    /// Drop the packet; the core reports `reason` in an `Event::Dropped`.
    Drop {
        /// Static description of why the packet was dropped.
        reason: &'static str,
    },
    /// The filter consumed the packet: no `Deliver` or `Transmit` and no drop event.
    Handled,
}

/// A filter on the plaintext side of the core. It is called synchronously and never does I/O.
///
/// Filters form an onion: the chain is installed from the wire side to the local side.
/// Decrypted packets run through it in install order before they are delivered, local
/// packets in reverse install order before they are encrypted, so the first filter is the one
/// next to the tunnel in both directions and sees what the peer sends and receives. The first
/// verdict other than [`Verdict::Accept`] ends the chain. Local packets are routed to a peer
/// before the chain runs.
///
/// Packets injected with [`Core::inject_inbound`](crate::Core::inject_inbound),
/// [`Core::inject_outbound`](crate::Core::inject_outbound) or
/// [`Core::inject_outbound_on`](crate::Core::inject_outbound_on) skip the chain (part of the
/// contract): no filter sees them, so a stateful filter keeps no state for them.
pub trait PacketFilter: Send + Sync + 'static {
    /// Decrypted packet from `peer`, before it is delivered. May rewrite it in place.
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;

    /// Decrypted packet from `peer` that arrived on `from`, before it is delivered; what the
    /// core calls for every decrypted datagram. The default ignores the path and calls
    /// [`PacketFilter::inbound`]; a filter that answers on the path a packet came from (a
    /// probe responder, say) overrides this one. A wrapper around another filter should
    /// forward both.
    ///
    /// Order (part of the contract): for a transport data message the core first records it
    /// as authenticated (handshake bookkeeping and [`crate::PathPolicy::on_authenticated`],
    /// including a possible path change), then checks the source and destination addresses,
    /// and only then runs the inbound filters, so a filter sees the path state after the
    /// policy decided about this very datagram.
    fn inbound_from(&self, peer: PeerId, from: &Path, packet: &mut PacketBuf) -> Verdict {
        let _ = from;
        self.inbound(peer, packet)
    }

    /// Local packet routed to `peer`, before it is encrypted. May rewrite it in place.
    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;
}
