//! Synchronous packet filters run by the core on the plaintext side.

use nsplane_packet::{PacketBuf, PeerId};

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
pub trait PacketFilter: Send + Sync + 'static {
    /// Decrypted packet from `peer`, before it is delivered. May rewrite it in place.
    fn inbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;
    /// Local packet routed to `peer`, before it is encrypted. May rewrite it in place.
    fn outbound(&self, peer: PeerId, packet: &mut PacketBuf) -> Verdict;
}
