//! Reassembly of ingress fragments and the barriers of revoked flows.

use std::net::{IpAddr, SocketAddr};

use nsplane_packet::reassembly::Outcome;
use nsplane_packet::{IpPacket, PacketBuf, protocol};
use tokio::time::Instant;

use crate::flow::Target;
use crate::stats::{self};

use super::Driver;

/// A revoked flow whose fragments the reassembler may still hold. Later fragments carry
/// no ports, so a held datagram cannot be told apart from one of a new flow on the same
/// tuple: every datagram completed for the flow's tuple before `until` is dropped.
#[derive(Debug)]
pub(super) struct Barrier {
    protocol: u8,
    local: SocketAddr,
    /// `None` for a bound socket: every remote.
    remote: Option<SocketAddr>,
    until: std::time::Instant,
}

impl Barrier {
    /// Whether a datagram from `src` to `dst` completed at `now` is held back; `ports`
    /// gives its protocol and `(src, dst)` ports if it is TCP or UDP. One whose ports
    /// cannot be read is held back by its addresses alone.
    fn holds(
        &self,
        src: IpAddr,
        dst: IpAddr,
        ports: Option<(u8, u16, u16)>,
        now: std::time::Instant,
    ) -> bool {
        let local_ip = self.local.ip();
        let addresses = (local_ip == dst
            || (local_ip.is_unspecified() && local_ip.is_ipv4() == dst.is_ipv4()))
            && self.remote.is_none_or(|remote| remote.ip() == src);
        let ports = ports.is_none_or(|(protocol, src_port, dst_port)| {
            protocol == self.protocol
                && dst_port == self.local.port()
                && self.remote.is_none_or(|remote| remote.port() == src_port)
        });
        now < self.until && addresses && ports
    }
}

impl Driver {
    /// Feeds a packet to an address the stack accepts through the reassembler, if there is one:
    /// the packet to route (the packet itself or a completed datagram), or `None` while
    /// its datagram is incomplete or once the fragment is dropped.
    pub(super) fn reassemble(&mut self, packet: PacketBuf) -> Option<PacketBuf> {
        let Some(reassembler) = self.reassembler.as_mut() else {
            return Some(packet);
        };
        let now = Instant::now().into_std();
        let Ok(ip) = IpPacket::parse(packet.as_packet()) else {
            // `classify` counts it.
            return Some(packet);
        };
        if !self.settings.accepts(ip.dst()) {
            return Some(packet);
        }
        if self.owners.is_discarded(&ip, now) {
            stats::add(&self.stats.reassembly_overflow, 1);
            return None;
        }
        let routed = match reassembler.push(packet.as_packet(), now) {
            Outcome::Pass => return Some(packet),
            Outcome::Complete(datagram) if self.barred(&datagram, now) => {
                stats::add(&self.stats.retired, 1);
                None
            }
            Outcome::Complete(datagram) => Some(PacketBuf::from_packet(&datagram)),
            Outcome::Held | Outcome::Dropped => None,
        };
        self.count_reassembly();
        routed
    }

    /// Discards incomplete datagrams past the reassembly timeout, and forgets discarded
    /// ones; free while none is held.
    pub(super) fn expire_fragments(&mut self) {
        let Some(reassembler) = self.reassembler.as_mut() else {
            return;
        };
        let now = Instant::now().into_std();
        if reassembler.expire(now) > 0 {
            self.count_reassembly();
        }
        self.owners.expire_discarded(now);
        self.barriers.retain(|barrier| now < barrier.until);
    }

    /// Whether a reassembled `datagram` may hold fragments of a revoked flow; free while
    /// there is no barrier.
    fn barred(&self, datagram: &[u8], now: std::time::Instant) -> bool {
        if self.barriers.is_empty() {
            return false;
        }
        let Ok(ip) = IpPacket::parse(datagram) else {
            return false;
        };
        let protocol = ip.protocol();
        let ports = ip
            .payload()
            .first_chunk::<4>()
            .filter(|_| protocol == protocol::TCP || protocol == protocol::UDP)
            .map(|&[a, b, c, d]| {
                (
                    protocol,
                    u16::from_be_bytes([a, b]),
                    u16::from_be_bytes([c, d]),
                )
            });
        self.barriers
            .iter()
            .any(|barrier| barrier.holds(ip.src(), ip.dst(), ports, now))
    }

    /// Bars the datagrams of a revoked flow the reassembler may still complete, see
    /// [`Barrier`]; `false` if the table is full. Nothing while no datagram is held.
    pub(super) fn bar(&mut self, target: &Target) -> bool {
        let Some(reassembler) = self.reassembler.as_ref() else {
            return true;
        };
        if reassembler.pending() == 0 {
            return true;
        }
        if self.barriers.len() >= reassembler.config().max_datagrams {
            return false;
        }
        let (protocol, local, remote) = match *target {
            Target::Tcp { local, peer, .. } => (protocol::TCP, local, Some(peer)),
            Target::UdpFlow((remote, local)) | Target::UdpConnected((remote, local)) => {
                (protocol::UDP, local, Some(remote))
            }
            Target::UdpBound(local) => (protocol::UDP, local, None),
        };
        let until = Instant::now().into_std() + reassembler.config().timeout;
        self.barriers.push(Barrier {
            protocol,
            local,
            remote,
            until,
        });
        true
    }

    /// Adds what the reassembler counted since the last call to the stack's counters.
    fn count_reassembly(&mut self) {
        let Some(reassembler) = self.reassembler.as_ref() else {
            return;
        };
        let now = reassembler.stats();
        let before = std::mem::replace(&mut self.reassembly_counted, now);
        stats::add(
            &self.stats.reassembled,
            now.reassembled - before.reassembled,
        );
        stats::add(&self.stats.reassembly_timeout, now.timeout - before.timeout);
        stats::add(
            &self.stats.reassembly_overflow,
            now.overflow - before.overflow,
        );
        let rejected = (now.overlap + now.malformed) - (before.overlap + before.malformed);
        stats::add(&self.stats.malformed, rejected);
    }
}
