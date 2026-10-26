//! UDP egress positions and the retirement of revoked flows.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use nsplane_packet::PacketBuf;

use crate::flow::{Fence, FlowState, RetirementOutcome, Target};
use crate::stats::{self};

use super::Driver;
use super::wire::{placeholder, tcp_tuple};

impl Driver {
    /// Moves queued UDP sends into the egress backlog while it has room, and forgets the
    /// marks of datagrams the source took.
    pub(super) fn take_udp_sends(&mut self) {
        let oldest = self.oldest_queued();
        while self
            .marks
            .front()
            .is_some_and(|(position, _)| *position < oldest)
        {
            self.marks.pop_front();
        }
        while !self.device.tx_full() {
            match self.udp_rx.try_recv() {
                Ok((packet, flow)) => self.push_udp(packet, flow),
                Err(_) => break,
            }
        }
    }

    /// Appends a UDP datagram of `flow` to the egress backlog, or drops it if the flow was
    /// revoked.
    fn push_udp(&mut self, packet: PacketBuf, flow: Arc<FlowState>) {
        if flow.is_revoked() {
            return stats::add(&self.stats.retired, 1);
        }
        self.marks.push_back((self.position(), flow));
        self.device.tx_queue.push_back(packet);
    }

    /// The egress position of the next packet appended to the backlog.
    pub(super) fn position(&self) -> u64 {
        self.sent + self.device.tx_queue.len() as u64
    }

    /// The egress position of the oldest packet possibly still in the egress queue.
    fn oldest_queued(&self) -> u64 {
        let queued = self.egress.max_capacity() - self.egress.capacity();
        self.sent.saturating_sub(queued as u64)
    }

    /// Retires the flows revoked since the last turn, see [`retire`](Self::retire).
    pub(super) fn retire_revoked(&mut self) {
        self.revocations.take(&mut self.retiring);
        // Each flow stays in `retiring` until its outcome is written, so a panic leaves the
        // rest to `Drop`, which reports them unknown.
        while let Some(flow) = self.retiring.last().cloned() {
            #[cfg(test)]
            flow.observed_in(self.turns);
            let outcome = self.retire(&flow);
            #[cfg(test)]
            flow.completed_in(self.turns);
            flow.finish(outcome);
            self.retiring.pop();
        }
    }

    /// Removes a revoked flow's state and its output from the stack: the socket (without
    /// an RST) or the queue entry, its packets in the backlog, a fence for those already
    /// in the egress queue, and a barrier for its fragments the reassembler may hold.
    /// `Failed` if the fence or the barrier table is full.
    ///
    /// A lifetime not handed out yet is found at its stage: the pending entry, the
    /// listener socket mid handshake, the connection waiting for `incoming_tcp`, or the
    /// flow entry.
    fn retire(&mut self, flow: &Arc<FlowState>) -> RetirementOutcome {
        let fenced = match flow.target() {
            None => {
                // Held, or accepted and dropped in `take_decisions`: no output yet.
                if self
                    .pending
                    .as_mut()
                    .is_some_and(|table| table.remove_lifetime(flow))
                {
                    self.count_pending();
                }
                true
            }
            Some(&Target::Tcp {
                handle,
                local,
                peer,
                start,
                ..
            }) => {
                if self
                    .conns
                    .get(&handle)
                    .is_some_and(|conn| Arc::ptr_eq(&conn.flow, flow))
                {
                    self.aborting.retain(|&aborting| aborting != handle);
                    self.release_conn(handle);
                } else if self.inbound.get(&handle).is_some_and(|inbound| {
                    inbound
                        .flow
                        .as_ref()
                        .is_some_and(|owner| Arc::ptr_eq(owner, flow))
                }) {
                    self.release_handshake(handle, local.port());
                    flow.set_end(self.position());
                }
                if !self.waiting.is_empty() {
                    self.waiting.retain(|conn| !Arc::ptr_eq(conn.flow(), flow));
                }
                self.purge_tcp(local, peer, start, flow.end())
            }
            Some(Target::UdpFlow(key)) => {
                if self
                    .flows
                    .get(key)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.flows.remove(key);
                }
                self.purge_udp(flow)
            }
            Some(Target::UdpBound(local)) => {
                if self
                    .bound
                    .get(local)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.bound.remove(local);
                }
                self.purge_udp(flow)
            }
            Some(Target::UdpConnected(key)) => {
                if self
                    .connected
                    .get(key)
                    .is_some_and(|(_, owner)| Arc::ptr_eq(owner, flow))
                {
                    self.connected.remove(key);
                }
                self.purge_udp(flow)
            }
        };
        let barred = self.bar(flow);
        if fenced && barred {
            RetirementOutcome::Retired
        } else {
            RetirementOutcome::Failed
        }
    }

    /// Drops the TCP packets from `local` to `peer` at egress positions in `[start, end)`
    /// from the backlog and fences those possibly in the egress queue; `false` if the
    /// fence table is full.
    fn purge_tcp(&mut self, local: SocketAddr, peer: SocketAddr, start: u64, end: u64) -> bool {
        let sent = self.sent;
        let mut dropped = 0;
        for (position, packet) in (sent..).zip(self.device.tx_queue.iter_mut()) {
            if (start..end).contains(&position)
                && tcp_tuple(packet.as_packet()) == Some((local, peer))
            {
                *packet = placeholder();
                dropped += 1;
            }
        }
        stats::add(&self.stats.retired, dropped);
        let (start, end) = (start.max(self.oldest_queued()), end.min(sent));
        start >= end
            || self.fences.insert(Fence::Tcp {
                local,
                peer,
                start,
                end,
            })
    }

    /// Drops the UDP datagrams of `flow` from the backlog and fences those possibly in the
    /// egress queue; `false` if the fence table is full.
    fn purge_udp(&mut self, flow: &Arc<FlowState>) -> bool {
        let (sent, oldest) = (self.sent, self.oldest_queued());
        let tx_queue = &mut self.device.tx_queue;
        let mut dropped = 0;
        let mut queued = VecDeque::new();
        self.marks.retain(|(position, owner)| {
            if !Arc::ptr_eq(owner, flow) {
                return true;
            }
            if *position >= sent {
                let index = usize::try_from(position - sent).unwrap_or(usize::MAX);
                if let Some(packet) = tx_queue.get_mut(index) {
                    *packet = placeholder();
                    dropped += 1;
                }
            } else if *position >= oldest {
                queued.push_back(*position);
            }
            false
        });
        stats::add(&self.stats.retired, dropped);
        queued.is_empty() || self.fences.insert(Fence::Udp(queued))
    }
}
