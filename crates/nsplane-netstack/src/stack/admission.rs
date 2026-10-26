//! Connections and flows held for the application's decision.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use nsplane_packet::{IpPacket, protocol};
use tokio::time::Instant;

use crate::events::FlowEventReason;
use crate::pending::{self, Hold, Pending, PendingProtocol};
use crate::stats::{self};
use crate::udp::Datagram;

use super::Driver;
use super::wire::tcp_reset;

impl Driver {
    /// Answers the bare SYN `packet` of `key` with RST for `max_connections`.
    pub(super) fn reject_connection_limit(&mut self, key: &pending::Key, packet: &[u8]) {
        stats::add(&self.stats.rejected_connection_limit, 1);
        self.emit(key, FlowEventReason::ConnectionLimit);
        if let Some(reset) = tcp_reset(packet) {
            self.push_reply(reset);
        }
    }

    /// Holds a new connection or flow for the application's decision, rejecting it at
    /// once when the table is full or the application's stream is gone.
    pub(super) fn hold(&mut self, key: pending::Key, held: pending::Held) {
        let Some(table) = self.pending.as_mut() else {
            return;
        };
        match table.hold(key, held, Instant::now()) {
            Hold::Held => self.count_pending(),
            Hold::Full(held) => self.reject(&key, &held, FlowEventReason::TableFull),
            Hold::Gone(held) => self.reject(&key, &held, FlowEventReason::Hook),
        }
    }

    /// Answers a held SYN or datagram of `key` with RST or port unreachable, counting it
    /// in the `rejected_` counter of `reason` (`Hook`, `Timeout` or `TableFull`).
    fn reject(&mut self, key: &pending::Key, held: &pending::Held, reason: FlowEventReason) {
        let counter = match reason {
            FlowEventReason::Timeout => &self.stats.rejected_timeout,
            FlowEventReason::TableFull => &self.stats.rejected_table_full,
            _ => &self.stats.rejected_hook,
        };
        stats::add(counter, 1);
        self.emit(key, reason);
        if let Some(reply) = held.rejection(self.settings.mtu) {
            self.push_reply(reply);
        }
    }

    /// Applies the application's decisions on held connections and flows: an accepted SYN
    /// goes into smoltcp with this batch (counted in `demand`), an accepted datagram
    /// opens its flow. Only with `Admission::Decide`.
    #[cold]
    #[inline(never)]
    pub(super) fn take_decisions(&mut self, demand: &mut HashMap<u16, usize>) {
        let mut changed = false;
        while let Some((decision, key, held)) =
            self.pending.as_deref_mut().and_then(Pending::next_decision)
        {
            changed = true;
            if !decision.accept {
                self.reject(&key, &held, FlowEventReason::Hook);
                continue;
            }
            match held {
                pending::Held::Tcp(syn) => {
                    if self.at_connection_limit(demand) {
                        self.reject_connection_limit(&key, syn.as_packet());
                        continue;
                    }
                    stats::add(&self.stats.accepted, 1);
                    self.emit(&key, FlowEventReason::Admitted);
                    *demand.entry(key.local.port()).or_insert(0) += 1;
                    self.device.inject(syn);
                }
                pending::Held::Udp { payload, .. } => {
                    let datagram = Datagram {
                        src: key.remote,
                        dst: key.local,
                        payload,
                    };
                    self.dispatch_held_udp(datagram, None);
                }
            }
        }
        if changed {
            self.count_pending();
        }
    }

    /// Holds the new flow from `remote` to `local` with its first datagram, or drops the
    /// datagram of a flow already held.
    #[cold]
    #[inline(never)]
    pub(super) fn hold_udp(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
        payload: Bytes,
        packet: Bytes,
    ) {
        let key = pending::Key {
            protocol: PendingProtocol::Udp,
            remote,
            local,
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|table| table.contains(&key))
        {
            // A held flow queues its first datagram only.
            stats::add(&self.stats.udp_queue_full, 1);
            return;
        }
        self.hold(key, pending::Held::Udp { payload, packet });
    }

    /// Counts and reports the new flow from `remote` to `local` admitted in transparent
    /// mode.
    #[cold]
    #[inline(never)]
    pub(super) fn admit_udp(&mut self, remote: SocketAddr, local: SocketAddr) {
        stats::add(&self.stats.accepted, 1);
        let key = pending::Key {
            protocol: PendingProtocol::Udp,
            remote,
            local,
        };
        self.emit(&key, FlowEventReason::Admitted);
    }

    /// Rejects the held connections and flows past their deadline. Only with
    /// [`Admission::Decide`], so that without it the driver does not read the clock.
    #[cold]
    #[inline(never)]
    pub(super) fn expire_pending(&mut self) {
        let now = Instant::now();
        let mut changed = false;
        while let Some((key, held)) = self
            .pending
            .as_mut()
            .and_then(|table| table.next_expired(now))
        {
            changed = true;
            self.reject(&key, &held, FlowEventReason::Timeout);
        }
        if changed {
            self.count_pending();
        }
    }

    /// Emits the admission event of `key` for `reason`, with `TransparentConfig::events`.
    pub(super) fn emit(&mut self, key: &pending::Key, reason: FlowEventReason) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        let protocol = match key.protocol {
            PendingProtocol::Tcp => protocol::TCP,
            PendingProtocol::Udp => protocol::UDP,
        };
        events.emit(&self.stats, protocol, key.remote, key.local, reason);
    }

    /// Emits the admission event of `packet`, rejected for its destination prefix.
    pub(super) fn emit_prefix(&mut self, packet: &[u8]) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        // `classify` parsed the packet before rejecting it.
        let Ok(ip) = IpPacket::parse(packet) else {
            return;
        };
        let (src_port, dst_port) = ip
            .five_tuple()
            .map_or((0, 0), |tuple| (tuple.src_port, tuple.dst_port));
        events.emit(
            &self.stats,
            ip.protocol(),
            SocketAddr::new(ip.src(), src_port),
            SocketAddr::new(ip.dst(), dst_port),
            FlowEventReason::Prefix,
        );
    }

    /// Publishes the number of held connections and flows.
    fn count_pending(&self) {
        if let Some(table) = &self.pending {
            self.stats
                .pending
                .store(table.len() as u64, Ordering::Relaxed);
        }
    }
}
