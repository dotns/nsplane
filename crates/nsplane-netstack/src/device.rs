//! The smoltcp device between the driver's queues and the interface.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;

use nsplane_packet::{PacketBuf, PacketPool};
use smoltcp::iface::{Interface, PollIngressSingleResult, PollResult, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::stats::{self, Counters};

/// Idle buffers the device keeps for reuse.
const POOL_SIZE: usize = 256;

/// Spare bytes behind every egress packet. An engine seals a packet in place and appends
/// its trailer there (WireGuard: a 16-byte tag after up to 15 bytes of padding), so a
/// full-size packet does not have to move to a larger buffer.
pub(crate) const TAILROOM: usize = 32;

/// RX token that hands a packet to smoltcp, then recycles its buffer for egress.
pub(crate) struct VirtualRxToken<'a> {
    packet: PacketBuf,
    pool: &'a RefCell<PacketPool>,
}

impl RxToken for VirtualRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let result = f(self.packet.as_packet());
        if let Ok(mut pool) = self.pool.try_borrow_mut() {
            pool.put(self.packet);
        }
        result
    }
}

/// TX token that appends a packet to the bounded egress backlog.
///
/// smoltcp only asks for a TX token through [`Device::transmit`] while the backlog has
/// room. A token handed out with an RX token (an immediate reply to an ingested packet)
/// can still find the backlog full; that packet is dropped and counted.
pub(crate) struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<PacketBuf>,
    limit: usize,
    mtu: usize,
    pool: &'a RefCell<PacketPool>,
    stats: &'a Counters,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let capacity = len.max(self.mtu) + TAILROOM;
        let mut packet = self.pool.try_borrow_mut().map_or_else(
            |_| PacketBuf::with_capacity(capacity),
            |mut pool| pool.get(capacity),
        );
        packet.set_len(len);
        let result = f(packet.as_packet_mut());
        if self.queue.len() < self.limit {
            self.queue.push_back(packet);
        } else {
            stats::add(&self.stats.egress_full, 1);
            if let Ok(mut pool) = self.pool.try_borrow_mut() {
                pool.put(packet);
            }
        }
        result
    }
}

/// Virtual IP-medium device: ingress packets in, egress packets out.
pub(crate) struct VirtualDevice {
    pub(crate) rx_queue: VecDeque<PacketBuf>,
    pub(crate) tx_queue: VecDeque<PacketBuf>,
    tx_limit: usize,
    mtu: usize,
    pool: RefCell<PacketPool>,
    stats: Arc<Counters>,
}

impl VirtualDevice {
    /// Creates a device with an `mtu`-byte MTU and an egress backlog of `tx_limit` packets.
    pub(crate) fn new(mtu: u16, tx_limit: usize, stats: Arc<Counters>) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            tx_limit,
            mtu: usize::from(mtu),
            pool: RefCell::new(PacketPool::new(POOL_SIZE)),
            stats,
        }
    }

    /// Enqueues a packet for smoltcp to receive.
    pub(crate) fn inject(&mut self, packet: PacketBuf) {
        self.rx_queue.push_back(packet);
    }

    /// Whether the egress backlog is full.
    pub(crate) fn tx_full(&self) -> bool {
        self.tx_queue.len() >= self.tx_limit
    }

    /// Ingests every queued packet, giving smoltcp one egress turn after each one (and one
    /// turn if nothing was queued).
    ///
    /// A single egress turn sends at most one packet per socket, so the work per ingested
    /// packet stays bounded and the backlog cannot be flooded by one call; smoltcp's own
    /// `poll` would drain all egress instead.
    pub(crate) fn poll_interface(
        &mut self,
        interface: &mut Interface,
        timestamp: Instant,
        sockets: &mut SocketSet<'_>,
    ) -> PollResult {
        interface.poll_maintenance(timestamp);
        let mut result = PollResult::None;
        let mut ingested = false;
        loop {
            match interface.poll_ingress_single(timestamp, self, sockets) {
                PollIngressSingleResult::None => break,
                PollIngressSingleResult::PacketProcessed => {}
                PollIngressSingleResult::SocketStateChanged => {
                    result = PollResult::SocketStateChanged;
                }
            }
            ingested = true;
            if interface.poll_egress(timestamp, self, sockets) == PollResult::SocketStateChanged {
                result = PollResult::SocketStateChanged;
            }
        }
        if !ingested
            && interface.poll_egress(timestamp, self, sockets) == PollResult::SocketStateChanged
        {
            result = PollResult::SocketStateChanged;
        }
        result
    }

    /// Takes every packet smoltcp wants to transmit.
    #[cfg(test)]
    pub(crate) fn drain_tx(&mut self) -> impl Iterator<Item = PacketBuf> + '_ {
        self.tx_queue.drain(..)
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        let rx = VirtualRxToken {
            packet,
            pool: &self.pool,
        };
        let tx = VirtualTxToken {
            queue: &mut self.tx_queue,
            limit: self.tx_limit,
            mtu: self.mtu,
            pool: &self.pool,
            stats: &self.stats,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        (self.tx_queue.len() < self.tx_limit).then(|| VirtualTxToken {
            queue: &mut self.tx_queue,
            limit: self.tx_limit,
            mtu: self.mtu,
            pool: &self.pool,
            stats: &self.stats,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use nsplane_packet::HEADROOM;

    use super::*;

    fn device() -> VirtualDevice {
        VirtualDevice::new(1360, 4, Arc::default())
    }

    #[test]
    fn new_device_has_empty_queues() {
        let dev = device();
        assert!(dev.rx_queue.is_empty());
        assert!(dev.tx_queue.is_empty());
    }

    #[test]
    fn inject_enqueues_to_rx_queue() {
        let mut dev = device();
        dev.inject(PacketBuf::from_packet(&[1, 2, 3]));
        dev.inject(PacketBuf::from_packet(&[4, 5, 6]));
        assert_eq!(dev.rx_queue.len(), 2);
    }

    #[test]
    fn receive_pops_from_rx_queue_in_order() -> Result<(), &'static str> {
        let mut dev = device();
        dev.inject(PacketBuf::from_packet(&[0xAA]));
        dev.inject(PacketBuf::from_packet(&[0xBB]));

        let ts = Instant::from_millis(0);
        let (rx, _tx) = dev.receive(ts).ok_or("no packet")?;
        // First injected packet should be consumed first.
        let got = rx.consume(<[u8]>::to_vec);
        assert_eq!(got, vec![0xAA]);
        Ok(())
    }

    #[test]
    fn receive_returns_none_when_rx_queue_empty() {
        let mut dev = device();
        let ts = Instant::from_millis(0);
        assert!(dev.receive(ts).is_none());
    }

    #[test]
    fn rx_token_consume_passes_correct_bytes_and_recycles() {
        let pool = RefCell::new(PacketPool::new(1));
        let token = VirtualRxToken {
            packet: PacketBuf::from_packet(&[10, 20, 30]),
            pool: &pool,
        };
        let result = token.consume(<[u8]>::to_vec);
        assert_eq!(result, [10, 20, 30]);
        assert_eq!(pool.borrow().free_len(), 1);
    }

    #[test]
    fn tx_token_consume_appends_to_tx_queue_with_headroom() -> Result<(), &'static str> {
        let mut dev = device();
        let token = dev.transmit(Instant::from_millis(0)).ok_or("no token")?;
        token.consume(4, |buf| buf.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(dev.tx_queue.len(), 1);
        let packet = &mut dev.tx_queue[0];
        assert_eq!(packet.as_packet(), [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(packet.with_headroom_mut().len(), HEADROOM + 4);
        Ok(())
    }

    #[test]
    fn tx_token_leaves_tailroom_behind_a_full_size_packet() -> Result<(), &'static str> {
        let mut dev = device();
        // A recycled ingress buffer smaller than the MTU, as the pool holds after an ACK.
        dev.inject(PacketBuf::from_packet(&[0; 40]));
        let (rx, _tx) = dev.receive(Instant::from_millis(0)).ok_or("no packet")?;
        rx.consume(|_| ());
        let token = dev.transmit(Instant::from_millis(0)).ok_or("no token")?;
        token.consume(1360, |buf| buf.fill(1));
        let packet = &dev.tx_queue[0];
        assert_eq!(packet.len(), 1360);
        assert!(packet.capacity() >= 1360 + TAILROOM);
        Ok(())
    }

    #[test]
    fn drain_tx_empties_tx_queue() {
        let mut dev = device();
        dev.tx_queue.push_back(PacketBuf::from_packet(&[1]));
        dev.tx_queue.push_back(PacketBuf::from_packet(&[2]));
        assert_eq!(dev.drain_tx().count(), 2);
        assert!(dev.tx_queue.is_empty());
    }

    #[test]
    fn transmit_returns_a_token_until_the_backlog_is_full() -> Result<(), &'static str> {
        let mut dev = device();
        let ts = Instant::from_millis(0);
        for _ in 0..4 {
            let token = dev.transmit(ts).ok_or("no token")?;
            token.consume(1, |buf| buf[0] = 1);
        }
        assert!(dev.tx_full());
        assert!(dev.transmit(ts).is_none());
        Ok(())
    }

    #[test]
    fn reply_token_drops_and_counts_when_the_backlog_is_full() -> Result<(), &'static str> {
        let mut dev = device();
        dev.tx_queue
            .extend((0..4).map(|i| PacketBuf::from_packet(&[i])));
        dev.inject(PacketBuf::from_packet(&[9]));
        let (_rx, tx) = dev.receive(Instant::from_millis(0)).ok_or("no packet")?;
        tx.consume(1, |buf| buf[0] = 7);
        assert_eq!(dev.tx_queue.len(), 4);
        assert_eq!(dev.stats.egress_full.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn capabilities_reports_ip_medium_and_tunnel_mtu() {
        let dev = device();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        // Must be the tunnel MTU, not a physical 1500, so smoltcp advertises an MSS that
        // survives WireGuard encapsulation.
        assert_eq!(caps.max_transmission_unit, 1360);
        assert_eq!(caps.ip_mtu(), 1360);
    }
}
