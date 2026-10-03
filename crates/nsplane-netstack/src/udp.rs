//! UDP fast path: datagrams bypass smoltcp.
//!
//! smoltcp has no UDP listener that accepts arbitrary destination ports the way the TCP
//! listener pool does, so the driver intercepts UDP at the IP layer, extracts
//! `(src, dst, payload)` and fans each `(remote, local)` tuple into a per-flow queue. An
//! application can keep one upstream socket per flow instead of handling each datagram
//! on its own. Replies are wrapped into IPv4/UDP or IPv6/UDP packets right here.

use std::io;
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use nsplane_packet::checksum::{
    ipv4_header_checksum, transport_checksum_v4, transport_checksum_v6,
};
use nsplane_packet::{IpPacket, PacketBuf, UdpHeader, protocol};
use tokio::sync::mpsc;

use crate::ownership::Registration;

/// UDP header length.
const UDP_HEADER: usize = 8;
/// Hop limit / TTL of every emitted datagram.
const HOP_LIMIT: u8 = 64;
/// The IPv4 DF flag in byte 6 of the header.
const DONT_FRAGMENT: u8 = 0x40;

/// A parsed inbound UDP datagram.
#[derive(Debug)]
pub(crate) struct Datagram {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    /// A view into the ingress packet; parsing copies nothing.
    pub(crate) payload: Bytes,
}

/// Extracts the UDP datagram from an IPv4 or IPv6 packet.
///
/// Returns `None` if the packet is not an unfragmented UDP datagram or is malformed.
/// IPv6 extension headers are not walked.
pub(crate) fn parse_udp(packet: PacketBuf) -> Option<Datagram> {
    let bytes = packet.as_packet();
    let ip = IpPacket::parse(bytes).ok()?;
    if ip.protocol() != protocol::UDP || ip.fragment().is_some() {
        return None;
    }
    let header_len = match &ip {
        IpPacket::V4 { header, .. } => header.header_len(),
        IpPacket::V6 { .. } => 40,
    };
    let (udp, _) = UdpHeader::parse(ip.payload()).ok()?;
    let udp_len = usize::from(udp.len());
    if udp_len < UDP_HEADER || udp_len > ip.payload().len() {
        return None;
    }
    let src = SocketAddr::new(ip.src(), udp.src_port());
    let dst = SocketAddr::new(ip.dst(), udp.dst_port());
    let start = header_len + UDP_HEADER;
    let end = header_len + udp_len;
    let payload = packet.freeze().slice(start..end);
    Some(Datagram { src, dst, payload })
}

/// Builds an IP/UDP packet from `src` to `dst` carrying `payload`.
///
/// Returns `None` if the addresses are of different families or the packet would not
/// fit the 16-bit length fields.
pub(crate) fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<PacketBuf> {
    let header_len = match (src.ip(), dst.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 20,
        (IpAddr::V6(_), IpAddr::V6(_)) => 40,
        _ => return None,
    };
    let udp_len = UDP_HEADER + payload.len();
    let total = header_len + udp_len;
    let udp_len_field = u16::try_from(udp_len).ok()?;
    let total_field = u16::try_from(total).ok()?;

    let mut packet = PacketBuf::with_capacity(total);
    packet.set_len(total);
    let bytes = packet.as_packet_mut();
    let (ip, segment) = bytes.split_at_mut(header_len);
    segment[0..2].copy_from_slice(&src.port().to_be_bytes());
    segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
    segment[4..6].copy_from_slice(&udp_len_field.to_be_bytes());
    segment[UDP_HEADER..].copy_from_slice(payload);
    let checksum = match (src.ip(), dst.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&total_field.to_be_bytes());
            // Don't fragment: the stack never exceeds its MTU, unless
            // `udp_allow_fragmentation` clears it on an oversize datagram.
            ip[6] = DONT_FRAGMENT;
            ip[8] = HOP_LIMIT;
            ip[9] = protocol::UDP;
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let header_checksum = ipv4_header_checksum(ip);
            ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            transport_checksum_v4(src, dst, protocol::UDP, segment)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&udp_len_field.to_be_bytes());
            ip[6] = protocol::UDP;
            ip[7] = HOP_LIMIT;
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
            transport_checksum_v6(src, dst, protocol::UDP, segment)
        }
        _ => return None,
    };
    // RFC 768: a computed checksum of zero is sent as all ones.
    let checksum = if checksum == 0 { 0xFFFF } else { checksum };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

/// Clears DF on an IPv4 packet built by [`build_udp`] and updates its header checksum.
fn clear_dont_fragment(packet: &mut PacketBuf) {
    let ip = &mut packet.as_packet_mut()[..20];
    ip[6] &= !DONT_FRAGMENT;
    let header_checksum = ipv4_header_checksum(ip);
    ip[10..12].copy_from_slice(&header_checksum.to_be_bytes());
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn stack_gone() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "network stack stopped")
}

/// The path from UDP handles to the driver's egress.
#[derive(Debug, Clone)]
pub(crate) struct UdpOut {
    pub(crate) tx: mpsc::Sender<PacketBuf>,
    pub(crate) mtu: usize,
    /// IPv4 datagrams above the MTU leave with DF clear instead of failing.
    pub(crate) allow_fragmentation: bool,
}

impl UdpOut {
    /// Wraps `payload` from `src` to `dst` and queues it, waiting while the queue is full.
    async fn send(&self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        if src.is_ipv4() != dst.is_ipv4() {
            return Err(invalid("address families differ"));
        }
        let mut packet =
            build_udp(src, dst, payload).ok_or_else(|| invalid("datagram exceeds the MTU"))?;
        if packet.len() > self.mtu {
            if !self.allow_fragmentation || !src.is_ipv4() {
                return Err(invalid("datagram exceeds the MTU"));
            }
            clear_dont_fragment(&mut packet);
        }
        self.tx.send(packet).await.map_err(|_| stack_gone())
    }
}

/// A UDP flow: the datagrams one remote sends to one local address.
///
/// Emitted once per `(remote, local)` tuple by
/// [`NetStackHandle::incoming_udp`](crate::NetStackHandle::incoming_udp), with the first
/// datagram already queued. Later datagrams of the tuple go to the same flow until it is
/// dropped; the next datagram after that opens a new flow. Datagrams arriving while the
/// flow's queue is full are dropped and counted.
#[derive(Debug)]
pub struct UdpFlow {
    /// Declared before `rx`: the tuple leaves the ownership table before the driver can
    /// see the queue closed and open a new flow for it.
    _registration: Registration,
    rx: mpsc::Receiver<Bytes>,
    reply: UdpReply,
}

impl UdpFlow {
    pub(crate) const fn new(
        registration: Registration,
        rx: mpsc::Receiver<Bytes>,
        reply: UdpReply,
    ) -> Self {
        Self {
            _registration: registration,
            rx,
            reply,
        }
    }

    /// The stack's address the datagrams were sent to.
    pub const fn local_addr(&self) -> SocketAddr {
        self.reply.local
    }

    /// The remote address the datagrams came from.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.reply.peer
    }

    /// The next datagram's payload, or `None` once the stack stopped and the queue is empty.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }

    /// Sends `payload` back from the local address to the remote; see [`UdpReply::send`].
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.reply.send(payload).await
    }

    /// A handle that sends replies on this flow from another task.
    pub fn reply_handle(&self) -> UdpReply {
        self.reply.clone()
    }
}

/// Sends datagrams from a flow's local address to its remote.
#[derive(Debug, Clone)]
pub struct UdpReply {
    local: SocketAddr,
    peer: SocketAddr,
    out: UdpOut,
}

impl UdpReply {
    pub(crate) const fn new(local: SocketAddr, peer: SocketAddr, out: UdpOut) -> Self {
        Self { local, peer, out }
    }

    /// Sends `payload` from the flow's local address to its remote.
    ///
    /// Waits while the stack's send queue is full. Fails with
    /// [`io::ErrorKind::InvalidInput`] if the IP packet would exceed the MTU (the stack
    /// does not fragment) and with [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    ///
    /// With [`NetStackConfig::udp_allow_fragmentation`](crate::NetStackConfig::udp_allow_fragmentation),
    /// an IPv4 packet above the MTU leaves as one datagram with DF clear (for the engine's
    /// fragmenter to split) and only a packet above the IPv4 total length limit of 65 535
    /// bytes fails; IPv6 above the MTU still fails.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.out.send(self.local, self.peer, payload).await
    }
}

/// A UDP socket bound to one of the stack's addresses, from
/// [`NetStackHandle::bind_udp`](crate::NetStackHandle::bind_udp).
///
/// Datagrams to the bound address go to this socket, not to `incoming_udp`. A socket bound
/// to the unspecified address of a family receives that family's datagrams to its port
/// unless another socket is bound to the exact address. Dropping the socket unbinds it.
#[derive(Debug)]
pub struct UdpSocket {
    /// Declared before `rx`: the address leaves the ownership table before the driver can
    /// see the queue closed and bind it again.
    _registration: Registration,
    local: SocketAddr,
    source: IpAddr,
    rx: mpsc::Receiver<(SocketAddr, Bytes)>,
    out: UdpOut,
}

impl UdpSocket {
    pub(crate) const fn new(
        registration: Registration,
        local: SocketAddr,
        source: IpAddr,
        rx: mpsc::Receiver<(SocketAddr, Bytes)>,
        out: UdpOut,
    ) -> Self {
        Self {
            _registration: registration,
            local,
            source,
            rx,
            out,
        }
    }

    /// The bound address, with the port the stack picked if `0` was requested.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Sends `payload` to `remote`.
    ///
    /// The source address is the bound address, or the stack's address of the family if
    /// the socket is bound to the unspecified address. Fails with
    /// [`io::ErrorKind::InvalidInput`] if `remote` is of the other family or the IP packet
    /// would exceed the MTU, and with [`io::ErrorKind::BrokenPipe`] once the stack stopped.
    /// Oversize IPv4 packets are handled as described on [`UdpReply::send`].
    pub async fn send_to(&self, payload: &[u8], remote: SocketAddr) -> io::Result<()> {
        let src = SocketAddr::new(self.source, self.local.port());
        self.out.send(src, remote, payload).await
    }

    /// The next datagram's payload and sender.
    ///
    /// Fails with [`io::ErrorKind::BrokenPipe`] once the stack stopped and the queue is
    /// empty.
    pub async fn recv_from(&mut self) -> io::Result<(Bytes, SocketAddr)> {
        let (from, payload) = self.rx.recv().await.ok_or_else(stack_gone)?;
        Ok((payload, from))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::time::Duration;

    use nsplane::{PacketSink, PacketSource, PeerId};
    use tokio::time::timeout;

    use super::*;
    use crate::{NetStack, NetStackConfig};

    type TestResult = Result<(), Box<dyn Error>>;

    const WAIT: Duration = Duration::from_secs(1);

    fn sample_udp_pkt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let udp_len = 8 + payload.len();
        let ip_total = 20 + udp_len;
        let mut pkt = vec![0u8; ip_total];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&u16::try_from(ip_total)?.to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&u16::try_from(udp_len)?.to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        Ok(pkt)
    }

    #[test]
    fn parse_udp_extracts_fields() -> TestResult {
        let pkt = sample_udp_pkt([10, 0, 0, 2], [10, 8, 0, 1], 12345, 53, &[1, 2, 3, 4])?;
        let got = parse_udp(PacketBuf::from_packet(&pkt)).ok_or("parse failed")?;
        assert_eq!(got.src, "10.0.0.2:12345".parse::<SocketAddr>()?);
        assert_eq!(got.dst, "10.8.0.1:53".parse::<SocketAddr>()?);
        assert_eq!(got.payload.as_ref(), &[1u8, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn parse_udp_rejects_tcp() -> TestResult {
        let mut pkt = sample_udp_pkt([1, 2, 3, 4], [5, 6, 7, 8], 80, 80, &[])?;
        pkt[9] = 6; // TCP
        assert!(parse_udp(PacketBuf::from_packet(&pkt)).is_none());
        Ok(())
    }

    #[test]
    fn parse_udp_rejects_bad_length() -> TestResult {
        let mut pkt = sample_udp_pkt([1, 2, 3, 4], [5, 6, 7, 8], 80, 80, &[1, 2])?;
        pkt[24..26].copy_from_slice(&11u16.to_be_bytes());
        assert!(parse_udp(PacketBuf::from_packet(&pkt)).is_none());
        pkt[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert!(parse_udp(PacketBuf::from_packet(&pkt)).is_none());
        Ok(())
    }

    #[test]
    fn build_udp_reply_round_trips_through_parse_udp() -> TestResult {
        for (src, dst) in [
            ("10.8.0.1:5353", "10.0.0.2:12345"),
            ("[fd00::1]:5353", "[fd00::2]:12345"),
        ] {
            let src: SocketAddr = src.parse()?;
            let dst: SocketAddr = dst.parse()?;
            let payload = b"hello udp";
            let pkt = build_udp(src, dst, payload).ok_or("build failed")?;
            let ip = IpPacket::parse(pkt.as_packet())?;
            let sum = match (src.ip(), dst.ip()) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    transport_checksum_v4(s, d, protocol::UDP, ip.payload())
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    transport_checksum_v6(s, d, protocol::UDP, ip.payload())
                }
                _ => return Err("mixed families".into()),
            };
            assert_eq!(sum, 0, "UDP checksum must verify");
            let got = parse_udp(pkt).ok_or("parse failed")?;
            assert_eq!(got.src, src);
            assert_eq!(got.dst, dst);
            assert_eq!(got.payload.as_ref(), payload);
        }
        Ok(())
    }

    #[test]
    fn build_udp_rejects_mixed_families_and_oversize() -> TestResult {
        let v4: SocketAddr = "10.0.0.1:1".parse()?;
        let v6: SocketAddr = "[fd00::1]:1".parse()?;
        assert!(build_udp(v4, v6, b"x").is_none());
        assert!(build_udp(v4, v4, &vec![0; 65_536]).is_none());
        Ok(())
    }

    /// A stack at 10.8.0.1 and `fd00::1` with MTU 1420 and `udp_allow_fragmentation` set to
    /// `allow`, plus its source and sink.
    fn fragmenting_stack(
        allow: bool,
    ) -> (
        crate::NetStackHandle,
        crate::NetStackSource,
        crate::NetStackSink,
    ) {
        let config = NetStackConfig {
            udp_allow_fragmentation: allow,
            ..NetStackConfig::new(
                vec![
                    (IpAddr::from([10, 8, 0, 1]), 24),
                    (IpAddr::from([0xfd00, 0, 0, 0, 0, 0, 0, 1]), 64),
                ],
                1420,
            )
        };
        let (stack, handle) = NetStack::new(config);
        let (source, sink) = stack.split();
        (handle, source, sink)
    }

    #[tokio::test]
    async fn oversize_send_fails_without_udp_allow_fragmentation() -> TestResult {
        let (handle, mut source, _sink) = fragmenting_stack(false);
        let socket = handle.bind_udp("10.8.0.1:53".parse()?).await?;
        let remote: SocketAddr = "10.0.0.2:5353".parse()?;
        let error = socket
            .send_to(&[1; 3000], remote)
            .await
            .err()
            .ok_or("oversize send must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        // A datagram that fits leaves exactly as built, DF set.
        socket.send_to(&[1; 1392], remote).await?;
        let packet = timeout(WAIT, source.recv()).await??;
        let expected = build_udp("10.8.0.1:53".parse()?, remote, &[1; 1392]).ok_or("build")?;
        assert_eq!(packet.as_packet(), expected.as_packet());
        assert_eq!(packet.len(), 1420);
        assert_eq!(packet.as_packet()[6], DONT_FRAGMENT);
        Ok(())
    }

    #[tokio::test]
    async fn oversize_ipv4_send_leaves_as_one_packet_with_df_clear() -> TestResult {
        let (handle, mut source, sink) = fragmenting_stack(true);
        let mut incoming = handle.incoming_udp();
        let pkt = sample_udp_pkt([10, 0, 0, 2], [10, 8, 0, 1], 12345, 53, &[0])?;
        sink.send(PacketBuf::from_packet(&pkt), PeerId::new(1))
            .await?;
        let flow = next_flow(&mut incoming).await?;
        let payload: Vec<u8> = (0..=250u8).cycle().take(3000).collect();
        flow.send(&payload).await?;

        let packet = timeout(WAIT, source.recv()).await??;
        assert_eq!(packet.len(), 20 + 8 + 3000);
        let bytes = packet.as_packet();
        assert_eq!(bytes[6] & DONT_FRAGMENT, 0, "DF clear");
        assert_eq!(bytes[6..8], [0, 0], "no MF, offset zero");
        assert_eq!(
            ipv4_header_checksum(&bytes[..20]).to_be_bytes(),
            bytes[10..12],
            "header checksum matches"
        );
        let ip = IpPacket::parse(bytes)?;
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (ip.src(), ip.dst()) else {
            return Err("IPv4 expected".into());
        };
        assert_eq!(
            transport_checksum_v4(src, dst, protocol::UDP, ip.payload()),
            0,
            "UDP checksum must verify"
        );
        let got = parse_udp(packet).ok_or("reply must parse")?;
        assert_eq!(got.payload.as_ref(), payload.as_slice());

        // A datagram that fits still sets DF.
        flow.send(b"small").await?;
        let packet = timeout(WAIT, source.recv()).await??;
        assert_eq!(packet.as_packet()[6], DONT_FRAGMENT);
        Ok(())
    }

    #[tokio::test]
    async fn oversize_send_fails_for_ipv6_and_above_the_ipv4_length_limit() -> TestResult {
        let (handle, _source, _sink) = fragmenting_stack(true);
        let v6 = handle.bind_udp("[fd00::1]:53".parse()?).await?;
        let error = v6
            .send_to(&[1; 3000], "[fd00::2]:5353".parse()?)
            .await
            .err()
            .ok_or("IPv6 oversize send must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let v4 = handle.bind_udp("10.8.0.1:53".parse()?).await?;
        let remote: SocketAddr = "10.0.0.2:5353".parse()?;
        v4.send_to(&vec![1; 65_535 - 28], remote).await?;
        let error = v4
            .send_to(&vec![1; 65_535 - 27], remote)
            .await
            .err()
            .ok_or("a packet above 65 535 bytes must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    /// A stack at 10.8.0.1 plus its sink/source.
    fn stack() -> (
        crate::NetStackHandle,
        crate::NetStackSource,
        crate::NetStackSink,
    ) {
        let config = NetStackConfig::new(vec![(IpAddr::from([10, 8, 0, 1]), 24)], 1420);
        let (stack, handle) = NetStack::new(config);
        let (source, sink) = stack.split();
        (handle, source, sink)
    }

    async fn next_flow(
        incoming: &mut (impl futures_core::Stream<Item = UdpFlow> + Unpin),
    ) -> Result<UdpFlow, Box<dyn Error>> {
        let flow = timeout(
            WAIT,
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut *incoming).poll_next(cx)),
        )
        .await?;
        Ok(flow.ok_or("incoming_udp ended")?)
    }

    #[tokio::test]
    async fn dispatch_emits_new_datagram_for_first_tuple() -> TestResult {
        let (handle, _source, sink) = stack();
        let mut incoming = handle.incoming_udp();
        let pkt = sample_udp_pkt([10, 0, 0, 2], [10, 8, 0, 1], 12345, 53, &[1, 2, 3, 4])?;
        sink.send(PacketBuf::from_packet(&pkt), PeerId::new(1))
            .await?;

        let mut flow = next_flow(&mut incoming).await?;
        assert_eq!(flow.peer_addr(), "10.0.0.2:12345".parse::<SocketAddr>()?);
        assert_eq!(flow.local_addr(), "10.8.0.1:53".parse::<SocketAddr>()?);
        let first = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
        assert_eq!(first.as_ref(), &[1u8, 2, 3, 4]);
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_fans_subsequent_datagrams_into_existing_flow() -> TestResult {
        let (handle, _source, sink) = stack();
        let mut incoming = handle.incoming_udp();
        for b in [1u8, 2, 3] {
            let pkt = sample_udp_pkt([10, 0, 0, 2], [10, 8, 0, 1], 12345, 53, &[b])?;
            sink.send(PacketBuf::from_packet(&pkt), PeerId::new(1))
                .await?;
        }

        let mut flow = next_flow(&mut incoming).await?;
        for b in [1u8, 2, 3] {
            let got = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
            assert_eq!(got.as_ref(), &[b]);
        }
        // Same tuple: no second flow.
        assert!(
            timeout(Duration::from_millis(50), next_flow(&mut incoming))
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_wraps_reply_payload_into_ip_udp_packet() -> TestResult {
        let (handle, mut source, sink) = stack();
        let mut incoming = handle.incoming_udp();
        let src: SocketAddr = "10.0.0.2:12345".parse()?;
        let dst: SocketAddr = "10.8.0.1:53".parse()?;
        let pkt = sample_udp_pkt([10, 0, 0, 2], [10, 8, 0, 1], 12345, 53, &[0])?;
        sink.send(PacketBuf::from_packet(&pkt), PeerId::new(1))
            .await?;

        let flow = next_flow(&mut incoming).await?;
        flow.reply_handle().send(b"pong").await?;

        let reply = timeout(WAIT, source.recv()).await??;
        let got = parse_udp(reply).ok_or("reply must parse")?;
        assert_eq!(got.src, dst); // swapped
        assert_eq!(got.dst, src);
        assert_eq!(got.payload.as_ref(), b"pong");
        Ok(())
    }
}
