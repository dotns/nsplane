//! Transparent mode: TCP and UDP to destinations that are not the stack's addresses.

use nsplane_packet::reassembly::ReassemblyConfig;

use super::ownership::{tcp_packet, udp_packet};
use super::reassembly::fragments_v4;
use super::*;
use crate::{Ownership, TransparentConfig};

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// The stack's own address in these tests.
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 6, 0, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 6, 0, 2);

/// A stack at [`LOCAL`] terminating `prefixes` (no transparent mode with `None`).
fn transparent(prefixes: Option<Vec<(IpAddr, u8)>>) -> NetStackConfig {
    NetStackConfig {
        transparent: prefixes.map(|prefixes| TransparentConfig {
            prefixes,
            ..Default::default()
        }),
        ..config(LOCAL)
    }
}

fn documentation_prefixes() -> Vec<(IpAddr, u8)> {
    vec![
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 24),
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        ),
    ]
}

fn syn(src: &str, dst: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(tcp_packet(src.parse()?, dst.parse()?, SYN))
}

fn udp(src: &str, dst: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(udp_packet(src.parse()?, dst.parse()?))
}

#[test]
fn classify_with_transparent_off_and_on() -> TestResult {
    let syn_v4 = syn("10.6.0.2:40000", "192.0.2.10:443")?;
    let udp_v4 = udp("10.6.0.2:40000", "192.0.2.10:53")?;
    let syn_v6 = syn("[fd00::2]:40000", "[2001:db8::10]:443")?;
    let udp_v6 = udp("[fd00::2]:40000", "[2001:db8::10]:53")?;
    let outside_v4 = udp("10.6.0.2:40000", "198.51.100.7:53")?;
    let outside_v6 = syn("[fd00::2]:40000", "[2001:db9::10]:443")?;
    let own = udp("10.6.0.2:40000", "10.6.0.1:53")?;
    let tcp = Ok(Class::Tcp {
        dst_port: 443,
        syn: true,
    });

    let off = Settings::new(transparent(None));
    for packet in [&syn_v4, &udp_v4, &syn_v6, &udp_v6, &outside_v4, &outside_v6] {
        assert_eq!(classify(packet, &off), Err(Reject::NoAddress));
    }
    assert_eq!(classify(&own, &off), Ok(Class::Udp));

    let on = Settings::new(transparent(Some(documentation_prefixes())));
    assert_eq!(classify(&syn_v4, &on), tcp);
    assert_eq!(classify(&udp_v4, &on), Ok(Class::Udp));
    assert_eq!(classify(&syn_v6, &on), tcp);
    assert_eq!(classify(&udp_v6, &on), Ok(Class::Udp));
    assert_eq!(classify(&outside_v4, &on), Err(Reject::Prefix));
    assert_eq!(classify(&outside_v6, &on), Err(Reject::Prefix));
    // The stack's own address stays its own outside the prefixes.
    assert_eq!(classify(&own, &on), Ok(Class::Udp));

    let all = Settings::new(transparent(Some(Vec::new())));
    for packet in [&syn_v4, &syn_v6, &outside_v6] {
        assert_eq!(classify(packet, &all), tcp);
    }
    for packet in [&udp_v4, &udp_v6, &outside_v4, &own] {
        assert_eq!(classify(packet, &all), Ok(Class::Udp));
    }
    Ok(())
}

#[test]
fn prefixes_ignore_host_bits_and_clamp_their_length() -> TestResult {
    let settings = Settings::new(transparent(Some(vec![
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)), 25),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), 200),
        (IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 0),
    ])));
    let prefixes = &settings.transparent.as_ref().ok_or("transparent")?.prefixes;
    assert!(prefixes.contains("192.0.2.128".parse()?));
    assert!(prefixes.contains("::1".parse()?));
    assert!(!prefixes.contains("::2".parse()?));
    // A /0 covers its whole family and nothing of the other.
    assert!(prefixes.contains("198.51.100.7".parse()?));
    let v4_only = Settings::new(transparent(Some(vec![(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)),
        25,
    )])));
    let prefixes = &v4_only.transparent.as_ref().ok_or("transparent")?.prefixes;
    assert!(prefixes.contains("192.0.2.255".parse()?));
    assert!(!prefixes.contains("192.0.2.127".parse()?));
    assert!(!prefixes.contains("2001:db8::1".parse()?));
    Ok(())
}

#[tokio::test]
async fn owns_foreign_destinations_only_in_transparent_mode() -> TestResult {
    let reassembly = Some(ReassemblyConfig::default());
    let syn_v4 = syn("10.6.0.2:40000", "192.0.2.10:443")?;
    let syn_v6 = syn("[fd00::2]:40000", "[2001:db8::10]:443")?;
    let ack_v4 = tcp_packet("10.6.0.2:40000".parse()?, "192.0.2.10:443".parse()?, ACK);
    let udp_v4 = udp("10.6.0.2:40000", "192.0.2.10:53")?;
    let outside = syn("10.6.0.2:40000", "198.51.100.7:443")?;
    let mut fragment = udp_v4.clone();
    fragment[6] = 0x20; // More fragments.
    let mut later = udp_v4.clone();
    later[7] = 1;

    let (stack, off) = NetStack::new(NetStackConfig {
        reassembly: reassembly.clone(),
        ..transparent(None)
    });
    let _halves = stack.split();
    for packet in [
        &syn_v4, &syn_v6, &ack_v4, &udp_v4, &outside, &fragment, &later,
    ] {
        assert_eq!(off.owns(packet), Ownership::None);
    }

    let (stack, on) = NetStack::new(NetStackConfig {
        reassembly,
        ..transparent(Some(documentation_prefixes()))
    });
    let _halves = stack.split();
    assert_eq!(on.owns(&syn_v4), Ownership::Listener);
    assert_eq!(on.owns(&syn_v6), Ownership::Listener);
    assert_eq!(on.owns(&udp_v4), Ownership::Listener);
    assert_eq!(on.owns(&fragment), Ownership::Listener, "first fragment");
    assert_eq!(on.owns(&later), Ownership::Listener, "later fragment");
    assert_eq!(on.owns(&ack_v4), Ownership::None);
    assert_eq!(on.owns(&outside), Ownership::None);
    Ok(())
}

#[tokio::test]
async fn tcp_and_udp_to_foreign_destinations_are_terminated() -> TestResult {
    let config = transparent(Some(documentation_prefixes()));
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 21);
    let mut incoming_tcp = handle.incoming_tcp();
    let mut incoming_udp = handle.incoming_udp();
    let dialed: SocketAddr = "192.0.2.10:443".parse()?;

    let socket = peer.connect(Ipv4Addr::new(192, 0, 2, 10), 443, 40_000)?;
    let mut conn = None;
    for _ in 0..40 {
        peer.pump(2).await;
        conn = try_next(&mut incoming_tcp);
        if conn.is_some() {
            break;
        }
    }
    let conn = conn.ok_or("TCP handshake should complete")?;
    assert_eq!(conn.local_addr(), dialed);
    assert_eq!(conn.peer_addr(), SocketAddr::new(CLIENT.into(), 40_000));
    assert_eq!(peer.state(socket), tcp::State::Established);
    let established = tcp_packet(conn.peer_addr(), dialed, ACK);
    assert_eq!(handle.owns(&established), Ownership::Flow);

    let flow_dst: SocketAddr = "192.0.2.7:53".parse()?;
    let client: SocketAddr = "10.6.0.2:5353".parse()?;
    let datagram = build_udp(client, flow_dst, b"query").ok_or("build")?;
    peer.sink.send(datagram, PeerId::new(0)).await?;
    let flow = timeout(WAIT, next(&mut incoming_udp))
        .await?
        .ok_or("no flow")?;
    assert_eq!(flow.local_addr(), flow_dst);
    assert_eq!(flow.peer_addr(), client);
    assert_eq!(handle.owns(&udp_packet(client, flow_dst)), Ownership::Flow);
    flow.send(b"answer").await?;
    let reply = loop {
        let packet = timeout(WAIT, peer.source.rx.recv())
            .await?
            .ok_or("no reply")?;
        if let Some(datagram) = udp::parse_udp(packet) {
            break datagram;
        }
    };
    assert_eq!((reply.src, reply.dst), (flow_dst, client));
    assert_eq!(&reply.payload[..], b"answer");

    let outside = build_udp(client, "198.51.100.7:53".parse()?, b"x").ok_or("build")?;
    peer.sink.send(outside, PeerId::new(0)).await?;
    timeout(WAIT, async {
        while handle.stats().rejected_prefix == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let stats = handle.stats();
    assert_eq!(stats.accepted, 2, "one SYN and one first datagram");
    assert_eq!(stats.rejected_prefix, 1);
    assert_eq!(stats.no_address, 1);
    Ok(())
}

#[tokio::test]
async fn ipv6_tcp_to_a_foreign_destination_is_terminated() -> TestResult {
    let client: IpAddr = "fd00::2".parse()?;
    let config = NetStackConfig {
        transparent: Some(TransparentConfig::default()),
        ..NetStackConfig::new(vec![(IpAddr::V6("fd00::1".parse()?), 128)], 1360)
    };
    let (handle, mut peer) = RawPeer::start_at(config, client, 22);
    let mut incoming = handle.incoming_tcp();
    let dialed: SocketAddr = "[2001:db8::10]:443".parse()?;
    peer.connect(dialed.ip(), dialed.port(), 40_001)?;
    for _ in 0..40 {
        peer.pump(2).await;
        if let Some(conn) = try_next(&mut incoming) {
            assert_eq!(conn.local_addr(), dialed);
            assert_eq!(conn.peer_addr(), SocketAddr::new(client, 40_001));
            return Ok(());
        }
    }
    Err("TCP handshake should complete".into())
}

#[tokio::test]
async fn without_transparent_mode_foreign_destinations_count_as_no_address() -> TestResult {
    let (handle, mut peer) = RawPeer::start(transparent(None), CLIENT, 23);
    let packet = PacketBuf::from_packet(&syn("10.6.0.2:40000", "192.0.2.10:443")?);
    peer.sink.send(packet, PeerId::new(0)).await?;
    let packet = PacketBuf::from_packet(&udp("10.6.0.2:40000", "192.0.2.10:53")?);
    peer.sink.send(packet, PeerId::new(0)).await?;
    timeout(WAIT, async {
        while handle.stats().no_address < 2 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    peer.pump(2).await;
    assert!(peer.source.rx.try_recv().is_err(), "nothing is answered");
    let stats = handle.stats();
    assert_eq!((stats.accepted, stats.rejected_prefix), (0, 0));
    Ok(())
}

#[tokio::test]
async fn fragments_to_a_foreign_destination_are_reassembled() -> TestResult {
    let config = NetStackConfig {
        reassembly: Some(ReassemblyConfig::default()),
        ..transparent(Some(documentation_prefixes()))
    };
    let (handle, peer) = RawPeer::start(config, CLIENT, 24);
    let mut incoming = handle.incoming_udp();
    let dst: SocketAddr = "192.0.2.20:5000".parse()?;
    let src: SocketAddr = "10.6.0.2:6000".parse()?;
    let payload = vec![7u8; 1000];
    let whole = build_udp(src, dst, &payload).ok_or("build")?;
    for fragment in fragments_v4(whole.as_packet(), 512, 9) {
        peer.sink
            .send(PacketBuf::from_packet(&fragment), PeerId::new(0))
            .await?;
    }
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert_eq!(flow.local_addr(), dst);
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&payload[..])
    );
    assert_eq!(handle.stats().reassembled, 1);
    Ok(())
}

#[tokio::test]
async fn a_syn_beyond_max_connections_is_reset_from_its_destination() -> TestResult {
    let config = NetStackConfig {
        transparent: Some(TransparentConfig {
            prefixes: documentation_prefixes(),
            max_connections: Some(1),
            ..Default::default()
        }),
        ..config(LOCAL)
    };
    let (handle, mut peer) = RawPeer::start(config, CLIENT, 25);
    let mut incoming = handle.incoming_tcp();
    peer.connect(Ipv4Addr::new(192, 0, 2, 10), 443, 40_000)?;
    let mut first = None;
    for _ in 0..40 {
        peer.pump(2).await;
        first = try_next(&mut incoming);
        if first.is_some() {
            break;
        }
    }
    let _first = first.ok_or("TCP handshake should complete")?;

    // The second connection's SYN, by hand so the answer can be read.
    let second = peer.connect(Ipv4Addr::new(192, 0, 2, 11), 443, 40_001)?;
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let syn = peer.device.drain_tx().next().ok_or("no SYN")?;
    let syn_seq = u32::from_be_bytes(syn.as_packet()[24..28].try_into()?);
    peer.sink.send(syn, PeerId::new(0)).await?;
    let reset = timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("no answer")?;
    let (src, dst) = tcp_tuple(reset.as_packet()).ok_or("not TCP")?;
    assert_eq!(src, "192.0.2.11:443".parse()?);
    assert_eq!(dst, SocketAddr::new(CLIENT.into(), 40_001));
    let segment = tcp_segment(reset.as_packet()).ok_or("not TCP")?;
    assert_eq!(segment[13], RST | ACK);
    assert_eq!(
        u32::from_be_bytes(segment[8..12].try_into()?),
        syn_seq.wrapping_add(1)
    );
    // The client takes it: checksums and acknowledgment hold.
    peer.device.inject(reset);
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    assert_eq!(peer.state(second), tcp::State::Closed);

    let stats = handle.stats();
    assert_eq!(stats.rejected_connection_limit, 1);
    assert_eq!(stats.accepted, 1);
    assert!(try_next(&mut incoming).is_none());
    Ok(())
}
