use std::future::Future;

use super::*;
use crate::Ownership;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
/// Next header of an IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;

/// An IPv4 or IPv6 packet from `src` to `dst` carrying `payload` as protocol `proto`.
pub(super) fn ip(src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20 + payload.len();
            let mut pkt = vec![0u8; 20];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&u16::try_from(total).unwrap_or(0).to_be_bytes());
            pkt[8] = 64;
            pkt[9] = proto;
            pkt[12..16].copy_from_slice(&src.octets());
            pkt[16..20].copy_from_slice(&dst.octets());
            pkt.extend_from_slice(payload);
            pkt
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pkt = vec![0u8; 40];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&u16::try_from(payload.len()).unwrap_or(0).to_be_bytes());
            pkt[6] = proto;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&src.octets());
            pkt[24..40].copy_from_slice(&dst.octets());
            pkt.extend_from_slice(payload);
            pkt
        }
        _ => Vec::new(),
    }
}

/// A TCP segment with `flags` and no payload (checksums are not checked by `owns`).
fn tcp_packet(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
    let mut segment = vec![0u8; 20];
    segment[0..2].copy_from_slice(&src.port().to_be_bytes());
    segment[2..4].copy_from_slice(&dst.port().to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = flags;
    ip(src.ip(), dst.ip(), protocol::TCP, &segment)
}

fn udp_packet(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    build_udp(src, dst, b"x").map_or_else(Vec::new, |packet| packet.as_packet().to_vec())
}

/// An ICMP message (IPv4 or IPv6) of `icmp_type` quoting `quoted`.
fn icmp_packet(src: IpAddr, dst: IpAddr, icmp_type: u8, quoted: &[u8]) -> Vec<u8> {
    let mut message = vec![icmp_type, 0, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(quoted);
    let proto = if src.is_ipv4() {
        protocol::ICMP
    } else {
        protocol::ICMPV6
    };
    ip(src, dst, proto, &message)
}

/// Polls `future` once, so it runs up to its first wait.
fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

/// Waits until `handle` classifies `packet` as `expected`.
async fn until_owns(handle: &NetStackHandle, packet: &[u8], expected: Ownership) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while handle.owns(packet) != expected {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("owns should become {expected:?}"))?;
    Ok(())
}

#[tokio::test]
async fn inbound_connection_is_flow_from_its_syn_ack_until_closed() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 9, 2, 1);
    let client_ip = Ipv4Addr::new(10, 9, 2, 2);
    let server = SocketAddr::new(server_ip.into(), 80);
    let client = SocketAddr::new(client_ip.into(), 49_300);
    let (handle, mut peer) = RawPeer::start(config(server_ip), client_ip, 11);
    let mut incoming = handle.incoming_tcp();
    let established = tcp_packet(client, server, ACK);
    assert_eq!(handle.owns(&established), Ownership::None);
    assert_eq!(
        handle.owns(&tcp_packet(client, server, SYN)),
        Ownership::Listener
    );

    // The client's SYN goes in; the tuple is registered before the SYN-ACK leaves.
    let socket = peer.connect(server_ip, 80, client.port())?;
    peer.pump_once().await;
    let syn_ack = timeout(WAIT, peer.source.rx.recv())
        .await?
        .ok_or("the stack should answer the SYN")?;
    assert_eq!(handle.owns(&established), Ownership::Flow);
    peer.device.inject(syn_ack);

    let mut conn = None;
    for _ in 0..40 {
        peer.pump(2).await;
        conn = try_next(&mut incoming);
        if conn.is_some() {
            break;
        }
    }
    let conn = conn.ok_or("TCP handshake should complete")?;
    assert_eq!(handle.owns(&established), Ownership::Flow);
    // A retransmitted SYN of the tuple is the connection's, not a new one.
    assert_eq!(
        handle.owns(&tcp_packet(client, server, SYN)),
        Ownership::Flow
    );

    // Foreign packets: another remote port, another stack address, another protocol, a
    // SYN-ACK nobody waits for.
    let other_port = SocketAddr::new(client_ip.into(), 49_301);
    assert_eq!(
        handle.owns(&tcp_packet(other_port, server, ACK)),
        Ownership::None
    );
    assert_eq!(
        handle.owns(&tcp_packet(other_port, server, SYN)),
        Ownership::Listener
    );
    let elsewhere = SocketAddr::new(Ipv4Addr::new(10, 9, 2, 9).into(), 80);
    assert_eq!(
        handle.owns(&tcp_packet(client, elsewhere, ACK)),
        Ownership::None
    );
    assert_eq!(
        handle.owns(&tcp_packet(client, elsewhere, SYN)),
        Ownership::None
    );
    assert_eq!(
        handle.owns(&ip(client.ip(), server.ip(), 47, &[0; 8])),
        Ownership::None
    );
    assert_eq!(
        handle.owns(&tcp_packet(other_port, server, SYN | ACK)),
        Ownership::None
    );

    // The client resets: the connection is released and its tuple with it.
    peer.socket(socket).abort();
    peer.pump(4).await;
    timeout(Duration::from_secs(5), conn.terminated()).await?;
    until_owns(&handle, &established, Ownership::None).await?;
    assert_eq!(
        handle.owns(&tcp_packet(client, server, SYN)),
        Ownership::Listener
    );
    Ok(())
}

#[tokio::test]
async fn connect_from_is_flow_before_its_syn_leaves() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 3, 1);
    let local = SocketAddr::new(local_ip.into(), 40_000);
    let remote: SocketAddr = "10.9.3.2:443".parse()?;
    let (stack, handle) = NetStack::new(config(local_ip));
    let (mut source, _sink) = stack.split();
    let syn_ack = tcp_packet(remote, local, SYN | ACK);
    assert_eq!(handle.owns(&syn_ack), Ownership::None);

    // Polled once, the connect has queued its command; the driver has not run yet.
    let mut connect = Box::pin(handle.connect_tcp_from(local.port(), remote));
    assert!(poll_once(&mut connect).is_pending());
    assert!(source.rx.try_recv().is_err(), "no SYN has left yet");
    assert_eq!(handle.owns(&syn_ack), Ownership::Flow);
    assert_eq!(
        handle.owns(&tcp_packet(remote, local, RST | ACK)),
        Ownership::Flow
    );

    let syn = timeout(WAIT, source.recv()).await??;
    assert_eq!(syn.as_packet()[9], protocol::TCP);
    assert_eq!(handle.owns(&syn_ack), Ownership::Flow);

    // An abandoned connect is aborted and unregistered.
    drop(connect);
    until_owns(&handle, &syn_ack, Ownership::None).await?;
    Ok(())
}

#[tokio::test]
async fn ephemeral_connect_is_flow_when_its_syn_leaves() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 4, 1);
    let remote: SocketAddr = "10.9.4.2:443".parse()?;
    let (stack, handle) = NetStack::new(config(local_ip));
    let (mut source, _sink) = stack.split();
    let mut connect = Box::pin(handle.connect_tcp(remote));
    assert!(poll_once(&mut connect).is_pending());
    let syn = timeout(WAIT, source.recv()).await??;
    let bytes = syn.as_packet();
    let local = SocketAddr::new(local_ip.into(), u16::from_be_bytes([bytes[20], bytes[21]]));
    let syn_ack = tcp_packet(remote, local, SYN | ACK);
    assert_eq!(handle.owns(&syn_ack), Ownership::Flow);
    let other_remote = SocketAddr::new(remote.ip(), 444);
    assert_eq!(
        handle.owns(&tcp_packet(other_remote, local, SYN | ACK)),
        Ownership::None
    );
    drop(connect);
    until_owns(&handle, &syn_ack, Ownership::None).await?;
    Ok(())
}

#[tokio::test]
async fn bound_udp_socket_is_flow_for_any_remote_until_dropped() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 5, 1);
    let (stack, handle) = NetStack::new(config(local_ip));
    let (_source, _sink) = stack.split();
    let bound = SocketAddr::new(local_ip.into(), 5353);
    let any_port: SocketAddr = "0.0.0.0:5354".parse()?;
    let remote: SocketAddr = "10.9.5.2:1000".parse()?;
    let other_remote: SocketAddr = "10.9.5.3:2000".parse()?;
    assert_eq!(handle.owns(&udp_packet(remote, bound)), Ownership::Listener);

    let socket = handle.bind_udp(bound).await?;
    let wildcard = handle.bind_udp(any_port).await?;
    let to_wildcard = SocketAddr::new(local_ip.into(), 5354);
    for from in [remote, other_remote] {
        assert_eq!(handle.owns(&udp_packet(from, bound)), Ownership::Flow);
        assert_eq!(handle.owns(&udp_packet(from, to_wildcard)), Ownership::Flow);
    }
    let unbound = SocketAddr::new(local_ip.into(), 5355);
    assert_eq!(
        handle.owns(&udp_packet(remote, unbound)),
        Ownership::Listener
    );
    let elsewhere: SocketAddr = "10.9.5.9:5353".parse()?;
    assert_eq!(handle.owns(&udp_packet(remote, elsewhere)), Ownership::None);

    drop(socket);
    drop(wildcard);
    assert_eq!(handle.owns(&udp_packet(remote, bound)), Ownership::Listener);
    assert_eq!(
        handle.owns(&udp_packet(remote, to_wildcard)),
        Ownership::Listener
    );
    // The address can be bound again and is owned again.
    let _socket = handle.bind_udp(bound).await?;
    assert_eq!(handle.owns(&udp_packet(remote, bound)), Ownership::Flow);
    Ok(())
}

#[tokio::test]
async fn udp_flow_is_flow_until_dropped() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 6, 1);
    let local = SocketAddr::new(local_ip.into(), 53);
    let remote: SocketAddr = "10.9.6.2:1000".parse()?;
    let (stack, handle) = NetStack::new(config(local_ip));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let datagram = udp_packet(remote, local);
    assert_eq!(handle.owns(&datagram), Ownership::Listener);

    sink.send(PacketBuf::from_packet(&datagram), PeerId::new(0))
        .await?;
    let flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert_eq!(handle.owns(&datagram), Ownership::Flow);
    let other_remote = SocketAddr::new(remote.ip(), 1001);
    assert_eq!(
        handle.owns(&udp_packet(other_remote, local)),
        Ownership::Listener
    );
    drop(flow);
    assert_eq!(handle.owns(&datagram), Ownership::Listener);
    Ok(())
}

#[tokio::test]
async fn icmp_errors_quoting_an_owned_tuple_are_flow() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 7, 1);
    let local_v6: Ipv6Addr = "fd00:9:7::1".parse()?;
    let config = NetStackConfig::new(
        vec![(IpAddr::V4(local_ip), 32), (IpAddr::V6(local_v6), 128)],
        1360,
    );
    let (stack, handle) = NetStack::new(config);
    let (_source, _sink) = stack.split();
    let router: IpAddr = "10.9.7.254".parse()?;
    let router_v6: IpAddr = "fd00:9:7::fe".parse()?;

    // IPv4: a bound UDP socket's datagram to a remote, a TCP connect.
    let bound = SocketAddr::new(local_ip.into(), 5353);
    let _socket = handle.bind_udp(bound).await?;
    let remote: SocketAddr = "10.9.7.2:53".parse()?;
    let sent = udp_packet(bound, remote);
    for icmp_type in [3, 11, 12] {
        let error = icmp_packet(router, local_ip.into(), icmp_type, &sent);
        assert_eq!(
            handle.owns(&error),
            Ownership::Flow,
            "ICMP type {icmp_type}"
        );
    }
    let tcp_local = SocketAddr::new(local_ip.into(), 40_001);
    let tcp_remote: SocketAddr = "10.9.7.3:443".parse()?;
    let mut connect = Box::pin(handle.connect_tcp_from(tcp_local.port(), tcp_remote));
    assert!(poll_once(&mut connect).is_pending());
    let quoted = tcp_packet(tcp_local, tcp_remote, SYN);
    // Quotes are usually truncated after the first 8 bytes of the transport header.
    let error = icmp_packet(router, local_ip.into(), 3, &quoted[..28]);
    assert_eq!(handle.owns(&error), Ownership::Flow);

    // Not owned: an unrelated quoted tuple, the inbound direction, a non-error type, a
    // non-first fragment and an error to another address.
    let unrelated = udp_packet(SocketAddr::new(local_ip.into(), 6000), remote);
    let inbound = udp_packet(remote, bound);
    for quoted in [&unrelated, &inbound] {
        let error = icmp_packet(router, local_ip.into(), 3, quoted);
        assert_eq!(handle.owns(&error), Ownership::None);
    }
    let echo = icmp_packet(router, local_ip.into(), 8, &sent);
    assert_eq!(handle.owns(&echo), Ownership::None);
    let mut fragment = sent.clone();
    fragment[7] = 1;
    let error = icmp_packet(router, local_ip.into(), 3, &fragment);
    assert_eq!(handle.owns(&error), Ownership::None);
    let error = icmp_packet(router, "10.9.7.9".parse()?, 3, &sent);
    assert_eq!(handle.owns(&error), Ownership::None);

    // IPv6: a TCP connect and a bound UDP socket.
    let tcp_local_v6 = SocketAddr::new(local_v6.into(), 40_002);
    let tcp_remote_v6: SocketAddr = "[fd00:9:7::2]:443".parse()?;
    let mut connect_v6 = Box::pin(handle.connect_tcp_from(tcp_local_v6.port(), tcp_remote_v6));
    assert!(poll_once(&mut connect_v6).is_pending());
    let quoted = tcp_packet(tcp_local_v6, tcp_remote_v6, SYN);
    for icmp_type in [1, 2, 3, 4] {
        let error = icmp_packet(router_v6, local_v6.into(), icmp_type, &quoted[..48]);
        assert_eq!(
            handle.owns(&error),
            Ownership::Flow,
            "ICMPv6 type {icmp_type}"
        );
    }
    let echo = icmp_packet(router_v6, local_v6.into(), 128, &quoted);
    assert_eq!(handle.owns(&echo), Ownership::None);
    let bound_v6 = SocketAddr::new(local_v6.into(), 5353);
    let _socket_v6 = handle.bind_udp(bound_v6).await?;
    let sent_v6 = udp_packet(bound_v6, "[fd00:9:7::2]:53".parse()?);
    let error = icmp_packet(router_v6, local_v6.into(), 1, &sent_v6);
    assert_eq!(handle.owns(&error), Ownership::Flow);
    let unrelated_v6 = udp_packet(
        SocketAddr::new(local_v6.into(), 6000),
        "[fd00:9:7::2]:53".parse()?,
    );
    let error = icmp_packet(router_v6, local_v6.into(), 1, &unrelated_v6);
    assert_eq!(handle.owns(&error), Ownership::None);
    Ok(())
}

#[tokio::test]
async fn fragments_and_malformed_packets_are_none() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 8, 1);
    let local_v6: Ipv6Addr = "fd00:9:8::1".parse()?;
    let config = NetStackConfig::new(
        vec![(IpAddr::V4(local_ip), 32), (IpAddr::V6(local_v6), 128)],
        1360,
    );
    let (stack, handle) = NetStack::new(config);
    let (_source, _sink) = stack.split();
    let bound = SocketAddr::new(local_ip.into(), 5353);
    let _socket = handle.bind_udp(bound).await?;
    let remote: SocketAddr = "10.9.8.2:1000".parse()?;
    let datagram = udp_packet(remote, bound);
    assert_eq!(handle.owns(&datagram), Ownership::Flow);

    let mut first = datagram.clone();
    first[6] = 0x20;
    assert_eq!(handle.owns(&first), Ownership::None, "first fragment");
    let mut later = datagram.clone();
    later[7] = 1;
    assert_eq!(handle.owns(&later), Ownership::None, "non-first fragment");

    let remote_v6: SocketAddr = "[fd00:9:8::2]:1000".parse()?;
    let local_v6_addr = SocketAddr::new(local_v6.into(), 5353);
    let segment = &udp_packet(remote_v6, local_v6_addr)[40..];
    let mut fragmented = vec![protocol::UDP, 0, 0, 1, 0, 0, 0, 1];
    fragmented.extend_from_slice(segment);
    let packet = ip(remote_v6.ip(), local_v6.into(), IPV6_FRAGMENT, &fragmented);
    assert_eq!(handle.owns(&packet), Ownership::None, "IPv6 fragment");

    for malformed in [&[][..], &[0x45][..], &datagram[..24], &[0x70; 40][..]] {
        assert_eq!(handle.owns(malformed), Ownership::None);
    }
    let mut short_tcp = tcp_packet(remote, bound, ACK);
    short_tcp.truncate(30);
    short_tcp[2..4].copy_from_slice(&30u16.to_be_bytes());
    assert_eq!(handle.owns(&short_tcp), Ownership::None);
    Ok(())
}

#[tokio::test]
async fn stopped_stack_owns_nothing() -> TestResult {
    let local_ip = Ipv4Addr::new(10, 9, 9, 1);
    let (stack, handle) = NetStack::new(config(local_ip));
    let (source, sink) = stack.split();
    let bound = SocketAddr::new(local_ip.into(), 5353);
    let _socket = handle.bind_udp(bound).await?;
    let datagram = udp_packet("10.9.9.2:1000".parse()?, bound);
    assert_eq!(handle.owns(&datagram), Ownership::Flow);
    drop((source, sink));
    until_owns(&handle, &datagram, Ownership::None).await?;
    Ok(())
}
