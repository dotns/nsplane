use super::*;
use nsplane_packet::{Ecn, HEADROOM, MAX_BATCH};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::time::timeout;

mod icmp;
mod offload;
mod side;

const DATAGRAM: &[u8] = b"wireguard datagram";

/// Bound with offload, then without.
const OFFLOAD: [bool; 2] = [true, false];

fn bind(id: u16, addr: &str) -> UdpTransport {
    UdpTransport::bind(TransportId::new(id), addr.parse().unwrap()).unwrap()
}

fn bind_with(id: u16, addr: &str, offload: bool) -> UdpTransport {
    UdpTransport::bind_with_offload(TransportId::new(id), addr.parse().unwrap(), offload).unwrap()
}

fn path_to(addr: SocketAddr, ecn: Ecn) -> Path {
    Path {
        transport: TransportId::new(0),
        addr,
        ecn,
    }
}

/// The address peers see for `transport` when it sends over `ip`.
fn seen_as(transport: &UdpTransport, ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), transport.local_addr().port())
}

/// Receives one datagram into a buffer whose headroom is filled with a marker.
async fn recv(transport: &UdpTransport, capacity: usize) -> (PacketBuf, Path) {
    let mut buf = PacketBuf::with_capacity(capacity);
    buf.with_headroom_mut().fill(0xAA);
    let (len, path) = timeout(Duration::from_secs(5), transport.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, buf.len());
    assert!(
        buf.with_headroom_mut()[..HEADROOM]
            .iter()
            .all(|&b| b == 0xAA)
    );
    (buf, path)
}

async fn roundtrip(
    from: &UdpTransport,
    from_addr: SocketAddr,
    to: &UdpTransport,
    to_addr: SocketAddr,
) {
    from.send(DATAGRAM, &path_to(to_addr, Ecn::NotEct))
        .await
        .unwrap();
    let (buf, path) = recv(to, 1500).await;
    assert_eq!(buf.as_packet(), DATAGRAM);
    assert_eq!(path.transport, to.id());
    assert_eq!(path.addr, from_addr);
    assert_eq!(path.ecn, Ecn::NotEct);
}

#[tokio::test]
async fn ipv4_roundtrip() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        assert_eq!(a.id(), TransportId::new(1));
        roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
        roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
    }
}

#[tokio::test]
async fn truncates_into_small_buffer() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        let mut small = PacketBuf::with_capacity(4);
        let capacity = small.capacity();
        assert!(capacity < DATAGRAM.len());
        a.send(DATAGRAM, &path_to(b.local_addr(), Ecn::NotEct))
            .await
            .unwrap();
        small.with_headroom_mut().fill(0xAA);
        let (len, path) = b.recv(&mut small).await.unwrap();
        assert_eq!(len, capacity);
        assert_eq!(small.as_packet(), &DATAGRAM[..capacity]);
        assert!(
            small.with_headroom_mut()[..HEADROOM]
                .iter()
                .all(|&b| b == 0xAA)
        );
        assert_eq!(path.addr, a.local_addr());
    }
}

/// An ICMP port-unreachable for an earlier send must not fail a later receive
/// (Windows reports it as `WSAECONNRESET`).
#[tokio::test]
async fn port_unreachable_does_not_fail_recv() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        let closed = bind(3, "127.0.0.1:0").local_addr();
        a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
            .await
            .unwrap();
        b.send(DATAGRAM, &path_to(a.local_addr(), Ecn::NotEct))
            .await
            .unwrap();
        let (buf, path) = recv(&a, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(path.addr, b.local_addr());
    }
}

#[tokio::test]
async fn ipv6_roundtrip() {
    for offload in OFFLOAD {
        let a = bind_with(1, "[::1]:0", offload);
        let b = bind_with(2, "[::1]:0", offload);
        roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
        roundtrip(&b, b.local_addr(), &a, a.local_addr()).await;
    }
}

#[tokio::test]
async fn dual_stack_unmaps_ipv4_peers() {
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        assert!(dual.local_addr().is_ipv6());
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let v6 = bind_with(3, "[::1]:0", offload);
        roundtrip(&v4, v4.local_addr(), &dual, seen_as(&dual, "127.0.0.1")).await;
        roundtrip(&dual, seen_as(&dual, "127.0.0.1"), &v4, v4.local_addr()).await;
        roundtrip(&v6, v6.local_addr(), &dual, seen_as(&dual, "::1")).await;
        roundtrip(&dual, seen_as(&dual, "::1"), &v6, v6.local_addr()).await;
    }
}

/// A transport on `[::]:port` owns the port for IPv4 too: nobody else binds its IPv4 side
/// while the transport lives.
#[tokio::test]
async fn unspecified_bind_owns_the_ipv4_port() {
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        let port = dual.local_addr().port();
        let err = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }
}

/// A port whose IPv4 side is taken is in use for `[::]:port`, and the failed bind leaves
/// nothing bound.
#[tokio::test]
async fn unspecified_bind_fails_on_a_port_taken_for_ipv4() {
    for offload in OFFLOAD {
        let listener = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = (Ipv6Addr::UNSPECIFIED, port).into();
        let err = UdpTransport::bind_with_offload(TransportId::new(1), addr, offload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
        std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).unwrap();
    }
}

/// A transport on a wildcard address owns every local address of its port: a plain bind of
/// the loopback address on that port, which would take the datagrams sent to it, fails.
#[tokio::test]
async fn wildcard_bind_owns_the_local_addresses_of_the_port() {
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        let port = dual.local_addr().port();
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap_err();
        std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).unwrap_err();

        let v4 = bind_with(2, "0.0.0.0:0", offload);
        let port = v4.local_addr().port();
        std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap_err();
    }
}

/// A port one of whose local addresses another socket holds is in use for `[::]:port`.
#[tokio::test]
async fn unspecified_bind_fails_on_a_port_with_a_taken_local_address() {
    for offload in OFFLOAD {
        for holder in [
            IpAddr::from(Ipv4Addr::LOCALHOST),
            Ipv6Addr::LOCALHOST.into(),
        ] {
            let listener = std::net::UdpSocket::bind((holder, 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let addr = (Ipv6Addr::UNSPECIFIED, port).into();
            let err =
                UdpTransport::bind_with_offload(TransportId::new(1), addr, offload).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{holder}");
        }
    }
}

/// An IPv4-mapped destination leaves a transport on `[::]:port` as IPv4, as the plain
/// IPv4 address does.
#[tokio::test]
async fn dual_stack_sends_to_mapped_destinations() {
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{}", v4.local_addr().port())
            .parse()
            .unwrap();
        dual.send(DATAGRAM, &path_to(mapped, Ecn::NotEct))
            .await
            .unwrap();
        let (buf, path) = recv(&v4, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(path.addr, seen_as(&dual, "127.0.0.1"));

        let batch = batch(mapped, Ecn::NotEct, &train(1200, 3));
        send_all(&dual, &batch).await;
        let received: Vec<_> = recv_batches(&v4, batch.len())
            .await
            .into_iter()
            .flatten()
            .collect();
        check(
            &received,
            &train(1200, 3),
            seen_as(&dual, "127.0.0.1"),
            Ecn::NotEct,
        );
    }
}

/// A transport on `[::]:port` serves IPv4 and IPv6 senders at once: a backlog of one
/// family does not keep the datagrams of the other waiting behind it, and one batch
/// sends to both.
#[tokio::test]
async fn dual_stack_serves_both_families_at_once() {
    const BACKLOG: usize = 64;
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let v6 = bind_with(3, "[::1]:0", offload);
        for (busy, busy_ip, other, other_ip) in [
            (&v4, "127.0.0.1", &v6, "::1"),
            (&v6, "::1", &v4, "127.0.0.1"),
        ] {
            for _ in 0..BACKLOG {
                busy.send(b"backlog", &path_to(seen_as(&dual, busy_ip), Ecn::NotEct))
                    .await
                    .unwrap();
            }
            other
                .send(DATAGRAM, &path_to(seen_as(&dual, other_ip), Ecn::NotEct))
                .await
                .unwrap();
            // Loopback delivers before `send` returns: all of them are queued.
            let mut before = None;
            let mut backlog = 0;
            while backlog < BACKLOG || before.is_none() {
                let (buf, path) = recv(&dual, 1500).await;
                if buf.as_packet() == DATAGRAM {
                    assert_eq!(path.addr, other.local_addr());
                    before = Some(backlog);
                } else {
                    assert_eq!(path.addr, busy.local_addr());
                    backlog += 1;
                }
            }
            // Arrival order across families is not kept by two sockets; the single
            // datagram must not wait for the whole backlog of the other family there.
            if cfg!(windows) {
                assert!(before < Some(BACKLOG / 2), "served after {before:?}");
            }
        }

        let mut both = batch(v4.local_addr(), Ecn::NotEct, &train(1200, 2));
        both.extend(batch(v6.local_addr(), Ecn::NotEct, &train(1200, 2)));
        send_all(&dual, &both).await;
        for (to, ip) in [(&v4, "127.0.0.1"), (&v6, "::1")] {
            let received: Vec<_> = recv_batches(to, 3).await.into_iter().flatten().collect();
            check(&received, &train(1200, 2), seen_as(&dual, ip), Ecn::NotEct);
        }
    }
}

/// The two sockets that stand for `[::]:port` on Windows: both on one port, also when the
/// OS chooses it, and nothing bound when the IPv4 side of the port is taken.
#[test]
fn pair_binds_both_families_on_one_port() {
    let port_of = |socket: &Socket| socket.local_addr().unwrap().as_socket().unwrap().port();
    let (v6, v4) = socket::bind_pair(0).unwrap();
    let v4 = v4.unwrap();
    assert!(v6.only_v6().unwrap());
    assert_eq!(
        v6.local_addr().unwrap().as_socket().unwrap().ip(),
        Ipv6Addr::UNSPECIFIED
    );
    assert_eq!(
        v4.local_addr().unwrap().as_socket().unwrap().ip(),
        Ipv4Addr::UNSPECIFIED
    );
    let port = port_of(&v6);
    assert_ne!(port, 0);
    assert_eq!(port_of(&v4), port);
    drop((v6, v4));
    let (v6, v4) = socket::bind_pair(port).unwrap();
    assert_eq!((port_of(&v6), port_of(&v4.unwrap())), (port, port));
    drop(v6);

    let listener = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let err = socket::bind_pair(port).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).unwrap();
    let v6_listener = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    v6_listener.set_only_v6(true).unwrap();
    let any: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
    v6_listener.bind(&any.into()).unwrap();
    let err = socket::bind_pair(port_of(&v6_listener)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
}

/// Of the two sockets, the IPv4 one sends to IPv4 and IPv4-mapped addresses, unmapped.
#[test]
fn pair_sends_ipv4_and_mapped_destinations_on_the_ipv4_socket() {
    let v4: SocketAddr = "192.0.2.1:51820".parse().unwrap();
    for addr in ["192.0.2.1:51820", "[::ffff:192.0.2.1]:51820"] {
        assert_eq!(socket::ipv4_destination(addr.parse().unwrap()), Some(v4));
    }
    for addr in ["[2001:db8::1]:51820", "[::1]:51820", "[::]:51820"] {
        assert_eq!(socket::ipv4_destination(addr.parse().unwrap()), None);
    }
}

#[tokio::test]
async fn ipv4_socket_rejects_ipv6_destination() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let err = a
            .send(DATAGRAM, &path_to("[::1]:9".parse().unwrap(), Ecn::NotEct))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

/// Sends one datagram per ECN codepoint from `from` to `to` and checks the mark `to`
/// observes.
async fn ecn_marks(from: &UdpTransport, to: &UdpTransport, to_addr: SocketAddr) {
    for ecn in [Ecn::Ect0, Ecn::Ect1, Ecn::Ce, Ecn::NotEct] {
        from.send(DATAGRAM, &path_to(to_addr, ecn)).await.unwrap();
        let (_, path) = recv(to, 1500).await;
        // Marks are sent and received on Linux and Android in both modes.
        let expected = if cfg!(any(target_os = "linux", target_os = "android")) {
            ecn
        } else {
            Ecn::NotEct
        };
        assert_eq!(path.ecn, expected);
    }
}

#[tokio::test]
async fn ecn_ipv4() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        ecn_marks(&a, &b, b.local_addr()).await;
    }
}

#[tokio::test]
async fn ecn_ipv6() {
    for offload in OFFLOAD {
        let a = bind_with(1, "[::1]:0", offload);
        let b = bind_with(2, "[::1]:0", offload);
        ecn_marks(&a, &b, b.local_addr()).await;
    }
}

#[tokio::test]
async fn ecn_dual_stack() {
    for offload in OFFLOAD {
        let dual = bind_with(1, "[::]:0", offload);
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        ecn_marks(&v4, &dual, seen_as(&dual, "127.0.0.1")).await;
        ecn_marks(&dual, &v4, v4.local_addr()).await;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn fwmark() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        a.set_fwmark(0x5157).unwrap();
        assert_eq!(socket2::SockRef::from(&a.socket).mark().unwrap(), 0x5157);
    }
}

/// The socket options of a transport bound to `addr` and of a plain socket bound the
/// same way, as `(name, transport, plain)`. The path MTU discovery mode
/// (`IP_MTU_DISCOVER`, `IPV6_MTU_DISCOVER`) has no safe getter in `nix` or `socket2`;
/// the fragmentation e2e test in `nsplane-e2e` (`offload_udp`) checks its effect.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_options(addr: &str, offload: bool) -> Vec<(&'static str, bool, bool)> {
    use nix::sys::socket::{getsockopt, sockopt};

    let transport = bind_with(1, addr, offload);
    let addr: SocketAddr = addr.parse().unwrap();
    let plain = if addr.ip().is_unspecified() {
        bind_dual_stack(addr).unwrap()
    } else {
        bind_socket(addr).unwrap()
    };
    let socket = socket2::SockRef::from(&transport.socket);
    let mut options = vec![
        (
            "UDP_GRO",
            getsockopt(&transport.socket, sockopt::UdpGroSegment).unwrap(),
            getsockopt(&plain, sockopt::UdpGroSegment).unwrap(),
        ),
        (
            "SO_TIMESTAMPNS",
            getsockopt(&transport.socket, sockopt::ReceiveTimestampns).unwrap(),
            getsockopt(&plain, sockopt::ReceiveTimestampns).unwrap(),
        ),
        (
            "IP_RECVTOS",
            socket.recv_tos_v4().unwrap(),
            plain.recv_tos_v4().unwrap(),
        ),
        (
            "IP_RECVERR",
            getsockopt(&transport.socket, sockopt::Ipv4RecvErr).unwrap(),
            getsockopt(&plain, sockopt::Ipv4RecvErr).unwrap(),
        ),
    ];
    if addr.is_ipv4() {
        options.push((
            "IP_PKTINFO",
            getsockopt(&transport.socket, sockopt::Ipv4PacketInfo).unwrap(),
            getsockopt(&plain, sockopt::Ipv4PacketInfo).unwrap(),
        ));
    } else {
        options.extend([
            (
                "IPV6_DONTFRAG",
                getsockopt(&transport.socket, sockopt::Ipv6DontFrag).unwrap(),
                getsockopt(&plain, sockopt::Ipv6DontFrag).unwrap(),
            ),
            (
                "IPV6_RECVPKTINFO",
                getsockopt(&transport.socket, sockopt::Ipv6RecvPacketInfo).unwrap(),
                getsockopt(&plain, sockopt::Ipv6RecvPacketInfo).unwrap(),
            ),
            (
                "IPV6_RECVTCLASS",
                socket.recv_tclass_v6().unwrap(),
                plain.recv_tclass_v6().unwrap(),
            ),
            (
                "IPV6_RECVERR",
                getsockopt(&transport.socket, sockopt::Ipv6RecvErr).unwrap(),
                getsockopt(&plain, sockopt::Ipv6RecvErr).unwrap(),
            ),
        ]);
    }
    options
}

/// Bound without offload, the socket has the kernel defaults but for the ECN options
/// it asks for: `quinn-udp` never set it up.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn offload_off_bind_keeps_kernel_defaults() {
    for addr in ["127.0.0.1:0", "[::1]:0", "[::]:0"] {
        for (name, transport, plain) in socket_options(addr, false) {
            match name {
                "IP_RECVTOS" | "IPV6_RECVTCLASS" => assert!(transport, "{addr} {name}"),
                _ => assert_eq!(transport, plain, "{addr} {name}"),
            }
            if matches!(name, "IPV6_DONTFRAG" | "IP_RECVERR" | "IPV6_RECVERR") {
                assert!(!transport, "{addr} {name}");
            }
        }
    }
}

/// Bound with offload, the socket is set up by `quinn-udp`: fragmentation off
/// (`IPV6_DONTFRAG`), packet info and GRO on; turning offload off keeps that setup.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn offload_bind_sets_socket_up() {
    for addr in ["127.0.0.1:0", "[::1]:0", "[::]:0"] {
        for (name, transport, _) in socket_options(addr, true) {
            match name {
                // Off until path MTU discovery is turned on.
                "SO_TIMESTAMPNS" | "IP_RECVERR" | "IPV6_RECVERR" => {
                    assert!(!transport, "{addr} {name}");
                }
                // Set where `quinn-udp` finds it supported; IPv6 marks come with
                // IPV6_RECVTCLASS.
                "IP_RECVTOS" => {}
                _ => assert!(transport, "{addr} {name}"),
            }
        }
    }
    let a = bind(1, "[::]:0");
    a.set_offload(false).unwrap();
    assert!(
        nix::sys::socket::getsockopt(&a.socket, nix::sys::socket::sockopt::Ipv6DontFrag).unwrap()
    );
}

#[tokio::test]
async fn offload_cannot_be_turned_on_when_bound_without() {
    let a = bind_with(1, "127.0.0.1:0", false);
    assert!(!a.offload());
    assert_eq!(a.max_segments(), 1);
    a.set_offload(false).unwrap();
    let err = a.set_offload(true).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(!a.offload());
    assert!(a.state.is_none());
}

/// Linux's default socket buffer size (`net.core.rmem_default`), as reported.
const OLD_DEFAULT: usize = 212_992;

/// What the kernel reports for a request of `requested` bytes: on Linux the request
/// clamped to the sysctl `max` and doubled; `None` elsewhere or when unreadable.
fn granted(requested: usize, max: &str) -> Option<usize> {
    if !cfg!(any(target_os = "linux", target_os = "android")) {
        return None;
    }
    let max: usize = std::fs::read_to_string(format!("/proc/sys/net/core/{max}"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(2 * requested.min(max))
}

#[tokio::test]
async fn default_socket_buffers() {
    for offload in OFFLOAD {
        let plain = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let a = bind_with(1, "127.0.0.1:0", offload);
        for (effective, before, max) in [
            (a.recv_buffer_size(), plain.recv_buffer_size(), "rmem_max"),
            (a.send_buffer_size(), plain.send_buffer_size(), "wmem_max"),
        ] {
            let (effective, before) = (effective.unwrap(), before.unwrap());
            match granted(DEFAULT_SOCKET_BUFFER, max) {
                Some(granted) => {
                    assert_eq!(effective, granted, "{max}");
                    if granted > OLD_DEFAULT {
                        assert!(effective > OLD_DEFAULT, "{max}");
                    }
                }
                None => assert!(effective > 0 && effective >= before, "{max}"),
            }
        }
    }
}

#[tokio::test]
async fn socket_buffer_setters() {
    for offload in OFFLOAD {
        let a = bind_with(1, "[::]:0", offload);
        let mut previous = [0; 2];
        for bytes in [64 << 10, 1 << 20] {
            a.set_recv_buffer_size(bytes).unwrap();
            a.set_send_buffer_size(bytes).unwrap();
            let effective = [a.recv_buffer_size().unwrap(), a.send_buffer_size().unwrap()];
            for ((effective, previous), max) in
                effective.iter().zip(previous).zip(["rmem_max", "wmem_max"])
            {
                match granted(bytes, max) {
                    Some(granted) => assert_eq!(*effective, granted, "{max}"),
                    None => assert!(*effective > previous, "{max}"),
                }
            }
            previous = effective;
        }
    }
}

/// A burst of 512 datagrams of 1420 bytes sent before the receiver reads fits into the
/// default receive buffer, with offload on, turned off, and bound without.
#[tokio::test]
async fn burst_fits_default_buffer() {
    for (bound, offload) in [(true, true), (true, false), (false, false)] {
        let a = bind_with(1, "127.0.0.1:0", bound);
        let b = bind_with(2, "127.0.0.1:0", bound);
        a.set_offload(offload).unwrap();
        b.set_offload(offload).unwrap();
        let datagrams: Vec<_> = (0..512).map(|seq| numbered(seq, 1420)).collect();
        send_all(&a, &batch(b.local_addr(), Ecn::NotEct, &datagrams)).await;
        let received = recv_batches(&b, datagrams.len()).await.concat();
        check(&received, &datagrams, a.local_addr(), Ecn::NotEct);
    }
}

/// Datagram number `seq` of `len` bytes, different from its neighbours.
fn numbered(seq: usize, len: usize) -> Vec<u8> {
    (0..=u8::MAX).cycle().skip(seq % 256).take(len).collect()
}

/// `count` numbered datagrams of `size` bytes, then one shorter one if `size > 1`.
fn train(size: usize, count: usize) -> Vec<Vec<u8>> {
    let mut datagrams: Vec<_> = (0..count).map(|seq| numbered(seq, size)).collect();
    if size > 1 {
        datagrams.push(numbered(count, size / 2));
    }
    datagrams
}

fn batch(to: SocketAddr, ecn: Ecn, datagrams: &[Vec<u8>]) -> Vec<(Path, PacketBuf)> {
    datagrams
        .iter()
        .map(|datagram| (path_to(to, ecn), PacketBuf::from_packet(datagram)))
        .collect()
}

async fn send_all(transport: &UdpTransport, batch: &[(Path, PacketBuf)]) {
    let (mut sent, mut failed) = (0, 0);
    transport
        .send_batch(batch, &mut sent, &mut failed)
        .await
        .unwrap();
    assert_eq!((sent, failed), (batch.len(), 0));
}

/// Receives `count` datagrams with `recv_batch`; returns what each call appended.
async fn recv_batches(transport: &UdpTransport, count: usize) -> Vec<Vec<(Path, PacketBuf)>> {
    let mut buf = PacketBuf::with_capacity(65_535);
    let mut calls = Vec::new();
    let mut received = 0;
    while received < count {
        let mut datagrams = VecDeque::new();
        timeout(
            Duration::from_secs(5),
            transport.recv_batch(&mut buf, &mut datagrams),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!datagrams.is_empty() && datagrams.len() <= MAX_BATCH);
        received += datagrams.len();
        calls.push(datagrams.into());
    }
    assert_eq!(received, count);
    calls
}

/// Checks that `received` holds exactly `expected`, in order, from `from` with `ecn`
/// where the platform reports it.
fn check(received: &[(Path, PacketBuf)], expected: &[Vec<u8>], from: SocketAddr, ecn: Ecn) {
    let ecn = if cfg!(any(target_os = "linux", target_os = "android")) {
        ecn
    } else {
        Ecn::NotEct
    };
    assert_eq!(received.len(), expected.len());
    for ((path, datagram), expected) in received.iter().zip(expected) {
        assert_eq!(datagram.as_packet(), expected.as_slice());
        assert_eq!(path.addr, from);
        assert_eq!(path.ecn, ecn);
    }
}

/// Whether both ends coalesce: `from` sends segmented, `to` receives coalesced.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn coalescing(from: &UdpTransport, to: &UdpTransport) -> bool {
    from.max_segments() > 1
        && to.offload()
        && to
            .state
            .as_ref()
            .is_some_and(|state| state.gro_segments() > 1)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn coalescing(_: &UdpTransport, _: &UdpTransport) -> bool {
    false
}

/// Makes `a` take an ICMP error and waits until tokio reports a closed write side:
/// from then on it reports the socket writable for good. Sending recovers the error.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn icmp_error(a: &UdpTransport, ip: &str) {
    let closed = bind(3, &format!("{ip}:0")).local_addr();
    a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), a.socket.ready(Interest::ERROR))
        .await
        .unwrap()
        .unwrap();
    let ready = a.socket.ready(Interest::WRITABLE).await.unwrap();
    assert!(ready.is_write_closed());
    let open = SocketAddr::new(ip.parse().unwrap(), a.local_addr().port());
    for _ in 0..2 {
        a.send(DATAGRAM, &path_to(open, Ecn::NotEct)).await.unwrap();
    }
}

/// How often `send` runs within `period` under [`write_io`] with `discovery`, until it
/// does not fail with [`io::ErrorKind::WouldBlock`].
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn tries_within(
    a: &UdpTransport,
    errors: &SocketErrors,
    period: Duration,
    mut send: impl FnMut() -> io::Result<()> + Send,
) -> u64 {
    let tries = AtomicU64::new(0);
    let io = || {
        tries.fetch_add(1, Ordering::Relaxed);
        send()
    };
    let result = timeout(period, write_io(&a.socket, errors, io)).await;
    assert!(result.is_err(), "the send went through");
    tries.load(Ordering::Relaxed)
}

/// The prefix of the side datagrams in the side channel tests.
const SIDE: &[u8] = b"NSGWP2P1";

fn is_side(datagram: &[u8]) -> bool {
    datagram.starts_with(SIDE)
}

/// A side datagram carrying `body`.
fn side(body: &[u8]) -> Vec<u8> {
    [SIDE, body].concat()
}
