use super::*;
use nsplane_packet::{Ecn, HEADROOM, MAX_BATCH};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::timeout;

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

/// Path MTU discovery asks for ICMP errors only while on; the reports' receiver is
/// handed out once, after it was first turned on.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn path_mtu_discovery_sets_recverr() {
    // `IP_RECVERR` and `IPV6_RECVERR` when on; a socket bound to a specific IPv6
    // address is IPv6-only and leaves `IP_RECVERR` alone.
    for (addr, on) in [
        ("127.0.0.1:0", &[true][..]),
        ("[::1]:0", &[false, true]),
        ("[::]:0", &[true, true]),
    ] {
        let off = vec![false; on.len()];
        for offload in OFFLOAD {
            let a = bind_with(1, addr, offload);
            assert_eq!(recv_err(&a), off, "{addr}");
            assert!(Transport::path_mtu_reports(&a).is_none());
            a.set_path_mtu_discovery(false).unwrap();
            assert!(Transport::path_mtu_reports(&a).is_none());

            a.set_path_mtu_discovery(true).unwrap();
            assert_eq!(recv_err(&a), on, "{addr}");
            assert!(a.errors.discovery.load(Ordering::Relaxed));
            assert!(Transport::path_mtu_reports(&a).is_some());
            assert!(Transport::path_mtu_reports(&a).is_none());

            a.set_path_mtu_discovery(false).unwrap();
            assert_eq!(recv_err(&a), off, "{addr}");
            assert!(!a.errors.discovery.load(Ordering::Relaxed));
            a.set_path_mtu_discovery(true).unwrap();
            assert_eq!(recv_err(&a), on, "{addr}");
            assert!(Transport::path_mtu_reports(&a).is_none());
        }
    }
}

/// `IP_RECVERR` and, on an IPv6 socket, `IPV6_RECVERR` of `transport`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn recv_err(transport: &UdpTransport) -> Vec<bool> {
    use nix::sys::socket::{getsockopt, sockopt};

    let mut options = vec![getsockopt(&transport.socket, sockopt::Ipv4RecvErr).unwrap()];
    if transport.local.is_ipv6() {
        options.push(getsockopt(&transport.socket, sockopt::Ipv6RecvErr).unwrap());
    }
    options
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[tokio::test]
async fn path_mtu_discovery_is_unsupported() {
    let a = bind(1, "127.0.0.1:0");
    let err = a.set_path_mtu_discovery(true).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    a.set_path_mtu_discovery(false).unwrap();
    assert!(Transport::path_mtu_reports(&a).is_none());
    assert_eq!(a.path_mtu_reports_dropped(), 0);
}

/// An error-queue entry with `origin`, ICMP `kind` and `code`, and `info`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn queued_error(origin: u8, (kind, code): (u8, u8), info: u32) -> nix::libc::sock_extended_err {
    nix::libc::sock_extended_err {
        ee_errno: nix::libc::EMSGSIZE.cast_unsigned(),
        ee_origin: origin,
        ee_type: kind,
        ee_code: code,
        ee_pad: 0,
        ee_info: info,
        ee_data: 0,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn error_queue_entries_report_packet_too_big_only() {
    use nix::libc::{SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6, SO_EE_ORIGIN_LOCAL};

    let path = path_to("192.0.2.1:51820".parse().unwrap(), Ecn::NotEct);
    let quote = [4, 0, 0, 0, 1, 2, 3, 4];
    let report = |origin, icmp, info| {
        linux::path_mtu_report(path, &queued_error(origin, icmp, info), &quote)
    };

    let v4 = report(SO_EE_ORIGIN_ICMP, (3, 4), 1400).unwrap();
    assert_eq!((v4.path, v4.mtu, v4.quote()), (path, 1400, &quote[..]));
    let v6 = report(SO_EE_ORIGIN_ICMP6, (2, 0), 1280).unwrap();
    assert_eq!((v6.path, v6.mtu, v6.quote()), (path, 1280, &quote[..]));
    // No MTU in the message; one beyond 16 bits saturates.
    assert_eq!(report(SO_EE_ORIGIN_ICMP, (3, 4), 0).unwrap().mtu, 0);
    assert_eq!(
        report(SO_EE_ORIGIN_ICMP6, (2, 0), 70_000).unwrap().mtu,
        u16::MAX
    );
    let short = linux::path_mtu_report(
        path,
        &queued_error(SO_EE_ORIGIN_ICMP, (3, 4), 1400),
        &quote[..2],
    )
    .unwrap();
    assert_eq!(short.quote(), &quote[..2]);

    for (origin, icmp) in [
        // Port and host unreachable.
        (SO_EE_ORIGIN_ICMP, (3, 3)),
        (SO_EE_ORIGIN_ICMP, (3, 1)),
        // ICMPv6 codes under the other family's origin.
        (SO_EE_ORIGIN_ICMP, (2, 0)),
        (SO_EE_ORIGIN_ICMP6, (3, 4)),
        // Destination unreachable, time exceeded.
        (SO_EE_ORIGIN_ICMP6, (1, 4)),
        (SO_EE_ORIGIN_ICMP6, (3, 0)),
        // A local error (EMSGSIZE on send).
        (SO_EE_ORIGIN_LOCAL, (3, 4)),
        (SO_EE_ORIGIN_LOCAL, (0, 0)),
    ] {
        assert!(report(origin, icmp, 1400).is_none(), "{origin} {icmp:?}");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn path_mtu_reports_queue_is_bounded() {
    let a = bind(1, "127.0.0.1:0");
    let report = crate::PathMtuReport::new(path_to(a.local_addr(), Ecn::NotEct), 1400);
    // Not turned on yet: there is no queue.
    a.push_report(report.clone());
    assert_eq!(a.path_mtu_reports_dropped(), 0);

    a.set_path_mtu_discovery(true).unwrap();
    for _ in 0..70 {
        a.push_report(report.clone());
    }
    assert_eq!(a.path_mtu_reports_dropped(), 6);
    let mut reports = Transport::path_mtu_reports(&a).unwrap();
    let mut queued = 0;
    while let Ok(got) = reports.try_recv() {
        assert_eq!(got, report);
        queued += 1;
    }
    assert_eq!(queued, 64);
    a.push_report(report.clone());
    assert_eq!(reports.try_recv().unwrap(), report);

    // A closed receiver drops and counts too.
    drop(reports);
    a.push_report(report);
    assert_eq!(a.path_mtu_reports_dropped(), 7);
}

/// With path MTU discovery on, an ICMP port unreachable for an earlier send is read off
/// the error queue: receiving goes on with the next datagram, and nothing is reported.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn path_mtu_discovery_skips_other_icmp_errors() {
    for (addr, ip) in [
        ("127.0.0.1:0", "127.0.0.1"),
        ("[::1]:0", "::1"),
        ("[::]:0", "127.0.0.1"),
        ("[::]:0", "::1"),
    ] {
        for offload in OFFLOAD {
            let a = bind_with(1, addr, offload);
            let b = bind(2, &SocketAddr::new(ip.parse().unwrap(), 0).to_string());
            a.set_path_mtu_discovery(true).unwrap();
            let mut reports = Transport::path_mtu_reports(&a).unwrap();
            for _ in 0..2 {
                // A port nobody listens on: bound, then closed.
                let closed =
                    bind(3, &SocketAddr::new(ip.parse().unwrap(), 0).to_string()).local_addr();
                a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
                    .await
                    .unwrap();
                roundtrip(&b, b.local_addr(), &a, seen_as(&a, ip)).await;
            }
            assert!(reports.try_recv().is_err(), "{addr} {ip} {offload}");
            assert_eq!(a.path_mtu_reports_dropped(), 0);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn sends_survive_another_destinations_icmp_error() {
    for (addr, ip) in [
        ("127.0.0.1:0", "127.0.0.1"),
        ("[::1]:0", "::1"),
        ("[::]:0", "127.0.0.1"),
        ("[::]:0", "::1"),
    ] {
        for offload in OFFLOAD {
            for mode in 0..5 {
                let (a, side, _) = bind_with(1, addr, offload).with_side_channel(|_| false, 1);
                let b = bind(2, &SocketAddr::new(ip.parse().unwrap(), 0).to_string());
                a.set_path_mtu_discovery(true).unwrap();
                let closed =
                    bind(3, &SocketAddr::new(ip.parse().unwrap(), 0).to_string()).local_addr();
                a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
                    .await
                    .unwrap();
                timeout(Duration::from_secs(5), a.socket.ready(Interest::ERROR))
                    .await
                    .unwrap()
                    .unwrap();
                let to = path_to(b.local_addr(), Ecn::NotEct);
                let batch: Vec<_> = (0..4)
                    .map(|i| (to, PacketBuf::from_packet(&[i; 32])))
                    .collect();
                let mut sent = 0;
                let mut failed = 0;
                let result = match mode {
                    0 => a.send(batch[0].1.as_packet(), &to).await,
                    1 => a.send_batch(&batch, &mut sent, &mut failed).await,
                    2 => a.try_send_batch(&batch, &mut sent, &mut failed),
                    3 => side.send_to_async(batch[0].1.as_packet(), to.addr).await,
                    _ => side.send_to(batch[0].1.as_packet(), to.addr),
                };
                assert!(result.is_ok(), "{addr} {ip} {offload} {mode}: {result:?}");
                let count = if matches!(mode, 1 | 2) {
                    assert_eq!((sent, failed), (batch.len(), 0));
                    batch.len()
                } else {
                    1
                };
                for (_, packet) in &batch[..count] {
                    assert_eq!(recv(&b, 1500).await.0.as_packet(), packet.as_packet());
                }
                let mut packet = PacketBuf::with_capacity(1500);
                assert!(
                    timeout(Duration::from_millis(10), b.recv(&mut packet))
                        .await
                        .is_err(),
                    "duplicate datagram"
                );
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn icmp_recovery_preserves_partial_batches_and_real_errors() {
    for offload in OFFLOAD {
        for nonblocking in [false, true] {
            let a = bind_with(1, "127.0.0.1:0", offload);
            let b = bind(2, "127.0.0.1:0");
            a.set_path_mtu_discovery(true).unwrap();
            let closed = bind(3, "127.0.0.1:0").local_addr();
            a.send(DATAGRAM, &path_to(closed, Ecn::NotEct))
                .await
                .unwrap();
            timeout(Duration::from_secs(5), a.socket.ready(Interest::ERROR))
                .await
                .unwrap()
                .unwrap();
            let to = path_to(b.local_addr(), Ecn::NotEct);
            let batch = [
                (to, PacketBuf::from_packet(b"first")),
                (to, PacketBuf::from_packet(&vec![0; MAX_SEND + 1])),
                (to, PacketBuf::from_packet(b"last")),
            ];
            let mut sent = 0;
            let mut failed = 0;
            let result = if nonblocking {
                a.try_send_batch(&batch, &mut sent, &mut failed)
            } else {
                a.send_batch(&batch, &mut sent, &mut failed).await
            };
            assert_eq!(
                result.unwrap_err().raw_os_error(),
                Some(nix::libc::EMSGSIZE)
            );
            assert_eq!((sent, failed), (2, 1));
            assert_eq!(recv(&b, 1500).await.0.as_packet(), b"first");
            if nonblocking {
                a.try_send_batch(&batch, &mut sent, &mut failed).unwrap();
            } else {
                a.send_batch(&batch, &mut sent, &mut failed).await.unwrap();
            }
            assert_eq!((sent, failed), (3, 1));
            assert_eq!(recv(&b, 1500).await.0.as_packet(), b"last");
            let mut packet = PacketBuf::with_capacity(1500);
            assert!(
                timeout(Duration::from_millis(10), b.recv(&mut packet))
                    .await
                    .is_err()
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn send_recovery_does_not_spin_on_local_errors_or_backpressure() {
    let a = bind(1, "127.0.0.1:0");
    for discovery in [false, true] {
        a.set_path_mtu_discovery(discovery).unwrap();
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::WouldBlock] {
            let mut attempts = 0;
            let result: io::Result<()> = a.errors.write(&a.socket, || {
                attempts += 1;
                Err(kind.into())
            });
            assert_eq!(result.unwrap_err().kind(), kind);
            let expected = if discovery && kind != io::ErrorKind::WouldBlock {
                2
            } else {
                1
            };
            assert_eq!(attempts, expected);
        }
    }
}

/// Builds an ICMP Packet Too Big quoting a UDP datagram. The raw IPv6 socket supplies
/// the `ICMPv6` checksum; IPv4 carries its own checksum.
#[cfg(target_os = "linux")]
fn too_big_quote(from: SocketAddr, to: SocketAddr) -> (Socket, Vec<u8>) {
    use nsplane_packet::checksum::{
        internet_checksum, ipv4_header_checksum, transport_checksum_v6,
    };
    let mut udp = vec![0_u8; 16];
    udp[..2].copy_from_slice(&from.port().to_be_bytes());
    udp[2..4].copy_from_slice(&to.port().to_be_bytes());
    udp[4..6].copy_from_slice(&16_u16.to_be_bytes());
    udp[8..].copy_from_slice(b"pmtu1234");
    let mut icmp = vec![0_u8; 8];
    let (socket, header) = match (from.ip(), to.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => {
            let mut header = vec![0_u8; 20];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&36_u16.to_be_bytes());
            header[6] = 0x40;
            header[8] = 64;
            header[9] = 17;
            header[12..16].copy_from_slice(&src.octets());
            header[16..20].copy_from_slice(&dst.octets());
            let checksum = ipv4_header_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            icmp[0] = 3;
            icmp[1] = 4;
            icmp[6..8].copy_from_slice(&1400_u16.to_be_bytes());
            (
                Socket::new(Domain::IPV4, Type::RAW, Some(socket2::Protocol::ICMPV4)).unwrap(),
                header,
            )
        }
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => {
            let checksum = transport_checksum_v6(src, dst, 17, &udp);
            udp[6..8].copy_from_slice(&checksum.to_be_bytes());
            let mut header = vec![0_u8; 40];
            header[0] = 0x60;
            header[4..6].copy_from_slice(&16_u16.to_be_bytes());
            header[6] = 17;
            header[7] = 64;
            header[8..24].copy_from_slice(&src.octets());
            header[24..40].copy_from_slice(&dst.octets());
            icmp[0] = 2;
            icmp[4..8].copy_from_slice(&1400_u32.to_be_bytes());
            (
                Socket::new(Domain::IPV6, Type::RAW, Some(socket2::Protocol::ICMPV6)).unwrap(),
                header,
            )
        }
        _ => unreachable!(),
    };
    icmp.extend(header);
    icmp.extend(udp);
    if from.is_ipv4() {
        let checksum = internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    socket.set_nonblocking(true).unwrap();
    (socket, icmp)
}

/// Needs `CAP_NET_RAW` and a disposable network namespace: injected Packet Too Big
/// messages can change the namespace's loopback path-MTU cache.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires CAP_NET_RAW in a disposable network namespace"]
async fn send_recovery_preserves_real_path_mtu_reports() {
    for (addr, ip) in [
        ("127.0.0.1:0", "127.0.0.1"),
        ("[::1]:0", "::1"),
        ("[::]:0", "127.0.0.1"),
        ("[::]:0", "::1"),
    ] {
        for offload in OFFLOAD {
            for mode in 0..5 {
                let (a, side, _) = bind_with(1, addr, offload).with_side_channel(|_| false, 1);
                let b = bind(2, &SocketAddr::new(ip.parse().unwrap(), 0).to_string());
                let c = bind(3, &SocketAddr::new(ip.parse().unwrap(), 0).to_string());
                a.set_path_mtu_discovery(true).unwrap();
                let mut reports = a.path_mtu_reports().unwrap();
                a.send(b"pmtu1234", &path_to(b.local_addr(), Ecn::NotEct))
                    .await
                    .unwrap();
                assert_eq!(recv(&b, 1500).await.0.as_packet(), b"pmtu1234");
                let (raw, quote) = too_big_quote(seen_as(&a, ip), b.local_addr());
                raw.send_to(&quote, &SocketAddr::new(ip.parse().unwrap(), 0).into())
                    .unwrap();
                timeout(Duration::from_secs(5), a.socket.ready(Interest::ERROR))
                    .await
                    .unwrap()
                    .unwrap();
                let to = path_to(c.local_addr(), Ecn::NotEct);
                let batch = [(to, PacketBuf::from_packet(DATAGRAM))];
                let mut sent = 0;
                let mut failed = 0;
                let result = match mode {
                    0 => a.send(DATAGRAM, &to).await,
                    1 => a.send_batch(&batch, &mut sent, &mut failed).await,
                    2 => a.try_send_batch(&batch, &mut sent, &mut failed),
                    3 => side.send_to_async(DATAGRAM, to.addr).await,
                    _ => side.send_to(DATAGRAM, to.addr),
                };
                assert!(result.is_ok(), "{addr} {ip} {offload} {mode}: {result:?}");
                assert_eq!(recv(&c, 1500).await.0.as_packet(), DATAGRAM);
                let report = reports.try_recv().unwrap();
                assert_eq!(report.path.addr, b.local_addr());
                assert_eq!(report.path.transport, a.id());
                assert_eq!(report.mtu, 1400);
                assert_eq!(report.quote(), b"pmtu1234");
                assert!(reports.try_recv().is_err());
                assert_eq!(a.path_mtu_reports_dropped(), 0);
            }
        }
    }
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

/// Once tokio reports the socket closed for writing after an ICMP error, a send that
/// finds the buffer full pauses between tries instead of spinning, and sends still go
/// out.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn full_sends_back_off_after_an_icmp_error() {
    use std::io::Write as _;

    const PERIOD: Duration = Duration::from_millis(100);
    for offload in OFFLOAD {
        let (a, sender, _) = bind_with(1, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
        let b = bind(2, "127.0.0.1:0");
        a.set_path_mtu_discovery(true).unwrap();
        icmp_error(&a, "127.0.0.1").await;

        let full = || Err(io::ErrorKind::WouldBlock.into());
        let tries = tries_within(&a, &a.errors, PERIOD, full).await;
        // Pauses of 1, 2, 4 and then 8 ms: about 15 tries.
        assert!((3..=30).contains(&tries), "{tries} tries in {PERIOD:?}");
        // Without the pauses (`async_io`) this never yields: tokio's readiness returns
        // at once without spending the task's budget, so not even a timeout ends it.
        writeln!(
            io::stderr(),
            "offload {offload}: {tries} tries in {PERIOD:?}"
        )
        .unwrap();

        roundtrip(&a, a.local_addr(), &b, b.local_addr()).await;
        timeout(
            Duration::from_secs(5),
            sender.send_to_async(&side(b"after"), b.local_addr()),
        )
        .await
        .unwrap()
        .unwrap();
        let (buf, _) = recv(&b, 1500).await;
        assert_eq!(buf.as_packet(), side(b"after"));
    }
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

#[test]
fn runs_split_at_path_ecn_and_size_changes() {
    let a: SocketAddr = "192.0.2.1:1".parse().unwrap();
    let b: SocketAddr = "192.0.2.2:1".parse().unwrap();
    let datagram = |to, ecn, len| (path_to(to, ecn), PacketBuf::from_packet(&vec![0; len]));
    let datagrams = [
        datagram(a, Ecn::NotEct, 100),
        datagram(a, Ecn::NotEct, 100),
        datagram(a, Ecn::NotEct, 60), // shorter: ends the run
        datagram(a, Ecn::NotEct, 60),
        datagram(a, Ecn::Ect0, 60), // other ECN
        datagram(b, Ecn::Ect0, 60), // other address
        datagram(b, Ecn::Ect0, 80), // longer
        datagram(b, Ecn::Ect0, 0),  // empty
        datagram(b, Ecn::Ect0, 0),
    ];
    let runs = |max_segments| {
        let mut runs = Vec::new();
        let mut start = 0;
        while start < datagrams.len() {
            let run = run_len(&datagrams[start..], max_segments);
            runs.push(run);
            start += run;
        }
        runs
    };
    assert_eq!(runs(64), [3, 1, 1, 1, 1, 1, 1]);
    assert_eq!(runs(2), [2, 2, 1, 1, 1, 1, 1]);
    assert_eq!(runs(1), [1; 9]);
    assert_eq!(run_len(&[], 64), 0);

    // A run stops before it outgrows one send.
    let big: Vec<_> = (0..64).map(|_| datagram(a, Ecn::NotEct, 1420)).collect();
    assert_eq!(run_len(&big, 64), MAX_SEND / 1420);
}

/// Senders bound to `send_on` send segmented trains of every size to a plain socket
/// bound to `recv_on`, which gets them as separate datagrams.
async fn segmented_to_plain(send_on: &str, recv_on: &str, seen_as_ip: &str) {
    for offload in OFFLOAD {
        segmented_to_plain_with(send_on, recv_on, seen_as_ip, offload).await;
    }
}

async fn segmented_to_plain_with(send_on: &str, recv_on: &str, seen_as_ip: &str, offload: bool) {
    let sender = bind_with(1, send_on, offload);
    let plain = tokio::net::UdpSocket::bind(recv_on).await.unwrap();
    let from = seen_as(&sender, seen_as_ip);
    for size in [1, 1279, 1280, 1420] {
        let datagrams = train(size, 10);
        let batch = batch(plain.local_addr().unwrap(), Ecn::NotEct, &datagrams);
        if sender.max_segments() > 1 {
            assert_eq!(run_len(&batch, sender.max_segments()), batch.len());
        }
        send_all(&sender, &batch).await;
        let mut buf = [0; 2048];
        for expected in &datagrams {
            let (len, addr) = timeout(Duration::from_secs(5), plain.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..len], expected.as_slice(), "size {size}");
            assert_eq!(unmap(addr), from);
        }
    }
}

#[tokio::test]
async fn segmented_send_ipv4() {
    segmented_to_plain("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1").await;
}

#[tokio::test]
async fn segmented_send_ipv6() {
    segmented_to_plain("[::1]:0", "[::1]:0", "::1").await;
}

#[tokio::test]
async fn segmented_send_dual_stack() {
    segmented_to_plain("[::]:0", "127.0.0.1:0", "127.0.0.1").await;
    segmented_to_plain("[::]:0", "[::1]:0", "::1").await;
}

#[tokio::test]
async fn burst_from_plain_socket_keeps_boundaries() {
    for offload in OFFLOAD {
        let receiver = bind_with(1, "127.0.0.1:0", offload);
        let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let datagrams: Vec<_> = (0..100).map(|seq| numbered(seq, 1 + seq * 13)).collect();
        for datagram in &datagrams {
            plain
                .send_to(datagram, receiver.local_addr())
                .await
                .unwrap();
        }
        let received: Vec<_> = recv_batches(&receiver, datagrams.len()).await.concat();
        check(
            &received,
            &datagrams,
            plain.local_addr().unwrap(),
            Ecn::NotEct,
        );
    }
}

/// `from` sends a segmented train of each size with ECT(0) to `to`, which receives it
/// in one read where both ends coalesce: slices of one buffer where they were read,
/// without a copy.
async fn segmented_to_coalesced(
    from: &UdpTransport,
    from_addr: SocketAddr,
    to: &UdpTransport,
    to_addr: SocketAddr,
) {
    for size in [1, 1279, 1280, 1420] {
        let datagrams = train(size, 20);
        send_all(from, &batch(to_addr, Ecn::Ect0, &datagrams)).await;
        let calls = recv_batches(to, datagrams.len()).await;
        if coalescing(from, to) {
            assert_eq!(calls.len(), 1, "size {size}: one coalesced read");
            let first = calls[0][0].1.as_packet().as_ptr().addr();
            for (i, (_, datagram)) in calls[0].iter().enumerate() {
                assert_eq!(datagram.headroom(), 0, "size {size}: datagram {i}");
                assert_eq!(
                    datagram.as_packet().as_ptr().addr(),
                    first + i * size,
                    "size {size}: datagram {i} is not where it was read"
                );
            }
        }
        check(&calls.concat(), &datagrams, from_addr, Ecn::Ect0);
    }
}

#[tokio::test]
async fn coalesced_receive_ipv4() {
    let a = bind(1, "127.0.0.1:0");
    let b = bind(2, "127.0.0.1:0");
    segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
}

#[tokio::test]
async fn coalesced_receive_ipv6() {
    let a = bind(1, "[::1]:0");
    let b = bind(2, "[::1]:0");
    segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
}

#[tokio::test]
async fn coalesced_receive_dual_stack() {
    let dual = bind(1, "[::]:0");
    let v4 = bind(2, "127.0.0.1:0");
    let v6 = bind(3, "[::1]:0");
    let dual_v4 = seen_as(&dual, "127.0.0.1");
    let dual_v6 = seen_as(&dual, "::1");
    segmented_to_coalesced(&v4, v4.local_addr(), &dual, dual_v4).await;
    segmented_to_coalesced(&dual, dual_v4, &v4, v4.local_addr()).await;
    segmented_to_coalesced(&v6, v6.local_addr(), &dual, dual_v6).await;
    segmented_to_coalesced(&dual, dual_v6, &v6, v6.local_addr()).await;
}

/// `recv` hands out a coalesced train one datagram at a time.
#[tokio::test]
async fn recv_splits_coalesced_train() {
    let a = bind(1, "127.0.0.1:0");
    let b = bind(2, "127.0.0.1:0");
    let datagrams = train(1280, 10);
    send_all(&a, &batch(b.local_addr(), Ecn::Ect1, &datagrams)).await;
    let mut received = Vec::new();
    for _ in &datagrams {
        let (buf, path) = recv(&b, 1500).await;
        received.push((path, buf));
    }
    check(&received, &datagrams, a.local_addr(), Ecn::Ect1);
}

#[tokio::test]
async fn mixed_batch_reaches_each_receiver_in_order() {
    for offload in OFFLOAD {
        mixed_batch(offload).await;
    }
}

async fn mixed_batch(offload: bool) {
    let sender = bind_with(1, "[::]:0", offload);
    let v4 = bind_with(2, "127.0.0.1:0", offload);
    let v6 = bind_with(3, "[::1]:0", offload);
    let ecns = [Ecn::NotEct, Ecn::Ect0, Ecn::Ect1, Ecn::Ce];
    let mut batch = Vec::new();
    let mut expected: [Vec<(Ecn, Vec<u8>)>; 2] = Default::default();
    // Few enough to sit in a small (Wine) receive buffer until read.
    for seq in 0..MAX_BATCH {
        // Runs of a few datagrams, then a change of receiver, mark or size.
        let to = (seq / 7) % 2;
        let ecn = ecns[(seq / 5) % 4];
        let len = if seq % 11 == 10 { 700 } else { 1280 };
        let datagram = numbered(seq, len);
        let addr = [v4.local_addr(), v6.local_addr()][to];
        batch.push((path_to(addr, ecn), PacketBuf::from_packet(&datagram)));
        expected[to].push((ecn, datagram));
    }
    send_all(&sender, &batch).await;
    for (receiver, expected, ip) in [(&v4, &expected[0], "127.0.0.1"), (&v6, &expected[1], "::1")] {
        let received = recv_batches(receiver, expected.len()).await.concat();
        for ((path, datagram), (ecn, bytes)) in received.iter().zip(expected) {
            check(
                &[(*path, datagram.clone())],
                std::slice::from_ref(bytes),
                seen_as(&sender, ip),
                *ecn,
            );
        }
    }
}

/// Without offload nothing is segmented or coalesced, but on Linux and Android one
/// `recvmmsg` reads several datagrams, each its own exactly sized copy.
#[tokio::test]
async fn offload_off_batches_without_coalescing() {
    let a = bind(1, "127.0.0.1:0");
    let b = bind(2, "127.0.0.1:0");
    assert!(a.offload());
    a.set_offload(false).unwrap();
    b.set_offload(false).unwrap();
    assert!(!a.offload());
    assert_eq!(a.max_segments(), 1);
    let datagrams = train(1280, 20);
    let batch = batch(b.local_addr(), Ecn::Ce, &datagrams);
    assert_eq!(run_len(&batch, a.max_segments()), 1);
    send_all(&a, &batch).await;
    // Let every datagram reach the receive queue.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let calls = recv_batches(&b, datagrams.len()).await;
    if cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(calls[0].len(), 16, "one recvmmsg of 16 datagrams");
    } else {
        assert!(calls.iter().all(|call| call.len() == 1));
    }
    for (_, datagram) in calls.iter().flatten() {
        assert_eq!(
            datagram.headroom(),
            HEADROOM,
            "a copy, not a slice of a read"
        );
    }
    check(&calls.concat(), &datagrams, a.local_addr(), Ecn::Ce);

    // Back on, segmented again.
    a.set_offload(true).unwrap();
    b.set_offload(true).unwrap();
    segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
}

/// Bound without offload, reads batch too; every datagram is truncated to the
/// caller's buffer and sizes, order, senders and marks are kept.
#[tokio::test]
async fn batched_reads_keep_datagrams_apart() {
    let a = bind_with(1, "[::]:0", false);
    let b = bind_with(2, "[::]:0", false);
    let to = seen_as(&b, "127.0.0.1");
    let ecns = [Ecn::NotEct, Ecn::Ect0, Ecn::Ect1, Ecn::Ce];
    let mut batch = Vec::new();
    let mut expected = Vec::new();
    for seq in 0..40 {
        let datagram = numbered(seq, seq * 37);
        batch.push((
            path_to(to, ecns[seq % 4]),
            PacketBuf::from_packet(&datagram),
        ));
        expected.push((ecns[seq % 4], datagram));
    }
    send_all(&a, &batch).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut small = PacketBuf::with_capacity(1000);
    let capacity = small.capacity();
    let mut received = VecDeque::new();
    while received.len() < expected.len() {
        timeout(
            Duration::from_secs(5),
            b.recv_batch(&mut small, &mut received),
        )
        .await
        .unwrap()
        .unwrap();
    }
    assert_eq!(received.len(), expected.len());
    for ((path, datagram), (ecn, bytes)) in received.iter().zip(&expected) {
        let ecn = if cfg!(any(target_os = "linux", target_os = "android")) {
            *ecn
        } else {
            Ecn::NotEct
        };
        assert_eq!(datagram.as_packet(), &bytes[..bytes.len().min(capacity)]);
        assert_eq!(path.addr, seen_as(&a, "127.0.0.1"));
        assert_eq!(path.ecn, ecn);
    }
}

/// With receive offload, reads of one datagram each switch `recv_batch` to batched
/// copies, and the next train switches it back to slices of one read.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn receive_offload_batches_while_no_trains_arrive() {
    let a = bind(1, "127.0.0.1:0");
    let b = bind(2, "127.0.0.1:0");
    if !coalescing(&a, &b) {
        return; // No segmentation offload on this host.
    }
    let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let singles: Vec<_> = (0..40).map(|seq| numbered(seq, 1200)).collect();
    for datagram in &singles {
        plain.send_to(datagram, b.local_addr()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let calls = recv_batches(&b, singles.len()).await;
    let from = plain.local_addr().unwrap();
    check(&calls.concat(), &singles, from, Ecn::NotEct);
    let lens: Vec<_> = calls.iter().map(Vec::len).collect();
    assert_eq!(lens[..4], [1; 4], "coalesced reads first: {lens:?}");
    assert_eq!(lens[4], 16, "then batched: {lens:?}");
    assert!(b.batched());

    // A train read in a batch is split right and ends the batching.
    let train1 = train(1280, 20);
    send_all(&a, &batch(b.local_addr(), Ecn::Ect0, &train1)).await;
    let calls = recv_batches(&b, train1.len()).await;
    check(&calls.concat(), &train1, a.local_addr(), Ecn::Ect0);
    assert!(!b.batched());
    // The next one is sliced out of one read again.
    segmented_to_coalesced(&a, a.local_addr(), &b, b.local_addr()).await;
}

/// A segmented run leaves from the datagrams' own buffers on Linux and Android: the
/// train buffer stays unallocated, and a plain socket receives each datagram once.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn segmented_run_goes_out_without_a_train() {
    let sender = bind(1, "[::]:0");
    let plain = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let datagrams = [train(1420, 30), train(700, 5)].concat();
    let batch = batch(plain.local_addr().unwrap(), Ecn::Ect0, &datagrams);
    if sender.max_segments() == 1 {
        return; // No segmentation offload on this host.
    }
    assert!(run_len(&batch, sender.max_segments()) > 1);
    send_all(&sender, &batch).await;
    try_send_all(&sender, &batch).await;
    assert_eq!(sender.train.lock().unwrap().capacity(), 0);
    let mut buf = [0; 2048];
    for expected in datagrams.iter().chain(&datagrams) {
        let (len, _) = timeout(Duration::from_secs(5), plain.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], expected.as_slice());
    }
    let extra = timeout(Duration::from_millis(50), plain.recv_from(&mut buf)).await;
    assert!(extra.is_err(), "no datagram twice");
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn mmsg_runs_split_at_path_and_ecn_changes_only() {
    let a: SocketAddr = "192.0.2.1:1".parse().unwrap();
    let b: SocketAddr = "192.0.2.2:1".parse().unwrap();
    let datagram = |to, ecn, len| (path_to(to, ecn), PacketBuf::from_packet(&vec![0; len]));
    let datagrams = [
        datagram(a, Ecn::NotEct, 100),
        datagram(a, Ecn::NotEct, 60),
        datagram(a, Ecn::NotEct, 1400), // longer: same run
        datagram(a, Ecn::Ect0, 60),     // other ECN
        datagram(b, Ecn::Ect0, 60),     // other address
        datagram(b, Ecn::Ect0, 0),
    ];
    let mut runs = Vec::new();
    let mut start = 0;
    while start < datagrams.len() {
        let run = linux::mmsg_len(&datagrams[start..]);
        runs.push(run);
        start += run;
    }
    assert_eq!(runs, [3, 1, 2]);
    assert_eq!(linux::mmsg_len(&[]), 0);
    let long: Vec<_> = (0..100).map(|_| datagram(a, Ecn::NotEct, 10)).collect();
    assert_eq!(linux::mmsg_len(&long), MAX_BATCH);
}

/// A batch whose middle run goes to the limited broadcast address, which the kernel
/// refuses without `SO_BROADCAST`: a call fails only the datagrams of that run, and
/// called past its errors as the engine does, the batch loses exactly that run while
/// the runs around it arrive in order.
#[tokio::test]
async fn failed_run_counts_only_its_datagrams() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        let refused: SocketAddr = "255.255.255.255:9".parse().unwrap();
        let (head, lost, tail) = (train(1280, 6), train(1280, 4), train(1280, 3));
        let mut datagrams = batch(b.local_addr(), Ecn::NotEct, &head);
        datagrams.extend(batch(refused, Ecn::NotEct, &lost));
        datagrams.extend(batch(b.local_addr(), Ecn::NotEct, &tail));
        let run = run_len(&datagrams[head.len()..], a.max_segments());
        if offload && cfg!(any(target_os = "linux", target_os = "android")) {
            assert_eq!(run, lost.len(), "one segmented run");
        }

        let (mut sent, mut failed) = (0, 0);
        a.send_batch(&datagrams, &mut sent, &mut failed)
            .await
            .unwrap_err();
        assert_eq!((sent, failed), (head.len() + run, run));
        while sent < datagrams.len() {
            let before = (sent, failed);
            if a.send_batch(&datagrams, &mut sent, &mut failed)
                .await
                .is_ok()
            {
                assert_eq!(failed, before.1);
            } else {
                assert!(failed > before.1 && failed - before.1 <= sent - before.0);
            }
        }
        assert_eq!((sent, failed), (datagrams.len(), lost.len()));

        let received = recv_batches(&b, head.len() + tail.len()).await.concat();
        check(
            &received,
            &[head, tail].concat(),
            a.local_addr(),
            Ecn::NotEct,
        );
    }
}

/// Sends `batch` with `try_send_batch`, waiting for the socket after each
/// [`io::ErrorKind::WouldBlock`], which must leave the counts as they were.
async fn try_send_all(transport: &UdpTransport, batch: &[(Path, PacketBuf)]) {
    let (mut sent, mut failed) = (0, 0);
    loop {
        let before = sent;
        match transport.try_send_batch(batch, &mut sent, &mut failed) {
            Ok(()) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(sent >= before && sent < batch.len());
                transport.socket.writable().await.unwrap();
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!((sent, failed), (batch.len(), 0));
}

#[tokio::test]
async fn try_send_batch_sends_runs_in_order() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        let datagrams = [train(1280, 20), train(900, 3), vec![numbered(7, 1400)]].concat();
        let batch = batch(b.local_addr(), Ecn::Ect0, &datagrams);
        if offload && cfg!(any(target_os = "linux", target_os = "android")) {
            assert!(run_len(&batch, a.max_segments()) > 1, "segmented runs");
        }
        // The reactor has not reported the new socket writable yet: nothing goes out
        // and nothing counts.
        let (mut sent, mut failed) = (0, 0);
        let error = a
            .try_send_batch(&batch, &mut sent, &mut failed)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!((sent, failed), (0, 0));
        try_send_all(&a, &batch).await;
        let received = recv_batches(&b, datagrams.len()).await.concat();
        check(&received, &datagrams, a.local_addr(), Ecn::Ect0);
    }
}

#[tokio::test]
async fn try_send_batch_failed_run_counts_only_its_datagrams() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let b = bind_with(2, "127.0.0.1:0", offload);
        a.socket.writable().await.unwrap();
        let refused: SocketAddr = "255.255.255.255:9".parse().unwrap();
        let (head, lost, tail) = (train(1280, 6), train(1280, 4), train(1280, 3));
        let mut datagrams = batch(b.local_addr(), Ecn::NotEct, &head);
        datagrams.extend(batch(refused, Ecn::NotEct, &lost));
        datagrams.extend(batch(b.local_addr(), Ecn::NotEct, &tail));
        let run = run_len(&datagrams[head.len()..], a.max_segments());

        let (mut sent, mut failed) = (0, 0);
        let error = a
            .try_send_batch(&datagrams, &mut sent, &mut failed)
            .unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!((sent, failed), (head.len() + run, run));
        while sent < datagrams.len() {
            let before = (sent, failed);
            match a.try_send_batch(&datagrams, &mut sent, &mut failed) {
                Ok(()) => assert_eq!(failed, before.1),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert_eq!(failed, before.1);
                    a.socket.writable().await.unwrap();
                }
                Err(_) => {
                    assert!(failed > before.1 && failed - before.1 <= sent - before.0);
                }
            }
        }
        assert_eq!((sent, failed), (datagrams.len(), lost.len()));

        let received = recv_batches(&b, head.len() + tail.len()).await.concat();
        check(
            &received,
            &[head, tail].concat(),
            a.local_addr(),
            Ecn::NotEct,
        );
    }
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

/// The side datagrams waiting in `rx`, as `(from, datagram)`.
fn drain(rx: &mut mpsc::Receiver<SideDatagram>) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut taken = Vec::new();
    while let Ok(side) = rx.try_recv() {
        taken.push((side.from, side.datagram.to_vec()));
    }
    taken
}

/// Side datagrams sent before a WireGuard-like one are taken out of `recv`, which
/// returns the WireGuard-like one.
#[tokio::test]
async fn side_channel_takes_classified_datagrams_from_recv() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let (b, _, mut side_rx) =
            bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 8);
        let control = side(b"control");
        for datagram in [&control[..], &control, DATAGRAM] {
            a.send(datagram, &path_to(b.local_addr(), Ecn::NotEct))
                .await
                .unwrap();
        }
        let (buf, path) = recv(&b, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(path.addr, a.local_addr());
        assert_eq!(drain(&mut side_rx), vec![(a.local_addr(), control); 2]);
    }
}

/// A train of equally sized datagrams, every third one a side datagram: `recv_batch`
/// and `recv` hand out the others in order and the side channel gets the side ones,
/// with offload on (one coalesced read where the kernel coalesces) and off.
#[tokio::test]
async fn side_channel_splits_mixed_trains() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let (b, sender, mut side_rx) =
            bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 64);
        // Ends with a WireGuard-like datagram, so every side one was read before it.
        let datagrams: Vec<_> = (0..21)
            .map(|seq| {
                let datagram = numbered(seq, 1280);
                if seq % 3 == 1 {
                    side(&datagram[SIDE.len()..])
                } else {
                    datagram
                }
            })
            .collect();
        let (sides, wireguard): (Vec<_>, Vec<_>) =
            datagrams.iter().cloned().partition(|d| is_side(d));
        let sides: Vec<_> = sides.into_iter().map(|d| (a.local_addr(), d)).collect();
        let batch = batch(b.local_addr(), Ecn::Ect0, &datagrams);

        send_all(&a, &batch).await;
        let calls = recv_batches(&b, wireguard.len()).await;
        if coalescing(&a, &b) {
            assert_eq!(calls.len(), 1, "one coalesced read");
        }
        check(&calls.concat(), &wireguard, a.local_addr(), Ecn::Ect0);
        assert_eq!(drain(&mut side_rx), sides);

        send_all(&a, &batch).await;
        let mut received = Vec::new();
        for _ in &wireguard {
            let (buf, path) = recv(&b, 1500).await;
            received.push((path, buf));
        }
        check(&received, &wireguard, a.local_addr(), Ecn::Ect0);
        assert_eq!(drain(&mut side_rx), sides);
        assert_eq!(
            sender.stats(),
            SideStats {
                received: 2 * sides.len() as u64,
                dropped: 0
            }
        );
    }
}

/// A full receiver drops side datagrams and counts them; a read of side datagrams only
/// does not end `recv_batch` without a datagram.
#[tokio::test]
async fn side_channel_counts_drops_when_full() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let (b, sender, mut side_rx) =
            bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
        let sides = vec![side(b"control"); 3];
        send_all(&a, &batch(b.local_addr(), Ecn::NotEct, &sides)).await;
        a.send(DATAGRAM, &path_to(b.local_addr(), Ecn::NotEct))
            .await
            .unwrap();
        let calls = recv_batches(&b, 1).await;
        check(
            &calls.concat(),
            &[DATAGRAM.to_vec()],
            a.local_addr(),
            Ecn::NotEct,
        );
        assert_eq!(
            sender.stats(),
            SideStats {
                received: 1,
                dropped: 2
            }
        );
        assert_eq!(drain(&mut side_rx).len(), 1);
    }
}

/// A closed receiver drops side datagrams and counts them.
#[tokio::test]
async fn side_channel_counts_drops_when_closed() {
    for offload in OFFLOAD {
        let a = bind_with(1, "127.0.0.1:0", offload);
        let (b, sender, side_rx) =
            bind_with(2, "127.0.0.1:0", offload).with_side_channel(is_side, 4);
        drop(side_rx);
        let control = side(b"control");
        for datagram in [&control[..], &control, DATAGRAM] {
            a.send(datagram, &path_to(b.local_addr(), Ecn::NotEct))
                .await
                .unwrap();
        }
        let (buf, _) = recv(&b, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(
            sender.stats(),
            SideStats {
                received: 0,
                dropped: 2
            }
        );
    }
}

/// A side sender sends from the transport's address, unmarked, mapping destinations as
/// the transport does; side datagrams back are reported from the unmapped address. A
/// second side channel replaces the first.
#[tokio::test]
async fn side_sender_sends_from_the_transport() {
    for offload in OFFLOAD {
        let (dual, sender, mut side_rx) =
            bind_with(1, "[::]:0", offload).with_side_channel(is_side, 4);
        assert_eq!(sender.local_addr(), dual.local_addr());
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let dual_v4 = seen_as(&dual, "127.0.0.1");
        let control = side(b"punch");
        sender.send_to(&control, v4.local_addr()).unwrap();
        let (buf, path) = recv(&v4, 1500).await;
        assert_eq!(buf.as_packet(), control);
        assert_eq!(path.addr, dual_v4);
        assert_eq!(path.ecn, Ecn::NotEct);

        for datagram in [&control[..], DATAGRAM] {
            v4.send(datagram, &path_to(dual_v4, Ecn::NotEct))
                .await
                .unwrap();
        }
        let (buf, _) = recv(&dual, 1500).await;
        assert_eq!(buf.as_packet(), DATAGRAM);
        assert_eq!(drain(&mut side_rx), [(v4.local_addr(), control.clone())]);

        let (_, v4_sender, _) = bind_with(3, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
        let err = v4_sender
            .send_to(&control, "[::1]:9".parse().unwrap())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let (dual, second, mut second_rx) = dual.with_side_channel(is_side, 4);
        assert!(matches!(
            side_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        for datagram in [&control[..], DATAGRAM] {
            v4.send(datagram, &path_to(dual_v4, Ecn::NotEct))
                .await
                .unwrap();
        }
        recv(&dual, 1500).await;
        assert_eq!(drain(&mut second_rx), [(v4.local_addr(), control)]);
        assert_eq!(sender.stats().received, 1);
        assert_eq!(second.stats().received, 1);
    }
}

/// `send_to_async` addresses as `send_to` does: from the transport's address, unmarked,
/// IPv4 destinations of a dual-stack socket mapped, IPv6 ones on an IPv4 socket rejected.
#[tokio::test]
async fn side_sender_send_to_async_addresses_as_send_to() {
    for offload in OFFLOAD {
        let (dual, sender, _) = bind_with(1, "[::]:0", offload).with_side_channel(is_side, 1);
        let v4 = bind_with(2, "127.0.0.1:0", offload);
        let control = side(b"probe");
        sender
            .send_to_async(&control, v4.local_addr())
            .await
            .unwrap();
        let (buf, path) = recv(&v4, 1500).await;
        assert_eq!(buf.as_packet(), control);
        assert_eq!(path.addr, seen_as(&dual, "127.0.0.1"));
        assert_eq!(path.ecn, Ecn::NotEct);

        let (_, v4_sender, _) = bind_with(3, "127.0.0.1:0", offload).with_side_channel(is_side, 1);
        let err = v4_sender
            .send_to_async(&control, "[::1]:9".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

/// With the send buffer full, `send_to` fails with `WouldBlock` while `send_to_async`
/// waits and sends once the buffer drains; a `send_to_async` dropped while waiting sends
/// nothing. Loopback frees a datagram's buffer space at once, so the buffer is filled
/// with datagrams to a neighbour on a dummy interface that never answers ARP: they wait
/// in its queue until resolution gives up (about 3 s) and frees them.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn side_sender_send_to_async_waits_for_a_full_send_buffer() {
    const DEV: &str = "nsside0";
    let ip = |args: &[&str]| {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "ip {args:?}: {status}");
    };
    ip(&["link", "add", DEV, "type", "dummy"]);
    ip(&["link", "set", DEV, "arp", "on", "up"]);
    ip(&["addr", "add", "10.200.0.1/24", "dev", DEV]);

    let (a, sender, _) = bind(1, "0.0.0.0:0").with_side_channel(is_side, 1);
    a.set_send_buffer_size(1).unwrap();
    let b = bind(2, "127.0.0.1:0");
    let unresolved: SocketAddr = "10.200.0.2:9".parse().unwrap();
    for seq in 0.. {
        assert!(seq < 1000, "the send buffer never filled");
        match sender.send_to(&numbered(seq, 1400), unresolved) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }
    let control = side(b"register");
    let err = sender.send_to(&control, b.local_addr()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    let cancelled = sender.send_to_async(b"cancelled", b.local_addr());
    assert!(
        timeout(Duration::from_millis(100), cancelled)
            .await
            .is_err()
    );
    timeout(
        Duration::from_secs(10),
        sender.send_to_async(&control, b.local_addr()),
    )
    .await
    .unwrap()
    .unwrap();
    let (buf, path) = recv(&b, 1500).await;
    assert_eq!(buf.as_packet(), control);
    assert_eq!(path.addr, seen_as(&a, "127.0.0.1"));
    let mut buf = PacketBuf::with_capacity(1500);
    assert!(
        timeout(Duration::from_millis(100), b.recv(&mut buf))
            .await
            .is_err()
    );
    ip(&["link", "del", DEV]);
}

/// As [`full_sends_back_off_after_an_icmp_error`], with a send buffer that is really
/// full: datagrams to an unresolved neighbour on a dummy device fill it (as in
/// [`side_sender_send_to_async_waits_for_a_full_send_buffer`]) after an ICMP error.
/// Tries to send more pause, and the transport's and the side channel's sends go out
/// once the neighbour's queue is freed.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn full_send_buffer_backs_off_after_an_icmp_error() {
    use std::io::Write as _;

    const DEV: &str = "nspmtu0";
    const PERIOD: Duration = Duration::from_millis(200);
    let ip = |args: &[&str]| {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "ip {args:?}: {status}");
    };
    ip(&["link", "add", DEV, "type", "dummy"]);
    ip(&["link", "set", DEV, "arp", "on", "up"]);
    ip(&["addr", "add", "10.201.0.1/24", "dev", DEV]);

    let (a, sender, _) = bind(1, "0.0.0.0:0").with_side_channel(is_side, 1);
    let b = bind(2, "127.0.0.1:0");
    a.set_path_mtu_discovery(true).unwrap();
    a.set_send_buffer_size(1).unwrap();
    icmp_error(&a, "127.0.0.1").await;
    let unresolved: SocketAddr = "10.201.0.2:9".parse().unwrap();
    for seq in 0.. {
        assert!(seq < 1000, "the send buffer never filled");
        match sender.send_to(&numbered(seq, 1400), unresolved) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("{e}"),
        }
    }

    let to = b.local_addr().into();
    let tries = tries_within(&a, &a.errors, PERIOD, || {
        socket2::SockRef::from(&*a.socket)
            .send_to(DATAGRAM, &to)
            .map(drop)
    })
    .await;
    writeln!(
        io::stderr(),
        "{tries} tries in {PERIOD:?} with a full send buffer"
    )
    .unwrap();
    assert!((3..=50).contains(&tries), "{tries} tries in {PERIOD:?}");

    // Host unreachable errors from queued datagrams must not fail healthy sends.
    let control = side(b"control");
    let to_b = path_to(b.local_addr(), Ecn::NotEct);
    timeout(Duration::from_secs(10), async {
        a.send(DATAGRAM, &to_b).await.unwrap();
        sender
            .send_to_async(&control, b.local_addr())
            .await
            .unwrap();
    })
    .await
    .unwrap();
    let (buf, _) = recv(&b, 1500).await;
    assert_eq!(buf.as_packet(), DATAGRAM);
    let (buf, _) = recv(&b, 1500).await;
    assert_eq!(buf.as_packet(), control);
    ip(&["link", "del", DEV]);
}
