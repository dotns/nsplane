//! Path MTU discovery and recovery from ICMP errors.

use super::*;

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
