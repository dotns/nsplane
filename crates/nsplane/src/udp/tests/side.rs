//! The side channel.

use super::*;

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
