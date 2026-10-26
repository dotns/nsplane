//! Segmentation and receive offload, batched sends and reads.

use super::*;

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
