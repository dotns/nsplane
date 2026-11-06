use super::*;
use std::num::NonZeroU64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn datagram(label: Option<NonZeroU64>, payload: &[u8]) -> PacketBuf {
    let mut packet = build_udp(
        "10.0.0.2:5000".parse().unwrap(),
        "10.0.0.1:9000".parse().unwrap(),
        payload,
    )
    .unwrap();
    packet.set_tag(label);
    packet
}

#[tokio::test]
async fn udp_lifetime_drops_other_labels_and_none() -> TestResult {
    let a = NonZeroU64::new(41);
    let b = NonZeroU64::new(42);
    for (first, other) in [(a, b), (a, None), (None, a)] {
        let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
        let (_source, sink) = stack.split();
        let mut incoming = handle.incoming_udp();
        sink.send(datagram(first, b"first"), PeerId::new(0)).await?;
        let mut flow = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("missing flow")?;
        assert_eq!(timeout(WAIT, flow.recv()).await?.unwrap(), b"first"[..]);
        sink.send(datagram(other, b"wrong lifetime"), PeerId::new(0))
            .await?;
        sink.send(datagram(first, b"same lifetime"), PeerId::new(0))
            .await?;
        assert_eq!(
            timeout(WAIT, flow.recv()).await?.unwrap(),
            b"same lifetime"[..]
        );
    }
    Ok(())
}

#[tokio::test]
async fn udp_reply_carries_the_first_input_label() -> TestResult {
    let label = NonZeroU64::new(41);
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    let (mut source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    sink.send(datagram(label, b"request"), PeerId::new(0))
        .await?;
    let flow = timeout(WAIT, next(&mut incoming))
        .await?
        .ok_or("missing flow")?;
    flow.send(b"reply").await?;
    let packet = timeout(WAIT, source.recv()).await??;
    assert_eq!(packet.tag(), label);
    assert_eq!(udp::parse_udp(packet).unwrap().payload, b"reply"[..]);
    Ok(())
}

#[tokio::test]
async fn syn_ack_carries_the_first_syn_label() -> TestResult {
    let label = NonZeroU64::new(41);
    let (_handle, mut peer) =
        RawPeer::start(config([10, 0, 0, 1].into()), [10, 0, 0, 2].into(), 19);
    peer.connect(Ipv4Addr::new(10, 0, 0, 1), 9000, 5000)?;
    peer.iface
        .poll(peer.now(), &mut peer.device, &mut peer.sockets);
    let mut syn = peer.device.drain_tx().next().ok_or("missing SYN")?;
    syn.set_tag(label);
    peer.sink.send(syn, PeerId::new(0)).await?;
    let reply = timeout(WAIT, peer.source.recv()).await??;
    assert_eq!(reply.tag(), label);
    assert_eq!(tcp_segment(reply.as_packet()).unwrap()[13] & 0x12, 0x12);
    Ok(())
}

fn modes() -> Vec<NetStackConfig> {
    let mut modes = Vec::new();
    for transparent in [false, true] {
        for decide in [false, true] {
            let mut cfg = config([10, 0, 0, 1].into());
            if transparent {
                cfg.transparent = Some(crate::TransparentConfig::default());
            }
            if decide {
                cfg.admission = crate::Admission::Decide {
                    timeout: Duration::from_secs(5),
                    max_pending: 8,
                };
            }
            modes.push(cfg);
        }
    }
    modes
}

#[tokio::test]
async fn revocation_retires_delivered_udp_and_preserves_old_output_identity() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    for cfg in modes() {
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        let (stack, handle) = NetStack::new(cfg);
        let (mut source, sink) = stack.split();
        let mut incoming = handle.incoming_udp();
        let mut pending = handle.incoming_pending();
        sink.send(datagram(Some(a), b"old"), PeerId::new(0)).await?;
        if decide {
            let item = timeout(WAIT, next(&mut pending)).await?.ok_or("pending")?;
            assert_eq!(item.ingress_label(), Some(a));
            item.accept();
        }
        let mut old = timeout(WAIT, next(&mut incoming)).await?.ok_or("flow")?;
        assert_eq!(old.ingress_label(), Some(a));
        old.send(b"already outside the stack").await?;
        let outside = timeout(WAIT, source.recv()).await??;
        old.send(b"queued old output").await?;
        assert_eq!(
            timeout(WAIT, handle.revoke_label(a).wait()).await?,
            crate::RetirementOutcome::Retired
        );
        assert!(old.recv().await.is_none());
        assert_eq!(
            old.send(b"forbidden").await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        sink.send(datagram(Some(a), b"revoked"), PeerId::new(0))
            .await?;
        sink.send(datagram(Some(b), b"fresh"), PeerId::new(0))
            .await?;
        if decide {
            timeout(WAIT, next(&mut pending))
                .await?
                .ok_or("fresh pending")?
                .accept();
        }
        let mut fresh = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("fresh flow")?;
        assert_eq!(fresh.ingress_label(), Some(b));
        assert_eq!(fresh.recv().await.unwrap(), b"fresh"[..]);
        fresh.send(b"fresh output").await?;
        let output = timeout(WAIT, source.recv()).await??;
        assert_eq!(output.tag(), Some(b));
        assert_eq!(udp::parse_udp(output).unwrap().payload, b"fresh output"[..]);
        assert_eq!(outside.tag(), Some(a));
        assert_eq!(handle.stats().label_revoked, 1);
    }
    Ok(())
}

#[tokio::test]
async fn labeled_connected_udp_filters_input_and_is_retired() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    let (mut source, sink) = stack.split();
    let mut socket = handle
        .connect_udp_from_labeled("10.0.0.1:9000".parse()?, "10.0.0.2:5000".parse()?, a)
        .await?;
    assert_eq!(socket.ingress_label(), Some(a));
    socket.send(b"active").await?;
    assert_eq!(timeout(WAIT, source.recv()).await??.tag(), Some(a));
    for label in [None, Some(b), Some(a)] {
        sink.send(datagram(label, b"incoming"), PeerId::new(0))
            .await?;
    }
    assert_eq!(timeout(WAIT, socket.recv_from()).await??.0, b"incoming"[..]);
    assert_eq!(handle.stats().label_mismatch, 2);
    assert_eq!(
        timeout(WAIT, handle.revoke_label(a).wait()).await?,
        crate::RetirementOutcome::Retired
    );
    assert_eq!(
        socket.send(b"old").await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(
        handle
            .connect_udp_labeled("10.0.0.2:5000".parse()?, a)
            .await
            .is_err()
    );
    let fresh = handle
        .connect_udp_from_labeled("10.0.0.1:9000".parse()?, "10.0.0.2:5000".parse()?, b)
        .await?;
    fresh.send(b"fresh").await?;
    assert_eq!(timeout(WAIT, source.recv()).await??.tag(), Some(b));
    Ok(())
}

#[tokio::test]
async fn unlabeled_connected_udp_accepts_only_unlabeled_input() -> TestResult {
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    let (_source, sink) = stack.split();
    let mut socket = handle
        .connect_udp_from("10.0.0.1:9000".parse()?, "10.0.0.2:5000".parse()?)
        .await?;
    assert_eq!(socket.ingress_label(), None);
    for (label, payload) in [
        (NonZeroU64::new(41), &b"labeled"[..]),
        (None, &b"unlabeled"[..]),
    ] {
        sink.send(datagram(label, payload), PeerId::new(0)).await?;
    }
    assert_eq!(
        timeout(WAIT, socket.recv_from()).await??.0,
        b"unlabeled"[..]
    );
    assert_eq!(handle.stats().label_mismatch, 1);
    Ok(())
}

#[tokio::test]
async fn unlabeled_tcp_output_stays_unlabeled_beside_a_label_on_every_mode() -> TestResult {
    let label = NonZeroU64::new(41).unwrap();
    for cfg in modes() {
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        let (handle, mut peer) = RawPeer::start(cfg, [10, 0, 0, 2].into(), 31);
        let mut pending = handle.incoming_pending();
        let active = handle.clone();
        let connect = tokio::spawn(async move {
            active
                .connect_tcp_labeled("10.0.0.2:7000".parse().unwrap(), label)
                .await
        });
        assert_eq!(timeout(WAIT, peer.source.recv()).await??.tag(), Some(label));
        syn(&mut peer, None).await?;
        if decide {
            timeout(WAIT, next(&mut pending))
                .await?
                .ok_or("pending SYN")?
                .accept();
        }
        let reply = timeout(WAIT, peer.source.recv()).await??;
        assert_eq!(tcp_segment(reply.as_packet()).unwrap()[13] & 0x12, 0x12);
        assert_eq!(reply.tag(), None);
        connect.abort();
    }
    Ok(())
}

#[tokio::test]
async fn active_tcp_syn_and_retransmission_are_labeled_and_revoke_cancels_connect() -> TestResult {
    use std::future::Future;
    let label = NonZeroU64::new(41).unwrap();
    let mut cfg = config([10, 0, 0, 1].into());
    cfg.tcp_initial_rto = Duration::from_millis(30);
    let (stack, handle) = NetStack::new(cfg);
    let (mut source, _sink) = stack.split();
    let mut connect =
        Box::pin(handle.connect_tcp_from_labeled(9000, "10.0.0.2:5000".parse()?, label));
    assert!(
        connect
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let first = timeout(WAIT, source.recv()).await??;
    let resent = timeout(WAIT, source.recv()).await??;
    assert_eq!(first.tag(), Some(label));
    assert_eq!(resent.tag(), Some(label));
    assert_eq!(first.as_packet(), resent.as_packet());
    assert_eq!(
        timeout(WAIT, handle.revoke_label(label).wait()).await?,
        crate::RetirementOutcome::Retired
    );
    assert_eq!(
        timeout(WAIT, connect).await?.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    Ok(())
}

#[tokio::test]
async fn queued_input_is_fenced_after_tombstone_eviction() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    for mut cfg in modes() {
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        cfg.max_revoked_labels = 1;
        let (stack, handle) = NetStack::new(cfg);
        let (_source, sink) = stack.split();
        let mut incoming = handle.incoming_udp();
        let mut pending = handle.incoming_pending();
        // These sends and revokes do not yield on the current-thread runtime.
        sink.send(datagram(Some(a), b"queued before revoke"), PeerId::new(0))
            .await?;
        let first = handle.revoke_label(a);
        let second = handle.revoke_label(b);
        assert_eq!(
            timeout(WAIT, first.wait()).await?,
            crate::RetirementOutcome::Retired
        );
        assert_eq!(
            timeout(WAIT, second.wait()).await?,
            crate::RetirementOutcome::Retired
        );
        let fresh = NonZeroU64::new(43);
        sink.send(datagram(fresh, b"fresh"), PeerId::new(0)).await?;
        if decide {
            timeout(WAIT, next(&mut pending))
                .await?
                .ok_or("fresh pending")?
                .accept();
        }
        let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("flow")?;
        assert_eq!(flow.ingress_label(), fresh);
        assert_eq!(flow.recv().await.unwrap(), b"fresh"[..]);
        // Upstream distinguishes queue-fenced input from a retained tombstone.
        assert_eq!(handle.retired_drops(), 1);
    }
    Ok(())
}

#[tokio::test]
async fn a_full_ingress_fence_table_fails_then_allows_retry() -> TestResult {
    let mut cfg = config([10, 0, 0, 1].into());
    cfg.max_revoked_labels = 1;
    let (stack, handle) = NetStack::new(cfg);
    let (_source, sink) = stack.split();
    sink.send(datagram(NonZeroU64::new(1), b"queued"), PeerId::new(0))
        .await?;
    let receipts: Vec<_> = (1..=crate::flow::MAX_FENCES + 1)
        .map(|id| handle.revoke_label(NonZeroU64::new(id as u64).unwrap()))
        .collect();
    assert_eq!(
        timeout(WAIT, receipts[0].wait()).await?,
        crate::RetirementOutcome::Retired
    );
    assert_eq!(
        timeout(WAIT, receipts.last().unwrap().wait()).await?,
        crate::RetirementOutcome::Failed
    );
    let last = NonZeroU64::new((crate::flow::MAX_FENCES + 1) as u64).unwrap();
    assert_eq!(
        timeout(WAIT, handle.revoke_label(last).wait()).await?,
        crate::RetirementOutcome::Retired
    );
    Ok(())
}

#[tokio::test]
async fn stopped_stack_reports_unknown_for_label_retirement() -> TestResult {
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    drop(stack);
    tokio::task::yield_now().await;
    assert_eq!(
        timeout(
            WAIT,
            handle.revoke_label(NonZeroU64::new(41).unwrap()).wait()
        )
        .await?,
        crate::RetirementOutcome::Unknown
    );
    Ok(())
}

async fn syn(
    peer: &mut RawPeer,
    label: Option<NonZeroU64>,
) -> Result<(SocketHandle, PacketBuf), Box<dyn Error>> {
    let socket = peer.connect(Ipv4Addr::new(10, 0, 0, 1), 9000, 5000)?;
    peer.iface
        .poll(peer.now(), &mut peer.device, &mut peer.sockets);
    let mut packet = peer.device.drain_tx().next().ok_or("SYN")?;
    packet.set_tag(label);
    peer.sink.send(packet.clone(), PeerId::new(0)).await?;
    Ok((socket, packet))
}

async fn wait_mismatches(handle: &NetStackHandle, count: u64) -> TestResult {
    timeout(WAIT, async {
        while handle.stats().label_mismatch < count {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(handle.stats().label_mismatch, count);
    Ok(())
}

async fn handshake_ack(
    peer: &mut RawPeer,
    label: Option<NonZeroU64>,
) -> Result<PacketBuf, Box<dyn Error>> {
    let reply = timeout(WAIT, peer.source.recv()).await??;
    assert_eq!(reply.tag(), label);
    peer.device.inject(reply);
    peer.iface
        .poll(peer.now(), &mut peer.device, &mut peer.sockets);
    let mut ack = peer.device.drain_tx().next().ok_or("ACK")?;
    ack.set_tag(label);
    Ok(ack)
}

#[tokio::test]
async fn tcp_checks_syn_ack_and_established_input_labels_on_every_mode() -> TestResult {
    let a = NonZeroU64::new(41);
    let b = NonZeroU64::new(42);
    for cfg in modes() {
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        let (handle, mut peer) = RawPeer::start(cfg, [10, 0, 0, 2].into(), 29);
        let mut incoming = handle.incoming_tcp();
        let mut pending = handle.incoming_pending();
        let (socket, mut duplicate) = syn(&mut peer, a).await?;
        duplicate.set_tag(b);
        peer.sink.send(duplicate, PeerId::new(0)).await?;
        wait_mismatches(&handle, 1).await?;
        if decide {
            let item = timeout(WAIT, next(&mut pending))
                .await?
                .ok_or("pending SYN")?;
            assert_eq!(item.ingress_label(), a);
            item.accept();
        }
        let ack = handshake_ack(&mut peer, a).await?;
        let mut wrong = ack.clone();
        wrong.set_tag(None);
        peer.sink.send(wrong, PeerId::new(0)).await?;
        wait_mismatches(&handle, 2).await?;
        assert!(try_next(&mut incoming).is_none());
        peer.sink.send(ack, PeerId::new(0)).await?;
        let mut conn = timeout(WAIT, next(&mut incoming)).await?.ok_or("TCP")?;
        assert_eq!(conn.ingress_label(), a);
        peer.socket(socket).send_slice(b"payload")?;
        peer.iface
            .poll(peer.now(), &mut peer.device, &mut peer.sockets);
        let mut data = peer.device.drain_tx().next().ok_or("data")?;
        for label in [b, None] {
            let mut wrong = data.clone();
            wrong.set_tag(label);
            peer.sink.send(wrong, PeerId::new(0)).await?;
        }
        wait_mismatches(&handle, 4).await?;
        data.set_tag(a);
        peer.sink.send(data, PeerId::new(0)).await?;
        let mut read = [0; 7];
        timeout(WAIT, conn.read_exact(&mut read)).await??;
        assert_eq!(&read, b"payload");
        conn.abort();
        timeout(WAIT, async {
            loop {
                let packet = peer.source.recv().await?;
                assert_eq!(packet.tag(), a);
                if tcp_segment(packet.as_packet()).is_some_and(|tcp| tcp[13] & 4 != 0) {
                    break;
                }
            }
            Ok::<(), io::Error>(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn label_revoke_covers_held_and_syn_received_tcp_then_allows_same_tuple() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    for cfg in modes() {
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        for held in [false, true] {
            if held && !decide {
                continue;
            }
            let (handle, mut peer) = RawPeer::start(cfg.clone(), [10, 0, 0, 2].into(), 31);
            let mut pending = handle.incoming_pending();
            let mut incoming = handle.incoming_tcp();
            let (old_socket, _) = syn(&mut peer, Some(a)).await?;
            let control = if decide {
                let item = timeout(WAIT, next(&mut pending)).await?.ok_or("pending")?;
                let control = item.control();
                if held {
                    assert_eq!(
                        timeout(WAIT, handle.revoke_label(a).wait()).await?,
                        crate::RetirementOutcome::Retired
                    );
                }
                item.accept();
                Some(control)
            } else {
                None
            };
            if !held {
                let syn_ack = timeout(WAIT, peer.source.recv()).await??;
                assert_eq!(syn_ack.tag(), Some(a));
                assert_eq!(
                    timeout(WAIT, handle.revoke_label(a).wait()).await?,
                    crate::RetirementOutcome::Retired
                );
            }
            if let Some(control) = control {
                assert_eq!(
                    timeout(WAIT, control.delivery().wait()).await?,
                    crate::DeliveryOutcome::NotDelivered(crate::Undelivered::Revoked)
                );
            }
            peer.sockets.remove(old_socket);
            syn(&mut peer, Some(b)).await?;
            if decide {
                timeout(WAIT, next(&mut pending))
                    .await?
                    .ok_or("fresh pending")?
                    .accept();
            }
            let ack = handshake_ack(&mut peer, Some(b)).await?;
            peer.sink.send(ack, PeerId::new(0)).await?;
            let mut fresh = timeout(WAIT, next(&mut incoming))
                .await?
                .ok_or("fresh TCP")?;
            assert_eq!(fresh.ingress_label(), Some(b));
            assert_eq!(
                timeout(WAIT, handle.revoke_label(b).wait()).await?,
                crate::RetirementOutcome::Retired
            );
            assert_eq!(
                fresh.write_all(b"retired").await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn mixed_fragments_and_partial_old_datagrams_cannot_enter_a_replacement() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    for mut cfg in modes() {
        cfg.reassembly = Some(crate::ReassemblyConfig::default());
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        let (stack, handle) = NetStack::new(cfg);
        let (_source, sink) = stack.split();
        let mut incoming = handle.incoming_udp();
        let mut pending = handle.incoming_pending();
        let packet = datagram(Some(a), b"fragment payload longer than two fragments");
        let parts = super::reassembly::fragments_v4(packet.as_packet(), 16, 17);
        assert!(parts.len() > 2);
        for (index, part) in parts.iter().enumerate() {
            let mut fragment = PacketBuf::from_packet(part);
            fragment.set_tag(Some(if index == 1 { b } else { a }));
            sink.send(fragment, PeerId::new(0)).await?;
            if index == 1 {
                // Count the mismatch even if no final fragment ever arrives.
                wait_mismatches(&handle, 1).await?;
                assert_eq!(handle.stats().reassembled, 0);
            }
        }
        wait_mismatches(&handle, 1).await?;
        let mut first = PacketBuf::from_packet(&parts[0]);
        first.set_tag(Some(a));
        sink.send(first, PeerId::new(0)).await?;
        let mut marker = handle.bind_udp("10.0.0.1:9001".parse()?).await?;
        sink.send(
            build_udp(
                "10.0.0.2:5001".parse()?,
                "10.0.0.1:9001".parse()?,
                b"after fragment",
            )
            .unwrap(),
            PeerId::new(0),
        )
        .await?;
        timeout(WAIT, marker.recv_from()).await??;
        assert_eq!(
            timeout(WAIT, handle.revoke_label(a).wait()).await?,
            crate::RetirementOutcome::Retired
        );
        // A complete fresh datagram with the same fragment identity must work.
        for part in &parts {
            let mut fragment = PacketBuf::from_packet(part);
            fragment.set_tag(Some(b));
            sink.send(fragment, PeerId::new(0)).await?;
        }
        if decide {
            timeout(WAIT, next(&mut pending))
                .await?
                .ok_or("pending")?
                .accept();
        }
        let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("flow")?;
        assert_eq!(flow.ingress_label(), Some(b));
        assert_eq!(
            flow.recv().await.unwrap(),
            udp::parse_udp(packet).unwrap().payload
        );
    }
    Ok(())
}

#[tokio::test]
async fn labeled_tcp_accepts_unlabeled_pmtu_but_rejects_another_label() -> TestResult {
    for cfg in modes() {
        for a in [None, NonZeroU64::new(41)] {
            let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
            let b = NonZeroU64::new(42);
            let (handle, mut peer) = RawPeer::start(cfg.clone(), [10, 0, 0, 2].into(), 37);
            let mut incoming = handle.incoming_tcp();
            syn(&mut peer, a).await?;
            if decide {
                let mut pending = handle.incoming_pending();
                timeout(WAIT, next(&mut pending))
                    .await?
                    .ok_or("pending")?
                    .accept();
            }
            let ack = handshake_ack(&mut peer, a).await?;
            peer.sink.send(ack, PeerId::new(0)).await?;
            let mut conn = timeout(WAIT, next(&mut incoming)).await?.ok_or("TCP")?;
            conn.write_all(&[7; 1200]).await?;
            let data = timeout(WAIT, peer.source.recv()).await??;
            assert!(data.len() > 600);
            let mut message = vec![3, 4, 0, 0, 0, 0, 2, 88]; // IPv4 MTU 600.
            message.extend_from_slice(&data.as_packet()[..28]);
            let bytes = super::ownership::ip(
                [10, 0, 0, 3].into(),
                [10, 0, 0, 1].into(),
                protocol::ICMP,
                &message,
            );
            let mut wrong = PacketBuf::from_packet(&bytes);
            wrong.set_tag(b);
            peer.sink.send(wrong, PeerId::new(0)).await?;
            wait_mismatches(&handle, 1).await?;
            peer.sink
                .send(PacketBuf::from_packet(&bytes), PeerId::new(0))
                .await?;
            let resent = timeout(WAIT, peer.source.recv()).await??;
            assert_eq!(resent.tag(), a);
            assert!(resent.len() <= 600);
            assert_eq!(handle.stats().icmp_ignored, 0);
        }
    }
    Ok(())
}

#[tokio::test]
async fn full_output_fences_report_failed_without_preserving_live_access() -> TestResult {
    let label = NonZeroU64::new(41).unwrap();
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    let (mut source, _sink) = stack.split();
    let socket = handle
        .connect_udp_labeled("10.0.0.2:5000".parse()?, label)
        .await?;
    socket.send(b"already queued").await?;
    timeout(WAIT, async {
        while source.rx.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    for index in 0..crate::flow::MAX_FENCES {
        assert!(
            source
                .fences
                .insert(crate::flow::Fence::Label {
                    label: NonZeroU64::new(99 + index as u64).unwrap(),
                    end: 1
                })
                .is_ok()
        );
    }
    assert_eq!(
        timeout(WAIT, handle.revoke_label(label).wait()).await?,
        crate::RetirementOutcome::Failed
    );
    assert_eq!(
        socket.send(b"denied").await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    // Failed permits this old queued output to remain. Consuming it frees queue pressure.
    let old = timeout(WAIT, source.recv()).await??;
    assert_eq!(old.tag(), Some(label));
    assert_eq!(
        timeout(WAIT, handle.revoke_label(label).wait()).await?,
        crate::RetirementOutcome::Retired
    );
    Ok(())
}

#[tokio::test]
async fn pending_and_accept_queued_udp_are_never_delivered_after_label_revoke() -> TestResult {
    let a = NonZeroU64::new(41).unwrap();
    let b = NonZeroU64::new(42).unwrap();
    for accepted in [false, true] {
        let mut cfg = config([10, 0, 0, 1].into());
        cfg.admission = crate::Admission::Decide {
            timeout: WAIT,
            max_pending: 4,
        };
        let (stack, handle) = NetStack::new(cfg);
        let (_source, sink) = stack.split();
        let mut pending = handle.incoming_pending();
        let mut incoming = handle.incoming_udp();
        sink.send(datagram(Some(a), b"old"), PeerId::new(0)).await?;
        let item = timeout(WAIT, next(&mut pending)).await?.ok_or("pending")?;
        let control = item.control();
        let mut item = Some(item);
        if accepted {
            item.take().unwrap().accept();
            timeout(WAIT, async {
                while handle.stats().accepted == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
        }
        assert_eq!(
            timeout(WAIT, handle.revoke_label(a).wait()).await?,
            crate::RetirementOutcome::Retired
        );
        assert_eq!(
            control.delivery().outcome(),
            Some(crate::DeliveryOutcome::NotDelivered(
                crate::Undelivered::Revoked
            ))
        );
        if let Some(item) = item {
            item.accept();
        }
        sink.send(datagram(Some(b), b"fresh"), PeerId::new(0))
            .await?;
        timeout(WAIT, next(&mut pending))
            .await?
            .ok_or("fresh pending")?
            .accept();
        let flow = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("fresh flow")?;
        assert_eq!(flow.ingress_label(), Some(b));
    }
    Ok(())
}

#[tokio::test]
async fn repeated_label_revoke_does_not_consume_more_output_fences() -> TestResult {
    let label = NonZeroU64::new(41).unwrap();
    let (stack, handle) = NetStack::new(config([10, 0, 0, 1].into()));
    let (mut source, _sink) = stack.split();
    let socket = handle
        .connect_udp_labeled("10.0.0.2:5000".parse()?, label)
        .await?;
    socket.send(b"queued").await?;
    timeout(WAIT, async {
        while source.rx.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let receipts: Vec<_> = (0..=crate::flow::MAX_FENCES)
        .map(|_| handle.revoke_label(label))
        .collect();
    for receipt in receipts {
        assert_eq!(
            timeout(WAIT, receipt.wait()).await?,
            crate::RetirementOutcome::Retired
        );
    }
    assert!(source.try_admit().is_none());
    Ok(())
}

#[tokio::test]
async fn label_revoke_removes_tcp_from_accept_queue_and_backpressure_waiting() -> TestResult {
    let label = NonZeroU64::new(41).unwrap();
    for mut cfg in modes() {
        cfg.accept_capacity = 1;
        cfg.accept_backpressure = true;
        let decide = matches!(cfg.admission, crate::Admission::Decide { .. });
        let (handle, mut peer) = RawPeer::start(cfg, [10, 0, 0, 2].into(), 43);
        let mut incoming = handle.incoming_tcp();
        let mut pending = handle.incoming_pending();
        let mut controls = Vec::new();
        for port in [5000, 5001] {
            peer.connect(Ipv4Addr::new(10, 0, 0, 1), 9000, port)?;
            peer.iface
                .poll(peer.now(), &mut peer.device, &mut peer.sockets);
            let packets: Vec<_> = peer.device.drain_tx().collect();
            for mut packet in packets {
                packet.set_tag(Some(label));
                peer.sink.send(packet, PeerId::new(0)).await?;
            }
            if decide {
                let item = timeout(WAIT, next(&mut pending)).await?.ok_or("pending")?;
                controls.push(item.control());
                item.accept();
            }
        }
        // Both SYNs are admitted while the accept queue still has its first slot.
        for _ in 0..2 {
            let ack = handshake_ack(&mut peer, Some(label)).await?;
            peer.sink.send(ack, PeerId::new(0)).await?;
        }
        // A following UDP delivery proves both ACKs passed through the ingress batch.
        let mut marker = handle.bind_udp("10.0.0.1:9001".parse()?).await?;
        peer.sink
            .send(
                build_udp(
                    "10.0.0.2:5002".parse()?,
                    "10.0.0.1:9001".parse()?,
                    b"after ACKs",
                )
                .unwrap(),
                PeerId::new(0),
            )
            .await?;
        timeout(WAIT, marker.recv_from()).await??;
        assert_eq!(
            timeout(WAIT, handle.revoke_label(label).wait()).await?,
            crate::RetirementOutcome::Retired
        );
        for control in controls {
            assert_eq!(
                control.delivery().outcome(),
                Some(crate::DeliveryOutcome::NotDelivered(
                    crate::Undelivered::Revoked
                ))
            );
        }
        assert!(try_next(&mut incoming).is_none());
    }
    Ok(())
}

#[tokio::test]
async fn rejection_replies_keep_the_held_label_and_revoked_pending_is_not_offered() -> TestResult {
    let label = NonZeroU64::new(41).unwrap();
    for cfg in modes()
        .into_iter()
        .filter(|cfg| matches!(cfg.admission, crate::Admission::Decide { .. }))
    {
        let (handle, mut peer) = RawPeer::start(cfg, [10, 0, 0, 2].into(), 47);
        let mut pending = handle.incoming_pending();
        peer.sink
            .send(datagram(Some(label), b"reject UDP"), PeerId::new(0))
            .await?;
        timeout(WAIT, next(&mut pending))
            .await?
            .ok_or("UDP pending")?
            .reject();
        let reply = timeout(WAIT, peer.source.recv()).await??;
        assert_eq!(reply.tag(), Some(label));
        assert_eq!(
            IpPacket::parse(reply.as_packet()).unwrap().protocol(),
            protocol::ICMP
        );
        syn(&mut peer, Some(label)).await?;
        timeout(WAIT, next(&mut pending))
            .await?
            .ok_or("TCP pending")?
            .reject();
        let reply = timeout(WAIT, peer.source.recv()).await??;
        assert_eq!(reply.tag(), Some(label));
        assert_ne!(tcp_segment(reply.as_packet()).unwrap()[13] & 4, 0);
        peer.sink
            .send(datagram(Some(label), b"held"), PeerId::new(0))
            .await?;
        timeout(WAIT, async {
            while handle.stats().pending == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            timeout(WAIT, handle.revoke_label(label).wait()).await?,
            crate::RetirementOutcome::Retired
        );
        assert!(try_next(&mut pending).is_none());
    }
    Ok(())
}
