//! `NetStackHandle::revoke_label`: every lifetime of a label retired at every stage, its
//! input still queued in the stack dropped, its tombstone, and the outcomes.

use std::num::NonZeroU64;

use super::labels::{
    CLIENT, KINDS, Kind, L1, L2, L3, LOCAL, accept_all, client_turn, connected, datagram, flow,
    fragmented, pump_labeled, quiet, received, send, stack_config, until_stats,
};
use super::*;
use crate::stack::labels::INGRESS_FENCE_LIMIT;
use crate::{DeliveryOutcome, Ownership, RetirementOutcome, Undelivered};

/// Revokes `label` and waits for the outcome.
async fn revoke(
    handle: &NetStackHandle,
    label: NonZeroU64,
) -> Result<RetirementOutcome, Box<dyn Error>> {
    Ok(timeout(WAIT, handle.revoke_label(label).wait()).await?)
}

/// Whether the stack reports `remote -> local` as a UDP flow.
fn owns_udp(handle: &NetStackHandle, remote: SocketAddr, local: SocketAddr) -> bool {
    build_udp(remote, local, b"?")
        .is_some_and(|packet| handle.owns(packet.as_packet()) == Ownership::Flow)
}

/// Whether the stack reports `client -> server` as a TCP connection.
fn owns_tcp(handle: &NetStackHandle, client: SocketAddr, server: SocketAddr) -> bool {
    let packet = super::ownership::tcp_packet(client, server, 0x10);
    handle.owns(&packet) == Ownership::Flow
}

// ── UDP ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn revoking_a_label_retires_its_flows_at_every_stage() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let remotes: Vec<SocketAddr> = (5000..5004)
        .map(|port| SocketAddr::new(CLIENT.into(), port))
        .collect();
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        // Handed out, with a datagram queued.
        datagram(&sink, remotes[0], local, b"a", Some(L1)).await?;
        let mut handed = flow(&mut incoming).await?;
        datagram(&sink, remotes[0], local, b"b", Some(L1)).await?;
        // Of another label, and unlabeled.
        datagram(&sink, remotes[1], local, b"c", Some(L2)).await?;
        let mut other = flow(&mut incoming).await?;
        datagram(&sink, remotes[2], local, b"d", None).await?;
        let mut unlabeled = flow(&mut incoming).await?;
        // In the accept queue.
        datagram(&sink, remotes[3], local, b"e", Some(L1)).await?;
        timeout(WAIT, async {
            while !owns_udp(&handle, remotes[3], local) {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        assert_eq!(
            revoke(&handle, L1).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        assert!(handed.control().is_revoked(), "{kind:?}");
        assert!(timeout(WAIT, handed.recv()).await?.is_none(), "{kind:?}");
        assert!(
            quiet(&mut incoming).await,
            "{kind:?}: the queued flow is skipped"
        );
        // Nothing else is touched.
        assert_eq!(received(&mut other).await?, b"c");
        assert_eq!(received(&mut unlabeled).await?, b"d");
        datagram(&sink, remotes[1], local, b"f", Some(L2)).await?;
        assert_eq!(received(&mut other).await?, b"f", "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn revoking_a_label_retires_held_lifetimes() -> TestResult {
    let (handle, mut peer) = RawPeer::start(stack_config(Kind::Decide), CLIENT, 61);
    let mut pending = handle.incoming_pending();
    let mut incoming_udp = handle.incoming_udp();
    let mut incoming_tcp = handle.incoming_tcp();
    let (remote, local): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "192.0.2.7:53".parse()?);
    datagram(&peer.sink, remote, local, b"held", Some(L1)).await?;
    let held_udp = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    peer.connect(LOCAL, 443, 40_100)?;
    let syn = client_turn(&mut peer).into_iter().next().ok_or("no SYN")?;
    send(&peer.sink, &syn, Some(L1)).await?;
    let held_tcp = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    let (udp, tcp) = (held_udp.control(), held_tcp.control());

    assert_eq!(revoke(&handle, L1).await?, RetirementOutcome::Retired);
    for control in [&udp, &tcp] {
        assert!(control.is_revoked());
        assert_eq!(
            control.delivery().outcome(),
            Some(DeliveryOutcome::NotDelivered(Undelivered::Revoked))
        );
    }
    held_udp.accept();
    held_tcp.accept();
    for _ in 0..10 {
        pump_labeled(&mut peer, Some(L2)).await;
    }
    assert!(quiet(&mut incoming_udp).await);
    assert!(quiet(&mut incoming_tcp).await);
    assert_eq!(handle.stats().pending, 0);
    Ok(())
}

// ── TCP ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn revoking_a_label_retires_its_connections_at_every_stage() -> TestResult {
    let server = SocketAddr::new(LOCAL.into(), 443);
    let client = |port| SocketAddr::new(CLIENT.into(), port);
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 62);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        // Handed out.
        let (_, mut handed) = connected(&mut peer, &mut incoming, 40_110, Some(L1)).await?;
        // Of another label.
        let (other_socket, mut other) =
            connected(&mut peer, &mut incoming, 40_111, Some(L2)).await?;
        // Established and in the accept queue.
        let queued = peer.connect(LOCAL, 443, 40_112)?;
        for _ in 0..200 {
            pump_labeled(&mut peer, Some(L1)).await;
            if peer.state(queued) == tcp::State::Established {
                break;
            }
        }
        pump_labeled(&mut peer, Some(L1)).await;
        // In SYN-RECEIVED, its SYN-ACK not delivered.
        peer.connect(LOCAL, 443, 40_113)?;
        let syn = client_turn(&mut peer).into_iter().next().ok_or("no SYN")?;
        send(&peer.sink, &syn, Some(L1)).await?;
        timeout(WAIT, async {
            while !owns_tcp(&handle, client(40_113), server) {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;

        assert_eq!(
            revoke(&handle, L1).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        assert!(handed.control().is_revoked(), "{kind:?}");
        let mut storage = [0; 16];
        let error = tokio::io::AsyncReadExt::read(&mut handed, &mut storage)
            .await
            .err()
            .ok_or("reads must fail")?;
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            quiet(&mut incoming).await,
            "{kind:?}: the queued one is skipped"
        );
        for port in [40_110, 40_112, 40_113] {
            assert!(!owns_tcp(&handle, client(port), server), "{kind:?} {port}");
        }
        // The SYN-ACK of the revoked handshake never leaves.
        let leaving: Vec<_> = std::iter::from_fn(|| peer.source.try_admit()).collect();
        assert!(
            leaving
                .iter()
                .all(|packet| tcp_tuple(packet.as_packet()) != Some((server, client(40_113)))),
            "{kind:?}"
        );
        // The other label's connection still works.
        peer.socket(other_socket).send_slice(b"other")?;
        pump_labeled(&mut peer, Some(L2)).await;
        sleep(Duration::from_millis(20)).await;
        assert_eq!(try_read(&mut other), b"other", "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn revoking_a_label_retires_connections_waiting_for_the_accept_queue() -> TestResult {
    for kind in KINDS {
        let mut config = stack_config(kind);
        config.accept_capacity = 1;
        config.accept_backpressure = true;
        let (handle, mut peer) = RawPeer::start(config, CLIENT, 63);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let first = peer.connect(LOCAL, 443, 40_120)?;
        let second = peer.connect(LOCAL, 443, 40_121)?;
        for _ in 0..200 {
            pump_labeled(&mut peer, Some(L1)).await;
            if peer.state(first) == tcp::State::Established
                && peer.state(second) == tcp::State::Established
            {
                break;
            }
        }
        pump_labeled(&mut peer, Some(L1)).await;
        assert_eq!(
            revoke(&handle, L1).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        assert!(quiet(&mut incoming).await, "{kind:?}");
    }
    Ok(())
}

// ── Queued input and fragments ───────────────────────────────────────

#[tokio::test]
async fn revoking_a_label_drops_its_input_still_queued_in_the_stack() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let (remote, fresh): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "10.9.0.2:5001".parse()?);
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        datagram(&sink, remote, local, b"old", Some(L1)).await?;
        let mut old = flow(&mut incoming).await?;
        assert_eq!(received(&mut old).await?, b"old");

        // Queued complete input of the old lifetime; the stack has not taken it yet.
        let before = handle.retired_drops();
        datagram(&sink, remote, local, b"queued", Some(L1)).await?;
        datagram(&sink, fresh, local, b"queued", Some(L1)).await?;
        assert_eq!(
            revoke(&handle, L1).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        assert!(timeout(WAIT, old.recv()).await?.is_none());
        until_stats(&handle, |_| handle.retired_drops() == before + 2).await?;
        assert_eq!(handle.stats().label_revoked, 0, "{kind:?}");

        // A new resource on the same tuple, then an identical reinstall: each a fresh label,
        // and the input queued for the one before never reaches it.
        for (label, previous) in [(L2, None), (L3, Some(L2))] {
            if let Some(previous) = previous {
                datagram(&sink, remote, local, b"stale", Some(previous)).await?;
                assert_eq!(revoke(&handle, previous).await?, RetirementOutcome::Retired);
            }
            datagram(&sink, remote, local, b"new", Some(label)).await?;
            let mut new = flow(&mut incoming).await?;
            assert_eq!(new.ingress_label(), Some(label), "{kind:?}");
            assert_eq!(received(&mut new).await?, b"new", "{kind:?}");
            if previous.is_none() {
                assert_eq!(revoke(&handle, label).await?, RetirementOutcome::Retired);
            }
        }
        assert!(quiet(&mut incoming).await, "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn revoking_a_label_discards_its_partial_datagrams() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let remote: SocketAddr = "10.9.0.2:5000".parse()?;
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        datagram(&sink, remote, local, b"old", Some(L1)).await?;
        let mut old = flow(&mut incoming).await?;
        assert_eq!(received(&mut old).await?, b"old");
        // A partial datagram of the old lifetime, then the replacement.
        let (pieces, _) = fragmented(remote, local, 600, 9)?;
        send(&sink, &pieces[0], Some(L1)).await?;
        send(&sink, &pieces[1], Some(L1)).await?;
        sleep(Duration::from_millis(20)).await;
        assert_eq!(
            revoke(&handle, L1).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        // The rest arrives with the new label and completes nothing.
        send(&sink, &pieces[1], Some(L2)).await?;
        send(&sink, &pieces[2], Some(L2)).await?;
        // A late fragment with the old label is dropped as revoked.
        send(&sink, &pieces[2], Some(L1)).await?;
        until_stats(&handle, |stats| stats.label_revoked == 1).await?;
        assert!(quiet(&mut incoming).await, "{kind:?}");
        let stats = handle.stats();
        assert_eq!(
            (stats.reassembled, stats.label_mismatch),
            (0, 0),
            "{kind:?}"
        );
        // The new lifetime starts with its own input.
        datagram(&sink, remote, local, b"new", Some(L2)).await?;
        let mut new = flow(&mut incoming).await?;
        assert_eq!(new.ingress_label(), Some(L2));
        assert_eq!(received(&mut new).await?, b"new", "{kind:?}");
    }
    Ok(())
}

// ── Outcomes and tombstones ──────────────────────────────────────────

#[tokio::test]
async fn a_full_table_fails_the_revoke_and_a_later_call_retires() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let (first, second): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "10.9.0.2:5001".parse()?);
    INGRESS_FENCE_LIMIT.with(|limit| limit.set(Some(1)));
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        datagram(&sink, first, local, b"1", Some(L1)).await?;
        let mut one = flow(&mut incoming).await?;
        datagram(&sink, second, local, b"2", Some(L2)).await?;
        let mut two = flow(&mut incoming).await?;
        assert_eq!(received(&mut one).await?, b"1");
        assert_eq!(received(&mut two).await?, b"2");

        // Input of both labels queued: each revoke needs an ingress position, and the
        // table holds one.
        datagram(&sink, first, local, b"q", Some(L1)).await?;
        datagram(&sink, second, local, b"q", Some(L2)).await?;
        let (one_receipt, two_receipt) = (handle.revoke_label(L1), handle.revoke_label(L2));
        assert_eq!(
            timeout(WAIT, one_receipt.wait()).await?,
            RetirementOutcome::Retired
        );
        assert_eq!(
            timeout(WAIT, two_receipt.wait()).await?,
            RetirementOutcome::Failed,
            "{kind:?}"
        );
        // Everything found was retired all the same.
        assert!(two.control().is_revoked(), "{kind:?}");
        assert!(timeout(WAIT, two.recv()).await?.is_none());
        assert!(timeout(WAIT, one.recv()).await?.is_none());
        // Once the queue moved past the call, a second call fits.
        until_stats(&handle, |stats| stats.label_revoked == 1).await?;
        assert_eq!(
            revoke(&handle, L2).await?,
            RetirementOutcome::Retired,
            "{kind:?}"
        );
        assert!(quiet(&mut incoming).await, "{kind:?}");
    }
    INGRESS_FENCE_LIMIT.with(|limit| limit.set(None));
    Ok(())
}

#[tokio::test]
async fn a_label_used_after_its_revoke_is_dropped_and_opens_nothing() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let (remote, fresh): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "10.9.0.2:5001".parse()?);
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 64);
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        let mut incoming_tcp = handle.incoming_tcp();
        datagram(&peer.sink, remote, local, b"a", Some(L1)).await?;
        let _flow = flow(&mut incoming).await?;
        assert_eq!(revoke(&handle, L1).await?, RetirementOutcome::Retired);

        datagram(&peer.sink, remote, local, b"late", Some(L1)).await?;
        datagram(&peer.sink, fresh, local, b"late", Some(L1)).await?;
        until_stats(&handle, |stats| stats.label_revoked == 2).await?;
        assert!(quiet(&mut incoming).await, "{kind:?}");

        // A SYN with the label opens no connection and is not answered.
        let socket = peer.connect(LOCAL, 443, 40_130)?;
        for _ in 0..10 {
            pump_labeled(&mut peer, Some(L1)).await;
        }
        assert_eq!(peer.state(socket), tcp::State::SynSent, "{kind:?}");
        assert!(handle.stats().label_revoked >= 3, "{kind:?}");
        assert!(quiet(&mut incoming_tcp).await, "{kind:?}");
        // Only the first datagram was admitted (counted on the transparent stacks).
        let stats = handle.stats();
        let admitted = u64::from(kind != Kind::Ordinary);
        assert_eq!((stats.accepted, stats.pending), (admitted, 0), "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn the_same_tuple_after_retired_opens_a_fresh_lifetime() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let remote: SocketAddr = "10.9.0.2:5000".parse()?;
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 65);
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();
        let mut incoming_tcp = handle.incoming_tcp();

        datagram(&peer.sink, remote, local, b"old", Some(L1)).await?;
        let mut old = flow(&mut incoming).await?;
        let (socket, mut conn) = connected(&mut peer, &mut incoming_tcp, 40_140, Some(L1)).await?;
        assert_eq!(revoke(&handle, L1).await?, RetirementOutcome::Retired);
        assert!(timeout(WAIT, old.recv()).await?.is_none());
        assert_eq!(try_read(&mut conn), b"");

        datagram(&peer.sink, remote, local, b"new", Some(L2)).await?;
        let mut new = flow(&mut incoming).await?;
        assert_eq!(new.ingress_label(), Some(L2), "{kind:?}");
        assert_eq!(received(&mut new).await?, b"new");

        // The client starts over from the same port.
        peer.sockets.remove(socket);
        let (_, fresh) = connected(&mut peer, &mut incoming_tcp, 40_140, Some(L2)).await?;
        assert_eq!(fresh.ingress_label(), Some(L2), "{kind:?}");
        assert!(!fresh.control().is_revoked());
    }
    Ok(())
}

#[tokio::test]
async fn tombstones_are_bounded_by_max_revoked_labels() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let mut config = stack_config(Kind::Ordinary);
    config.max_revoked_labels = 2;
    let (stack, handle) = NetStack::new(config);
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    for (port, label) in [(5000, L1), (5001, L2), (5002, L3)] {
        datagram(
            &sink,
            SocketAddr::new(CLIENT.into(), port),
            local,
            b"x",
            Some(label),
        )
        .await?;
        let _ = flow(&mut incoming).await?;
        assert_eq!(revoke(&handle, label).await?, RetirementOutcome::Retired);
    }
    let remote = SocketAddr::new(CLIENT.into(), 6000);
    datagram(&sink, remote, local, b"3", Some(L3)).await?;
    until_stats(&handle, |stats| stats.label_revoked == 1).await?;
    // The oldest tombstone is gone: its label opens a lifetime again.
    datagram(&sink, remote, local, b"1", Some(L1)).await?;
    let reopened = flow(&mut incoming).await?;
    assert_eq!(reopened.ingress_label(), Some(L1));
    Ok(())
}

#[tokio::test]
async fn revoking_a_label_on_a_stopped_stack_is_unknown() -> TestResult {
    let (stack, handle) = NetStack::new(stack_config(Kind::Ordinary));
    let (source, sink) = stack.split();
    drop(sink);
    drop(source);
    timeout(WAIT, async {
        while handle.revoke_label(L1).outcome() != Some(RetirementOutcome::Unknown) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(revoke(&handle, L2).await?, RetirementOutcome::Unknown);
    Ok(())
}
