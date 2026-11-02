//! Lifetime labels across the public netstack and encrypted engine boundaries.
#![allow(clippy::unwrap_used, reason = "test harness")]

use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nsplane::{ChannelTransport, PacketBuf, PacketFilter, PeerId, TransportId};
use nsplane_core::Verdict;
use nsplane_e2e::{Family, StackNode, TestResult, WAIT, next_within};
use nsplane_netstack::{DEFAULT_MTU, RetirementOutcome};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

struct Labels {
    current: Arc<AtomicU64>,
    output: Arc<Mutex<Vec<Option<NonZeroU64>>>>,
}

impl PacketFilter for Labels {
    fn inbound(&self, _: PeerId, packet: &mut PacketBuf) -> Verdict {
        packet.set_tag(NonZeroU64::new(self.current.load(Ordering::SeqCst)));
        Verdict::Accept
    }

    fn outbound(&self, _: PeerId, packet: &mut PacketBuf) -> Verdict {
        self.output.lock().unwrap().push(packet.tag());
        Verdict::Accept
    }
}

#[tokio::test]
async fn active_tcp_and_connected_udp_keep_labels_through_engines() -> TestResult {
    for workers in [0, 2] {
        let a = (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        );
        let b = (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        );
        let (left, right) = ChannelTransport::pair(1024, a, b);
        let current = Arc::new(AtomicU64::new(41));
        let output = Arc::new(Mutex::new(Vec::new()));
        let filter = || {
            Box::new(Labels {
                current: Arc::clone(&current),
                output: Arc::clone(&output),
            })
        };
        let a = StackNode::with_builder(1, a.0, a.1, DEFAULT_MTU, |builder| {
            builder
                .transport(left)
                .filter(filter())
                .crypto_workers(workers)
        })?;
        let b = StackNode::with_builder(2, b.0, b.1, DEFAULT_MTU, |builder| {
            builder
                .transport(right)
                .filter(filter())
                .crypto_workers(workers)
        })?;
        a.handle
            .add_or_update_peer(b.as_peer(a.path.transport))
            .await?;
        b.handle
            .add_or_update_peer(a.as_peer(b.path.transport))
            .await?;
        let mut tcp = b.stack.incoming_tcp();
        let mut udp = b.stack.incoming_udp();
        for (family, first) in [(Family::V4, 41), (Family::V6, 43)] {
            for id in [first, first + 1] {
                current.store(id, Ordering::SeqCst);
                let label = NonZeroU64::new(id).unwrap();
                let mut client = timeout(
                    WAIT,
                    a.stack
                        .connect_tcp_from_labeled(5000, b.socket_addr(family, 9000), label),
                )
                .await??;
                let mut server = next_within(&mut tcp, WAIT).await?;
                assert_eq!(client.ingress_label(), Some(label));
                assert_eq!(server.ingress_label(), Some(label));
                client.write_all(b"labeled TCP").await?;
                client.shutdown().await?;
                let mut data = Vec::new();
                timeout(WAIT, server.read_to_end(&mut data)).await??;
                assert_eq!(data, b"labeled TCP");
                server.shutdown().await?;
                timeout(WAIT, client.read_to_end(&mut Vec::new())).await??;
                let mut socket = a
                    .stack
                    .connect_udp_from_labeled(
                        a.socket_addr(family, 5001),
                        b.socket_addr(family, 9001),
                        label,
                    )
                    .await?;
                socket.send(b"labeled UDP").await?;
                let mut flow = next_within(&mut udp, WAIT).await?;
                assert_eq!(flow.ingress_label(), Some(label));
                assert_eq!(
                    timeout(WAIT, flow.recv()).await?.ok_or("UDP ended")?,
                    b"labeled UDP"[..]
                );
                flow.send(b"reply").await?;
                assert_eq!(timeout(WAIT, socket.recv_from()).await??.0, b"reply"[..]);
                assert_eq!(
                    timeout(WAIT, a.stack.revoke_label(label).wait()).await?,
                    RetirementOutcome::Retired
                );
                assert_eq!(
                    timeout(WAIT, b.stack.revoke_label(label).wait()).await?,
                    RetirementOutcome::Retired
                );
            }
        }
        let tags = output.lock().unwrap();
        assert!(!tags.is_empty());
        assert!(
            tags.iter()
                .all(|tag| matches!(tag.map(NonZeroU64::get), Some(41..=44)))
        );
        assert!(tags.contains(&NonZeroU64::new(42)));
    }
    Ok(())
}
