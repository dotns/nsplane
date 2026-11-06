//! Real user-space TCP through two translators: a calculated application payload
//! produces a zero checksum either at stack egress or after the IPv6 update.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use nsplane::{PacketSink, PacketSource};
use nsplane_core::{PacketFilter, Verdict};
use nsplane_e2e::{TRANSFER, TestResult, next_within};
use nsplane_nat::{PeerMapping, SelfMapping, TranslationTable, Translator};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackSink, NetStackSource};
use nsplane_packet::checksum::{transport_checksum_v4, transport_checksum_v6};
use nsplane_packet::{PeerId, protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;

const A4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const B4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
const A6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const B6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
const PEER: PeerId = PeerId::new(1);

fn translator(
    local4: Ipv4Addr,
    local6: Ipv6Addr,
    remote4: Ipv4Addr,
    remote6: Ipv6Addr,
) -> TestResult<Translator> {
    Ok(Translator::new(
        TranslationTable::builder()
            .self_mapping(SelfMapping {
                eam4: local4,
                eam6: local6,
            })
            .peer(
                PEER,
                PeerMapping {
                    peer6: Ipv6Addr::from_bits(remote6.to_bits() + 0x100),
                    eam6: remote6,
                    local6: None,
                    eam4: Some(remote4),
                },
            )
            .build()?,
    ))
}

#[derive(Default)]
struct Zeros {
    emitted: AtomicUsize,
    translated: AtomicUsize,
}

/// Predict the next two-byte write from the first two-byte segment's TCP header.
/// The connection only sends data, so its receive window and ACK stay unchanged.
fn next_payload(segment: &[u8], translated: bool) -> TestResult<[u8; 2]> {
    let mut next = segment.to_vec();
    let header = usize::from(next[12] >> 4) * 4;
    assert_eq!(next.len(), header + 2);
    let seq = u32::from_be_bytes(next[4..8].try_into()?).wrapping_add(2);
    next[4..8].copy_from_slice(&seq.to_be_bytes());
    next[16..18].fill(0);
    next[header..].fill(0);
    let word = if translated {
        transport_checksum_v6(A6, B6, protocol::TCP, &next)
    } else {
        transport_checksum_v4(A4, B4, protocol::TCP, &next)
    };
    Ok(word.to_be_bytes())
}

async fn wire(
    mut source: NetStackSource,
    sink: NetStackSink,
    from: Arc<Translator>,
    to: Arc<Translator>,
    mut payload: Option<oneshot::Sender<[u8; 2]>>,
    translated: bool,
    zeros: Arc<Zeros>,
) -> TestResult {
    loop {
        let mut packet = source.recv().await?;
        let bytes = packet.as_packet();
        assert_eq!(bytes[0] >> 4, 4);
        assert_eq!(bytes[9], protocol::TCP);
        let ihl = usize::from(bytes[0] & 0xf) * 4;
        let segment = &bytes[ihl..];
        if segment[16..18] == [0, 0] {
            assert_eq!(transport_checksum_v4(A4, B4, protocol::TCP, segment), 0);
            zeros.emitted.fetch_add(1, Ordering::Relaxed);
        }
        let header = usize::from(segment[12] >> 4) * 4;
        if segment.len() > header
            && let Some(tx) = payload.take()
        {
            tx.send(next_payload(segment, translated)?)
                .map_err(|_| "payload receiver closed")?;
        }
        let verdict = from.outbound(PEER, &mut packet);
        if verdict != Verdict::Accept {
            return Err(format!("outbound translation: {verdict:?}").into());
        }
        let bytes = packet.as_packet();
        if bytes[56..58] == [0, 0] {
            assert_eq!(
                transport_checksum_v6(A6, B6, protocol::TCP, &bytes[40..]),
                0
            );
            zeros.translated.fetch_add(1, Ordering::Relaxed);
        }
        let verdict = to.inbound(PEER, &mut packet);
        if verdict != Verdict::Accept {
            return Err(format!("inbound translation: {verdict:?}").into());
        }
        sink.send(packet, PEER).await?;
    }
}

async fn transfer(translated: bool) -> TestResult {
    let config = |ip| NetStackConfig::new(vec![(IpAddr::V4(ip), 32)], DEFAULT_MTU);
    let (stack_a, a) = NetStack::new(config(A4));
    let (stack_b, b) = NetStack::new(config(B4));
    let (source_a, sink_a) = stack_a.split();
    let (source_b, sink_b) = stack_b.split();
    let from = Arc::new(translator(A4, A6, B4, B6)?);
    let to = Arc::new(translator(B4, B6, A4, A6)?);
    let zeros = Arc::new(Zeros::default());
    let (tx, rx) = oneshot::channel();
    let mut outbound = tokio::spawn(wire(
        source_a,
        sink_b,
        Arc::clone(&from),
        Arc::clone(&to),
        Some(tx),
        translated,
        Arc::clone(&zeros),
    ));
    let mut inbound = tokio::spawn(wire(
        source_b,
        sink_a,
        Arc::clone(&to),
        Arc::clone(&from),
        None,
        translated,
        Arc::new(Zeros::default()),
    ));
    let mut incoming = b.incoming_tcp();
    let exchange = async {
        let (client, server) = tokio::join!(
            a.connect_tcp(SocketAddr::new(B4.into(), 9000)),
            next_within(&mut incoming, TRANSFER)
        );
        let (mut client, mut server) = (client?, server?);
        let mut expected = vec![0, 0];
        let mut received = Vec::new();
        let send = async {
            client.write_all(&[0, 0]).await?;
            client.flush().await?;
            let word = rx.await?;
            client.write_all(&word).await?;
            client.flush().await?;
            expected.extend_from_slice(&word);
            let tail: Vec<u8> = (0_u32..65536).map(|i| (i % 251).to_le_bytes()[0]).collect();
            client.write_all(&tail).await?;
            client.flush().await?;
            expected.extend_from_slice(&tail);
            client.shutdown().await?;
            TestResult::Ok(())
        };
        let receive = async {
            server.read_to_end(&mut received).await?;
            TestResult::Ok(())
        };
        tokio::try_join!(send, receive)?;
        assert_eq!(received, expected);
        TestResult::Ok(())
    };
    let result = tokio::select! {
        biased;
        result = &mut outbound => result.map_err(Into::into).and_then(|r| r),
        result = &mut inbound => result.map_err(Into::into).and_then(|r| r),
        result = timeout(TRANSFER, exchange) => result.map_err(Into::into).and_then(|r| r),
    };
    outbound.abort();
    inbound.abort();
    result?;
    let seen = if translated {
        &zeros.translated
    } else {
        &zeros.emitted
    };
    assert!(
        seen.load(Ordering::Relaxed) > 0,
        "the calculated payload must produce a zero checksum"
    );
    assert_eq!(
        (
            from.stats().dropped_out,
            from.stats().dropped_in,
            to.stats().dropped_out,
            to.stats().dropped_in
        ),
        (0, 0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn tcp_zero_checksum_emitted_by_stack_delivers_and_flushes() -> TestResult {
    transfer(false).await
}

#[tokio::test]
async fn tcp_zero_checksum_after_translation_delivers_and_flushes() -> TestResult {
    transfer(true).await
}
