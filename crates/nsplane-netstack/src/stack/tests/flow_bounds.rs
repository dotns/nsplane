use std::net::SocketAddrV4;

use nsplane_packet::PacketPool;
use nsplane_packet::reassembly::ReassemblyConfig;

use super::*;
use crate::{FlowControl, RetirementOutcome};

// ── Retirement bounds: placeholders, UDP marks and positions, barriers ─

/// The `(src, dst)` and payload of a UDP packet.
fn datagram(packet: &PacketBuf) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    udp::parse_udp(packet.clone())
        .map(|datagram| (datagram.src, datagram.dst, datagram.payload.to_vec()))
}

/// Takes every packet the stack lets out until it stays quiet for 50 ms.
async fn drain(source: &mut NetStackSource) -> Vec<PacketBuf> {
    let mut packets = Vec::new();
    while let Ok(Ok(packet)) = timeout(Duration::from_millis(50), source.recv()).await {
        packets.push(packet);
    }
    packets
}

/// Revokes `control` and waits for the outcome.
async fn retire(control: &FlowControl) -> Result<RetirementOutcome, Box<dyn Error>> {
    Ok(timeout(WAIT, control.revoke().wait()).await?)
}

/// Sends `payload` from `socket` to `remote`; fails instead of waiting for room.
async fn send(socket: &UdpSocket, payload: &[u8], remote: SocketAddr) -> TestResult {
    timeout(WAIT, socket.send_to(payload, remote))
        .await
        .map_err(|_| "the send queue should have room")??;
    Ok(())
}

#[tokio::test]
async fn placeholders_never_leave_the_source() -> TestResult {
    let mut config = config(Ipv4Addr::new(10, 9, 70, 1));
    config.egress_capacity = 4;
    let (stack, handle) = NetStack::new(config);
    let (mut source, _sink) = stack.split();
    let remote: SocketAddr = "10.9.70.2:53".parse()?;
    let revoked = handle.bind_udp("10.9.70.1:5001".parse()?).await?;
    let other = handle.bind_udp("10.9.70.1:5002".parse()?).await?;

    // Nobody drains the egress: four of the other flow's datagrams fill it, and the
    // backlog behind it holds both flows' datagrams, interleaved.
    for seq in 0..4u8 {
        send(&other, &[seq], remote).await?;
    }
    sleep(Duration::from_millis(20)).await;
    for seq in 4..24u8 {
        send(&revoked, b"revoked", remote).await?;
        send(&other, &[seq], remote).await?;
    }
    sleep(Duration::from_millis(20)).await;
    assert_eq!(retire(&revoked.control()).await?, RetirementOutcome::Retired);
    // Twenty placeholders in the backlog, each counted once, when it was purged.
    assert_eq!(handle.retired_drops(), 20);

    let packets = drain(&mut source).await;
    // Every position went through the egress queue, placeholders included ...
    assert_eq!(source.received, 44);
    // ... and only the other flow's packets came out, in order and none of them empty.
    assert!(packets.iter().all(|packet| !packet.is_empty()));
    let expected: Vec<_> = (0..24u8)
        .map(|seq| (other.local_addr(), remote, vec![seq]))
        .collect();
    let got: Vec<_> = packets.iter().filter_map(datagram).collect();
    assert_eq!(got, expected);
    assert_eq!(packets.len(), 24);
    // The source discarded the placeholders without counting them again, and nothing
    // else counts them either.
    assert_eq!(handle.retired_drops(), 20);
    assert_eq!(handle.stats(), NetStackStats::default());

    // What the engine takes is recycled as usual: every buffer goes back to a pool and
    // is handed out again.
    let mut pool = PacketPool::new(packets.len());
    for packet in packets {
        pool.put(packet);
    }
    assert_eq!(pool.free_len(), 24);
    let reused = pool.get(1500);
    assert!(reused.is_empty() && reused.capacity() >= 1500);
    assert_eq!(pool.free_len(), 23);
    Ok(())
}

#[tokio::test]
async fn saturated_marks_and_positions_still_drop_every_retired_datagram() -> TestResult {
    const EGRESS: usize = 8;
    const BACKLOG: usize = 256;
    let mut config = config(Ipv4Addr::new(10, 9, 71, 1));
    config.egress_capacity = EGRESS;
    let (stack, handle) = NetStack::new(config);
    let (mut source, _sink) = stack.split();
    let remote: SocketAddr = "10.9.71.2:53".parse()?;
    let other = handle.bind_udp("10.9.71.1:5002".parse()?).await?;

    // Twice, so the second round runs on marks and positions left by the first.
    for round in 0..2u64 {
        let revoked = handle.bind_udp("10.9.71.1:0".parse()?).await?;
        // The egress queue holds only the revoked flow's datagrams: its position list
        // takes `egress_capacity` entries, the most it can hold.
        for _ in 0..EGRESS {
            send(&revoked, b"revoked", remote).await?;
        }
        sleep(Duration::from_millis(20)).await;
        // Then the backlog fills to its bound with both flows, interleaved: the marks
        // cover every datagram in the backlog and the egress queue, and the send queue
        // holds more of both.
        let pairs = BACKLOG / 2 + 50;
        for seq in 0..pairs {
            send(&revoked, b"revoked", remote).await?;
            send(&other, &seq.to_be_bytes(), remote).await?;
        }
        sleep(Duration::from_millis(20)).await;
        let before = handle.retired_drops();
        assert_eq!(retire(&revoked.control()).await?, RetirementOutcome::Retired);

        let packets = drain(&mut source).await;
        let revoked_tuple = revoked.local_addr();
        assert!(
            packets
                .iter()
                .filter_map(datagram)
                .all(|(src, _, _)| src != revoked_tuple),
            "round {round}: a retired datagram left"
        );
        let got: Vec<_> = packets.iter().filter_map(datagram).collect();
        let expected: Vec<_> = (0..pairs)
            .map(|seq| (other.local_addr(), remote, seq.to_be_bytes().to_vec()))
            .collect();
        assert_eq!(got, expected, "round {round}: the other flow loses nothing");
        let dropped = u64::try_from(EGRESS + pairs)?;
        assert_eq!(handle.retired_drops() - before, dropped, "round {round}");
    }
    assert_eq!(handle.stats(), NetStackStats::default());
    Ok(())
}

#[tokio::test]
async fn full_barrier_table_fails_tcp_and_udp_revokes() -> TestResult {
    let server: SocketAddrV4 = "10.9.72.1:80".parse()?;
    let client = Ipv4Addr::new(10, 9, 72, 2);
    let config = NetStackConfig {
        reassembly: Some(ReassemblyConfig {
            max_datagrams: 1,
            timeout: Duration::from_secs(5),
            ..ReassemblyConfig::default()
        }),
        ..config(*server.ip())
    };
    let (handle, mut peer) = RawPeer::start(config, client, 0xb0d5);
    let mut incoming = handle.incoming_tcp();
    let mut conns = Vec::new();
    for port in [49200, 49201] {
        let socket = peer.connect(*server.ip(), server.port(), port)?;
        peer.pump_until(|peer| peer.state(socket) == tcp::State::Established)
            .await?;
        conns.push(timeout(WAIT, next(&mut incoming)).await?.ok_or("no conn")?);
    }
    let udp = handle.bind_udp("10.9.72.1:5000".parse()?).await?;

    // A first fragment the reassembler holds: every revoke now needs a barrier, and the
    // table holds one.
    let remote: SocketAddr = SocketAddr::new(client.into(), 5353);
    let whole = build_udp(remote, "10.9.72.1:7000".parse()?, &[7; 2000]).ok_or("build")?;
    let mut first = whole.as_packet()[..20 + 1336].to_vec();
    let total = u16::try_from(first.len())?;
    first[2..4].copy_from_slice(&total.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    first[10..12].fill(0);
    let checksum = nsplane_packet::checksum::ipv4_header_checksum(&first);
    first[10..12].copy_from_slice(&checksum.to_be_bytes());
    peer.sink
        .send(PacketBuf::from_packet(&first), PeerId::new(0))
        .await?;
    sleep(Duration::from_millis(20)).await;

    let outcomes = [
        retire(&conns[0].control()).await?,
        retire(&conns[1].control()).await?,
        retire(&udp.control()).await?,
    ];
    assert_eq!(
        outcomes,
        [
            RetirementOutcome::Retired,
            RetirementOutcome::Failed,
            RetirementOutcome::Failed
        ]
    );
    // A failed revoke still retired the flow's state.
    let mut buf = [0; 8];
    let mut read_buf = ReadBuf::new(&mut buf);
    let read = std::future::poll_fn(|cx| {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut conns[1]), cx, &mut read_buf)
    })
    .await;
    assert_eq!(
        read.err().map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionAborted)
    );
    timeout(WAIT, conns[1].terminated()).await?;
    let error = udp.send_to(b"x", remote).await.err();
    assert_eq!(
        error.map(|error| error.kind()),
        Some(io::ErrorKind::ConnectionAborted)
    );
    assert!(handle.bind_udp("10.9.72.1:5000".parse()?).await.is_ok());
    Ok(())
}
