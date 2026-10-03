//! The host callback local side: queueing, closing, oversize drops and the write callback.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nsplane::{HEADROOM, PacketBatch, PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_tun::{
    HOST_TUN_DEFAULT_CAPACITY, HostTunInput, HostTunSink, HostTunSource, PushError, host_tun,
};
use tokio::time::timeout;

const MTU: u16 = 1280;
const WAIT: Duration = Duration::from_secs(5);

/// A host tun whose writes are discarded.
fn discarding(capacity: usize) -> (HostTunInput, HostTunSource, HostTunSink) {
    host_tun(MTU, capacity, Arc::new(|_: &[u8]| true))
}

async fn recv(source: &mut HostTunSource) -> io::Result<PacketBuf> {
    timeout(WAIT, source.recv())
        .await
        .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "recv timed out")))
}

#[tokio::test]
async fn packets_arrive_in_order_with_headroom() {
    let (input, mut source, _sink) = discarding(HOST_TUN_DEFAULT_CAPACITY);
    for i in 0..3u8 {
        input.push(&[i; 40]).unwrap();
    }
    for i in 0..3u8 {
        let packet = recv(&mut source).await.unwrap();
        assert_eq!(packet.as_packet(), [i; 40]);
        assert!(packet.headroom() >= HEADROOM);
    }
}

#[tokio::test]
async fn recv_batch_drains_queued_packets() {
    let (input, mut source, _sink) = discarding(16);
    for i in 0..5u8 {
        input.push(&[i; 20]).unwrap();
    }
    let mut batch = PacketBatch::new();
    timeout(WAIT, source.recv_batch(&mut batch))
        .await
        .unwrap()
        .unwrap();
    let packets: Vec<Vec<u8>> = batch.iter().map(|p| p.as_packet().to_vec()).collect();
    let expected: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 20]).collect();
    assert_eq!(packets, expected);
}

#[tokio::test]
async fn full_at_capacity_and_recovers_after_recv() {
    let (input, mut source, _sink) = discarding(2);
    input.push(&[1; 20]).unwrap();
    input.push(&[2; 20]).unwrap();
    assert_eq!(input.push(&[3; 20]), Err(PushError::Full));
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [1; 20]);
    input.push(&[4; 20]).unwrap();
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [2; 20]);
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [4; 20]);
}

#[tokio::test]
async fn closed_after_the_source_drops() {
    let (input, source, _sink) = discarding(4);
    drop(source);
    assert_eq!(input.push(&[1; 20]), Err(PushError::Closed));
}

#[tokio::test]
async fn broken_pipe_once_inputs_drop_and_the_queue_drains() {
    let (input, mut source, _sink) = discarding(4);
    let clone = input.clone();
    input.push(&[1; 20]).unwrap();
    clone.push(&[2; 20]).unwrap();
    drop(input);
    drop(clone);
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [1; 20]);
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [2; 20]);
    for _ in 0..2 {
        let err = recv(&mut source).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
    let mut batch = PacketBatch::new();
    let err = source.recv_batch(&mut batch).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn oversize_packets_are_dropped_and_counted() {
    let (input, mut source, _sink) = discarding(8);
    let mtu = usize::from(MTU);
    input.push(&[1; 1281]).unwrap();
    input.push(&vec![2; mtu]).unwrap();
    input.push(&[3; 2000]).unwrap();
    input.push(&[4; 20]).unwrap();
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), vec![2; mtu]);
    assert_eq!(source.oversize_drops(), 1);
    let mut batch = PacketBatch::new();
    timeout(WAIT, source.recv_batch(&mut batch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.iter().next().unwrap().as_packet(), [4; 20]);
    assert_eq!(source.oversize_drops(), 2);
}

#[tokio::test]
async fn sink_writes_the_exact_bytes() {
    let written = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&written);
    let (_input, _source, sink) = host_tun(
        MTU,
        4,
        Arc::new(move |packet: &[u8]| {
            log.lock().unwrap().push(packet.to_vec());
            true
        }),
    );
    let packet: Vec<u8> = (0..=255).collect();
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(1))
        .await
        .unwrap();
    sink.send(PacketBuf::from_packet(b"second"), PeerId::new(2))
        .await
        .unwrap();
    assert_eq!(*written.lock().unwrap(), vec![packet, b"second".to_vec()]);
}

#[tokio::test]
async fn write_returning_false_is_broken_pipe() {
    let open = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&open);
    let (_input, _source, sink) = host_tun(
        MTU,
        4,
        Arc::new(move |_: &[u8]| flag.load(Ordering::SeqCst)),
    );
    sink.send(PacketBuf::from_packet(b"ok"), PeerId::new(1))
        .await
        .unwrap();
    open.store(false, Ordering::SeqCst);
    let err = sink
        .send(PacketBuf::from_packet(b"lost"), PeerId::new(1))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn push_from_a_plain_thread_wakes_a_pending_recv() {
    let (input, mut source, _sink) = discarding(4);
    let host = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        input.push(&[9; 60]).unwrap();
    });
    assert_eq!(recv(&mut source).await.unwrap().as_packet(), [9; 60]);
    host.join().unwrap();
}

#[tokio::test]
async fn mtu_watch_reports_the_constructor_mtu() {
    let (_input, source, _sink) = host_tun(1400, 4, Arc::new(|_: &[u8]| true));
    assert_eq!(*source.mtu().borrow(), 1400);
}
