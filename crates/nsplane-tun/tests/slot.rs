//! `TunSlot` over datagram socket pairs standing in for a `VpnService` fd (they keep
//! packet boundaries); needs no privileges.

#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]

use std::error::Error;
use std::io;
use std::os::fd::OwnedFd;
use std::pin::pin;
use std::time::Duration;

use nsplane::{HEADROOM, PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_tun::{SlotSink, SlotSource, TunSlot};
use tokio::net::UnixDatagram;
use tokio::time::timeout;

const MTU: u16 = 100;
const WAIT: Duration = Duration::from_secs(5);
const QUIET: Duration = Duration::from_millis(100);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The slot's end as an fd and the host's end as a tokio socket.
fn pair() -> io::Result<(OwnedFd, UnixDatagram)> {
    let (slot, host) = std::os::unix::net::UnixDatagram::pair()?;
    host.set_nonblocking(true)?;
    Ok((OwnedFd::from(slot), UnixDatagram::from_std(host)?))
}

/// A slot with one fd installed, and the host's end of it.
fn installed() -> io::Result<(TunSlot, SlotSource, SlotSink, UnixDatagram)> {
    let (slot, source, sink) = TunSlot::new(MTU);
    let (fd, host) = pair()?;
    slot.replace(fd)?;
    Ok((slot, source, sink, host))
}

async fn recv(source: &mut SlotSource) -> TestResult<Vec<u8>> {
    Ok(timeout(WAIT, source.recv()).await??.as_packet().to_vec())
}

async fn send(sink: &SlotSink, packet: &[u8]) -> TestResult {
    let send = sink.send(PacketBuf::from_packet(packet), PeerId::new(0));
    Ok(timeout(WAIT, send).await??)
}

async fn host_recv(host: &UnixDatagram) -> TestResult<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let len = timeout(WAIT, host.recv(&mut buf)).await??;
    Ok(buf[..len].to_vec())
}

/// Whether nothing is queued on `host`.
fn is_empty(host: &UnixDatagram) -> bool {
    let mut buf = [0u8; 2048];
    matches!(host.try_recv(&mut buf), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
}

#[tokio::test]
async fn round_trip_both_ways() {
    let (_slot, mut source, sink, host) = installed().unwrap();

    host.send(&[0x45, 1, 2, 3]).await.unwrap();
    let packet = timeout(WAIT, source.recv()).await.unwrap().unwrap();
    assert_eq!(packet.as_packet(), [0x45, 1, 2, 3]);
    assert_eq!(packet.headroom(), HEADROOM);
    assert!(packet.capacity() > usize::from(MTU));

    send(&sink, &[0x60, 4, 5]).await.unwrap();
    assert_eq!(host_recv(&host).await.unwrap(), [0x60, 4, 5]);
}

#[tokio::test]
async fn oversize_reads_are_dropped_and_counted() {
    let (_slot, mut source, _sink, host) = installed().unwrap();
    let mtu = usize::from(MTU);

    host.send(&vec![1; mtu + 1]).await.unwrap();
    host.send(&vec![2; 5000]).await.unwrap();
    host.send(&vec![3; mtu]).await.unwrap();
    host.send(&[4]).await.unwrap();
    assert_eq!(recv(&mut source).await.unwrap(), vec![3; mtu]);
    assert_eq!(recv(&mut source).await.unwrap(), [4]);
    assert_eq!(source.oversize_drops(), 2);
}

#[tokio::test]
async fn empty_read_is_unexpected_eof() {
    let (_slot, mut source, _sink, host) = installed().unwrap();
    host.send(&[]).await.unwrap();
    let err = timeout(WAIT, source.recv()).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn io_waits_for_the_first_fd() {
    let (slot, mut source, sink) = TunSlot::new(MTU);
    let mut recv = pin!(source.recv());
    let mut send = pin!(sink.send(PacketBuf::from_packet(&[0x45]), PeerId::new(0)));
    assert!(timeout(QUIET, recv.as_mut()).await.is_err());
    assert!(timeout(QUIET, send.as_mut()).await.is_err());

    let (fd, host) = pair().unwrap();
    slot.replace(fd).unwrap();
    host.send(&[0x45, 9]).await.unwrap();
    let packet = timeout(WAIT, recv).await.unwrap().unwrap();
    assert_eq!(packet.as_packet(), [0x45, 9]);
    timeout(WAIT, send).await.unwrap().unwrap();
    assert_eq!(host_recv(&host).await.unwrap(), [0x45]);
}

#[tokio::test]
async fn disable_parks_io_until_enable() {
    let (slot, mut source, sink, host) = installed().unwrap();
    slot.disable();
    host.send(&[0x45, 1]).await.unwrap();
    let mut recv = pin!(source.recv());
    let mut send = pin!(sink.send(PacketBuf::from_packet(&[0x45, 2]), PeerId::new(0)));
    assert!(timeout(QUIET, recv.as_mut()).await.is_err());
    assert!(timeout(QUIET, send.as_mut()).await.is_err());
    assert!(is_empty(&host));

    slot.enable();
    let packet = timeout(WAIT, recv).await.unwrap().unwrap();
    assert_eq!(packet.as_packet(), [0x45, 1]);
    timeout(WAIT, send).await.unwrap().unwrap();
    assert_eq!(host_recv(&host).await.unwrap(), [0x45, 2]);
}

#[tokio::test]
async fn replace_fences_the_previous_fd() {
    let (slot, mut source, sink, old) = installed().unwrap();
    old.send(&[0x45, 0]).await.unwrap();
    old.send(&[0x45, 1]).await.unwrap();
    assert_eq!(recv(&mut source).await.unwrap(), [0x45, 0]);
    send(&sink, &[0x45, 10]).await.unwrap();
    assert_eq!(host_recv(&old).await.unwrap(), [0x45, 10]);

    let (fd, new) = pair().unwrap();
    slot.replace(fd).unwrap();
    // The previous fd is closed: nothing holds it any more.
    assert!(old.try_send(&[0x45, 99]).is_err());

    new.send(&[0x45, 2]).await.unwrap();
    new.send(&[0x45, 3]).await.unwrap();
    // The packet left on the previous fd is gone with it.
    assert_eq!(recv(&mut source).await.unwrap(), [0x45, 2]);
    assert_eq!(recv(&mut source).await.unwrap(), [0x45, 3]);
    send(&sink, &[0x45, 11]).await.unwrap();
    send(&sink, &[0x45, 12]).await.unwrap();
    assert_eq!(host_recv(&new).await.unwrap(), [0x45, 11]);
    assert_eq!(host_recv(&new).await.unwrap(), [0x45, 12]);
    assert!(is_empty(&old));
}

#[tokio::test]
async fn replace_wakes_a_waiting_recv() {
    let (slot, mut source, _sink, old) = installed().unwrap();
    let mut recv = pin!(source.recv());
    assert!(timeout(QUIET, recv.as_mut()).await.is_err());

    let (fd, new) = pair().unwrap();
    slot.replace(fd).unwrap();
    new.send(&[0x45, 7]).await.unwrap();
    let packet = timeout(WAIT, recv).await.unwrap().unwrap();
    assert_eq!(packet.as_packet(), [0x45, 7]);
    drop(old);
}

#[tokio::test]
async fn close_breaks_both_sides() {
    let (slot, mut source, sink, _host) = installed().unwrap();
    {
        let mut recv = pin!(source.recv());
        assert!(timeout(QUIET, recv.as_mut()).await.is_err());

        slot.close();
        let err = timeout(WAIT, recv).await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
    let err = source.recv().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    let err = sink
        .send(PacketBuf::from_packet(&[0x45]), PeerId::new(0))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    let (fd, _host) = pair().unwrap();
    let err = slot.replace(fd).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn dropping_the_last_handle_closes() {
    let (slot, mut source, _sink, _host) = installed().unwrap();
    let clone = slot.clone();
    drop(slot);
    let mut recv = pin!(source.recv());
    assert!(timeout(QUIET, recv.as_mut()).await.is_err());

    drop(clone);
    let err = timeout(WAIT, recv).await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn mtu_is_the_constructor_value() {
    let (_slot, source, _sink) = TunSlot::new(1280);
    assert_eq!(*source.mtu().borrow(), 1280);
}

#[test]
fn replace_needs_a_runtime() {
    let (slot, _source, _sink) = TunSlot::new(MTU);
    let (fd, _host) = std::os::unix::net::UnixDatagram::pair().unwrap();
    assert!(slot.replace(OwnedFd::from(fd)).is_err());
}
