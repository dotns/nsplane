//! Darwin descriptor identity checks and a privileged real-utun smoke test.
#![cfg(any(target_os = "macos", target_os = "ios"))]

use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixDatagram, UnixStream};

use nsplane::PacketSource;
use nsplane_tun::Tun;

fn rejects_non_utun(fd: OwnedFd) -> io::Result<()> {
    let tun = Tun::from_fd(fd, 1420)?;
    assert_eq!(
        tun.name().err().and_then(|e| e.raw_os_error()),
        Some(libc::EINVAL)
    );
    let (source, sink) = tun.split()?;
    assert_eq!(
        source.name().err().and_then(|e| e.raw_os_error()),
        Some(libc::EINVAL)
    );
    assert_eq!(
        sink.name().err().and_then(|e| e.raw_os_error()),
        Some(libc::EINVAL)
    );
    assert_eq!(*source.mtu().borrow(), 1420);
    Ok(())
}

#[tokio::test]
async fn unix_datagram_pid_is_not_an_interface_name() {
    let (socket, _peer) = UnixDatagram::pair().unwrap();
    rejects_non_utun(socket.into()).unwrap();
}

#[tokio::test]
async fn unix_stream_pid_is_not_an_interface_name() {
    let (socket, _peer) = UnixStream::pair().unwrap();
    rejects_non_utun(socket.into()).unwrap();
}

#[tokio::test]
async fn connected_udp_socket_is_not_utun() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(peer.local_addr().unwrap()).unwrap();
    rejects_non_utun(socket.into()).unwrap();
}

#[tokio::test]
#[ignore = "needs administrator privileges to create a utun interface"]
async fn real_utun_name_survives_adoption_and_split() {
    let created = Tun::create("utun").unwrap();
    let name = created.name().unwrap();
    assert!(name.starts_with("utun"), "{name:?}");
    assert!(name[4..].parse::<u32>().is_ok(), "{name:?}");
    let mtu = created.mtu();
    assert!(mtu > 0);
    let fd = created.as_fd().try_clone_to_owned().unwrap();
    let adopted = Tun::from_fd(fd, mtu).unwrap();
    drop(created);
    assert_eq!(adopted.name().unwrap(), name);
    let (source, sink) = adopted.split().unwrap();
    assert_eq!(source.name().unwrap(), name);
    assert_eq!(sink.name().unwrap(), name);
    assert_eq!(*source.mtu().borrow(), mtu);
}
