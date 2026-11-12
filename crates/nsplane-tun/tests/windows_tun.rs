//! A real Wintun adapter. Needs administrator privileges and `wintun.dll` beside the test
//! executable or in the system directory: run the test executable with
//! `--ignored --test-threads 1`.

#![cfg(windows)]

use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{IpPacket, protocol};
use nsplane_tun::{MTU_POLL_INTERVAL, Tun};

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(10);

fn netsh(args: &[&str]) -> TestResult {
    let output = Command::new("netsh").args(args).output()?;
    assert!(output.status.success(), "netsh {args:?}: {output:?}");
    Ok(())
}

/// An IPv4 UDP datagram from `src` port 4000 to `dst` port 4001.
fn datagram(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let udp_len = u16::try_from(8 + payload.len())?;
    let mut udp = [
        4000u16.to_be_bytes(),
        4001u16.to_be_bytes(),
        udp_len.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let checksum = transport_checksum_v4(src, dst, protocol::UDP, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let total = (20 + udp_len).to_be_bytes();
    let mut packet = vec![
        0x45,
        0,
        total[0],
        total[1],
        0,
        1,
        0x40,
        0,
        64,
        protocol::UDP,
        0,
        0,
    ];
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    Ok(packet)
}

/// Binds once Windows has finished configuring the address.
fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    let deadline = Instant::now() + WAIT;
    loop {
        match UdpSocket::bind(addr) {
            Ok(socket) => return Ok(socket),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// A datagram from a socket is read from the adapter, and a crafted datagram written to the
/// adapter reaches a bound socket. `Tun::create` loads the unpinned `wintun.dll`.
#[tokio::test]
#[ignore = "needs administrator privileges and wintun.dll"]
async fn wintun_adapter_round_trip() -> TestResult {
    let local = Ipv4Addr::new(10, 77, 9, 1);
    let remote = Ipv4Addr::new(10, 77, 9, 2);
    let tun = Tun::create("nsplanetest")?;
    let name = tun.name()?;
    assert_eq!(name, "nsplanetest");
    assert!(tun.mtu() > 0);
    netsh(&[
        "interface",
        "ipv4",
        "set",
        "address",
        &name,
        "static",
        &local.to_string(),
        "255.255.255.0",
    ])?;
    let (mut source, sink) = tun.split()?;
    assert_eq!(source.name()?, name);
    assert_eq!(sink.name()?, name);

    // OS -> adapter: a datagram to an address routed into the adapter.
    let socket = bind(SocketAddr::from((local, 0)))?;
    socket.send_to(b"to the tun", SocketAddr::from((remote, 4000)))?;
    // Skip unrelated traffic such as name resolution and router solicitations.
    loop {
        let packet = tokio::time::timeout(WAIT, source.recv()).await??;
        let parsed = IpPacket::parse(packet.as_packet())?;
        let Some(flow) = parsed.five_tuple() else {
            continue;
        };
        if matches!(parsed, IpPacket::V4 { .. })
            && flow.protocol == protocol::UDP
            && flow.dst == remote
            && flow.dst_port == 4000
        {
            assert_eq!(&parsed.payload()[8..], b"to the tun");
            break;
        }
    }

    // Adapter -> OS: a crafted datagram reaches a bound socket.
    let receiver = bind(SocketAddr::from((local, 4001)))?;
    receiver.set_read_timeout(Some(WAIT))?;
    let packet = datagram(remote, local, b"from the tun")?;
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
        .await?;
    let mut buf = [0u8; 64];
    let (len, from) = receiver.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"from the tun");
    assert_eq!(from, SocketAddr::from((remote, 4000)));
    assert_eq!(sink.ring_full_drops(), 0);
    Ok(())
}

/// A change of the interface MTU reaches the source's watch within a few poll intervals.
#[tokio::test]
#[ignore = "needs administrator privileges and wintun.dll"]
async fn interface_mtu_change_reaches_the_watch() -> TestResult {
    let tun = Tun::create("nsplanemtu")?;
    let name = tun.name()?;
    let (source, _sink) = tun.split()?;
    let mut mtu = source.mtu();
    assert_ne!(*mtu.borrow(), 1300);
    netsh(&[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &name,
        "mtu=1300",
        "store=active",
    ])?;
    tokio::time::timeout(MTU_POLL_INTERVAL * 5, mtu.wait_for(|mtu| *mtu == 1300)).await??;
    Ok(())
}

/// Packets written faster than the OS drains the send ring are dropped and counted, and
/// every send succeeds.
#[tokio::test]
#[ignore = "needs administrator privileges and wintun.dll"]
async fn full_send_ring_drops_and_counts() -> TestResult {
    let tun = Tun::create("nsplanering")?;
    let (_source, sink) = tun.split()?;
    let packet = datagram(
        Ipv4Addr::new(10, 77, 10, 2),
        Ipv4Addr::new(10, 77, 10, 1),
        &[0x5a; 1372],
    )?;
    let mut sent = 0u32;
    while sink.ring_full_drops() == 0 && sent < 4_000_000 {
        sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
            .await?;
        sent += 1;
    }
    println!("sent {sent}, dropped {}", sink.ring_full_drops());
    assert!(sink.ring_full_drops() > 0);
    // The sink still works after the ring was full.
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
        .await?;
    Ok(())
}

/// Without a pin, a `wintun.dll` that only the DLL search order would find (the current
/// directory, `PATH`) is not loaded. Run from a directory that holds `wintun.dll`, with no
/// copy beside the test executable or in the system directory.
#[test]
#[ignore = "needs wintun.dll in the current directory only"]
fn unpinned_dll_outside_the_trusted_directories_is_not_found() {
    let cwd = std::env::current_dir().unwrap();
    assert!(cwd.join("wintun.dll").is_file(), "{}", cwd.display());
    let exe = std::env::current_exe().unwrap();
    assert!(!exe.with_file_name("wintun.dll").exists());
    let system = std::env::var_os("SystemRoot").unwrap();
    assert!(!Path::new(&system).join("System32/wintun.dll").exists());
    let path = std::env::var_os("PATH").unwrap();
    assert!(
        std::env::split_paths(&path).any(|dir| dir == cwd),
        "the current directory is not on PATH"
    );

    let e = Tun::create("nsplanenodll").unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
}
