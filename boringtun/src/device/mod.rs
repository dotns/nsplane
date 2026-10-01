// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Longest-prefix-match table used for cryptokey routing.
pub mod allowed_ips;
/// Per-peer state of a device.
pub mod peer;
mod peer_table;
mod uapi;

#[cfg(unix)]
/// The cross-platform `wg` configuration protocol (UAPI) over a Unix socket.
pub mod api;
#[cfg(unix)]
mod dev_lock;
#[cfg(unix)]
/// Dropping root privileges after the device is set up.
pub mod drop_privileges;
#[cfg(test)]
#[cfg(unix)]
mod integration_tests;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "kqueue.rs"]
pub mod poll;

#[cfg(target_os = "linux")]
#[path = "epoll.rs"]
pub mod poll;

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
#[path = "tun_darwin.rs"]
pub mod tun;

#[cfg(target_os = "linux")]
#[path = "tun_linux.rs"]
pub mod tun;

#[cfg(windows)]
#[path = "windows/tun.rs"]
pub mod tun;

#[cfg(unix)]
pub use unix::{Device, DeviceHandle};
#[cfg(windows)]
pub use windows::DeviceHandle;

use std::io;
use std::net::SocketAddr;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{DATA_HEADER_SZ, Packet, Tunn, TunnResult};
use crate::x25519;
use peer::Peer;
use peer_table::{PeerTable, SharedPeer};
use tun::TunSocket;

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
/// Room behind a packet for its padding (up to 15 bytes) and the AEAD tag (16 bytes).
const TAIL_ROOM: usize = 15 + 16;

#[derive(Debug, thiserror::Error)]
/// Errors raised by the device layer.
pub enum Error {
    #[error("i/o error: {0}")]
    /// Generic I/O error.
    IoError(#[from] io::Error),
    #[error("{0}")]
    /// Creating or configuring a socket failed.
    Socket(io::Error),
    #[error("{0}")]
    /// Binding a socket failed.
    Bind(String),
    #[error("{0}")]
    /// `fcntl` failed.
    FCntl(io::Error),
    #[error("{0}")]
    /// Creating or updating the event queue failed.
    EventQueue(io::Error),
    #[error("{0}")]
    /// An `ioctl` on the TUN device failed.
    IOCtl(io::Error),
    #[error("{0}")]
    /// Connecting a peer socket failed.
    Connect(String),
    #[error("{0}")]
    /// Setting a socket option failed.
    SetSockOpt(String),
    #[error("Invalid tunnel name")]
    /// The interface name is not valid on this platform.
    InvalidTunnelName,
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    #[error("{0}")]
    /// Reading a socket option failed.
    GetSockOpt(io::Error),
    #[error("{0}")]
    /// Reading a socket address failed.
    GetSockName(String),
    #[cfg(target_os = "linux")]
    #[error("{0}")]
    /// Creating a timer failed.
    Timer(io::Error),
    #[error("iface read: {0}")]
    /// Reading from the TUN interface failed.
    IfaceRead(io::Error),
    #[error("{0}")]
    /// Dropping privileges failed.
    DropPrivileges(String),
    #[error("API socket error: {0}")]
    /// Setting up the UAPI socket failed.
    ApiSocket(io::Error),
    #[cfg(windows)]
    #[error("wintun: {0}")]
    /// Opening the Wintun adapter or session failed.
    Wintun(String),
}

#[derive(Debug, Clone, Copy)]
/// Settings of a device.
pub struct DeviceConfig {
    /// Number of event loop threads.
    pub n_threads: usize,
    /// Use a connected UDP socket per peer once its endpoint is known.
    pub use_connected_socket: bool,
    #[cfg(target_os = "linux")]
    /// Open one TUN queue per event loop thread.
    pub use_multi_queue: bool,
    #[cfg(target_os = "linux")]
    /// Inherited UAPI file descriptor, or `-1` to create the UAPI socket.
    pub uapi_fd: i32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            n_threads: 4,
            use_connected_socket: true,
            #[cfg(target_os = "linux")]
            use_multi_queue: true,
            #[cfg(target_os = "linux")]
            uapi_fd: -1,
        }
    }
}

/// Keys and limits for answering datagrams that arrive on the listen sockets.
struct ListenContext<'a> {
    peers: &'a PeerTable,
    private_key: &'a x25519::StaticSecret,
    public_key: &'a x25519::PublicKey,
    rate_limiter: &'a RateLimiter,
}

/// Handles a datagram from `addr` that arrived on a listen socket and sits in `buf[..len]`.
///
/// Transport data is decrypted in place; handshake messages are answered through `send`, using
/// `scratch` for the reply. Returns the peer whose endpoint moved to `addr`, if any.
fn receive_datagram<'p>(
    ctx: &ListenContext<'p>,
    iface: &TunSocket,
    buf: &mut [u8],
    scratch: &mut [u8],
    len: usize,
    addr: SocketAddr,
    send: &impl Fn(&[u8]),
) -> Option<&'p SharedPeer> {
    let data_index = match Tunn::parse_incoming_packet(buf.get(..len)?) {
        Ok(Packet::PacketData(data)) => Some(data.receiver_idx),
        Ok(_) => None,
        Err(_) => return None,
    };

    if let Some(index) = data_index {
        // Transport data names its session: find the peer and decrypt in place.
        let peer = ctx.peers.by_index(index)?;
        let mut p = peer.lock();
        let result = p.tunnel.decapsulate_in_place(Some(addr), buf, len);
        if deliver(ctx.peers, iface, peer, result, send)? {
            flush_queue(&mut p.tunnel, scratch, send);
        }
        p.set_endpoint(addr);
        return Some(peer);
    }

    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
    let parsed_packet = match ctx
        .rate_limiter
        .verify_packet(Some(addr), &buf[..len], scratch)
    {
        Ok(packet) => packet,
        Err(TunnResult::WriteToNetwork(cookie)) => {
            send(cookie);
            return None;
        }
        Err(_) => return None,
    };

    let peer = match &parsed_packet {
        Packet::HandshakeInit(p) => parse_handshake_anon(ctx.private_key, ctx.public_key, p)
            .ok()
            .and_then(|hh| {
                ctx.peers
                    .get(&x25519::PublicKey::from(hh.peer_static_public))
            }),
        Packet::HandshakeResponse(p) => ctx.peers.by_index(p.receiver_idx),
        Packet::PacketCookieReply(p) => ctx.peers.by_index(p.receiver_idx),
        Packet::PacketData(_) => None,
    }?;
    let roams = roams_endpoint(&parsed_packet);

    let mut p = peer.lock();
    let result = p.tunnel.handle_verified_packet(parsed_packet, scratch);
    // `scratch` holds the reply; queued packets are flushed through the receive buffer.
    if deliver(ctx.peers, iface, peer, result, send)? {
        flush_queue(&mut p.tunnel, buf, send);
    }
    // Cookie replies are not authenticated by the peer's keys and never move the endpoint.
    if !roams {
        return None;
    }
    p.set_endpoint(addr);
    Some(peer)
}

/// Encapsulates the IP packet that was read into `buf[DATA_HEADER_SZ..DATA_HEADER_SZ + len]`
/// for the peer it is routed to, and hands the datagram to `send`.
fn send_from_tun(peers: &PeerTable, buf: &mut [u8], len: usize, send: impl FnOnce(&Peer, &[u8])) {
    let Some(dst_addr) = buf
        .get(DATA_HEADER_SZ..DATA_HEADER_SZ + len)
        .and_then(Tunn::dst_address)
    else {
        return;
    };
    let Some(peer) = peers.by_destination(dst_addr) else {
        return;
    };
    let mut peer = peer.lock();

    match peer.tunnel.encapsulate_in_place(buf, len) {
        TunnResult::Done => {}
        TunnResult::Err(e) => {
            tracing::error!(message = "Encapsulate error", error = ?e);
        }
        TunnResult::WriteToNetwork(packet) => send(&peer, packet),
        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
            tracing::error!("Unexpected result from encapsulate");
        }
    }
}

/// Runs the timers of every peer; handshakes and keepalives that are due go to `send`
/// together with the peer's endpoint.
fn update_timers(peers: &PeerTable, scratch: &mut [u8], send: impl Fn(SocketAddr, &[u8])) {
    for peer in peers.peers() {
        let mut p = peer.lock();
        let endpoint = p.endpoint().addr;
        let Some(endpoint_addr) = endpoint else {
            continue;
        };

        match p.update_timers(scratch) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                p.shutdown_endpoint(); // close open udp socket
            }
            TunnResult::Err(e) => tracing::error!(message = "Timer error", error = ?e),
            TunnResult::WriteToNetwork(packet) => send(endpoint_addr, packet),
            TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => {
                tracing::error!("Unexpected result from update_timers");
            }
        }
    }
}

/// Acts on what a tunnel returned for a datagram from `peer`: replies go out through `send`,
/// decrypted packets go to the TUN interface if their source is routed to `peer`.
///
/// Returns `None` if the datagram was rejected, otherwise whether the tunnel's queued packets
/// must be flushed.
fn deliver(
    peers: &PeerTable,
    iface: &TunSocket,
    peer: &SharedPeer,
    result: TunnResult<'_>,
    send: &impl Fn(&[u8]),
) -> Option<bool> {
    match result {
        TunnResult::Done => Some(false),
        TunnResult::Err(e) => {
            tracing::debug!(message = "Decapsulate error", error = ?e);
            None
        }
        TunnResult::WriteToNetwork(packet) => {
            send(packet);
            Some(true)
        }
        TunnResult::WriteToTunnelV4(packet, src) => {
            if peers.routes_to(src.into(), peer) {
                iface.write4(packet);
            }
            Some(false)
        }
        TunnResult::WriteToTunnelV6(packet, src) => {
            if peers.routes_to(src.into(), peer) {
                iface.write6(packet);
            }
            Some(false)
        }
    }
}

/// Sends the packets a tunnel queued while it had no session.
fn flush_queue(tunnel: &mut Tunn, buf: &mut [u8], send: &impl Fn(&[u8])) {
    while let TunnResult::WriteToNetwork(packet) = tunnel.decapsulate(None, &[], buf) {
        send(packet);
    }
}

/// Whether an authenticated packet moves the peer's endpoint to its source address.
///
/// Cookie replies are encrypted with a key derived from the peer's public key only, so they do
/// not prove that the sender holds the peer's private key; they never cause roaming.
const fn roams_endpoint(packet: &Packet<'_>) -> bool {
    !matches!(packet, Packet::PacketCookieReply(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::Tunn;

    #[test]
    fn cookie_replies_do_not_roam() {
        let mut reply = [0u8; 64];
        reply[0] = 3;
        let packet = Tunn::parse_incoming_packet(&reply).unwrap();
        assert!(!roams_endpoint(&packet));

        let mut data = [0u8; 32];
        data[0] = 4;
        let packet = Tunn::parse_incoming_packet(&data).unwrap();
        assert!(roams_endpoint(&packet));
    }
}
