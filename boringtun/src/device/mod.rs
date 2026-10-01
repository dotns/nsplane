// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

/// Longest-prefix-match table used for cryptokey routing.
pub mod allowed_ips;
/// The cross-platform `wg` configuration protocol (UAPI).
pub mod api;
mod dev_lock;
/// Dropping root privileges after the device is set up.
pub mod drop_privileges;
#[cfg(test)]
mod integration_tests;
/// Per-peer state of a device.
pub mod peer;
mod peer_table;
mod uapi;

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

use std::io::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::thread::JoinHandle;

use crate::noise::errors::WireGuardError;
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{DATA_HEADER_SZ, Packet, Tunn, TunnResult};
use crate::x25519;
use peer::Peer;
use peer_table::{PeerTable, PeerTableError, PeerUpdate, SharedPeer};
use poll::{EventPoll, EventRef, WaitResult};
use socket2::{Domain, Protocol, Type};
use tun::TunSocket;

use dev_lock::{Lock, LockReadGuard};

const HANDSHAKE_RATE_LIMIT: u64 = 100; // The number of handshakes per second we can tolerate before using cookies

const MAX_UDP_SIZE: usize = (1 << 16) - 1;
const MAX_ITR: usize = 100; // Number of packets to handle per handler call
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
}

// What the event loop should do after a handler returns
enum Action {
    Continue, // Continue the loop
    Yield,    // Yield the read lock and acquire it again
    Exit,     // Stop the loop
}

// Event handler function
type Handler =
    Box<dyn for<'a> Fn(&mut LockReadGuard<'a, Device>, &mut ThreadData) -> Action + Send + Sync>;

#[derive(Debug)]
/// A running device and the threads of its event loop.
pub struct DeviceHandle {
    device: Arc<Lock<Device>>, // The interface this handle owns
    threads: Vec<JoinHandle<()>>,
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

/// A WireGuard interface: TUN device, UDP sockets and peers.
pub struct Device {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    queue: Arc<EventPoll<Handler>>,

    listen_port: u16,
    fwmark: Option<u32>,

    iface: Arc<TunSocket>,
    udp4: Option<Arc<UdpSocket>>,
    udp6: Option<Arc<UdpSocket>>,

    yield_notice: Option<EventRef>,
    exit_notice: Option<EventRef>,

    peers: PeerTable,

    config: DeviceConfig,

    cleanup_paths: Vec<String>,

    mtu: AtomicUsize,

    rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    uapi_fd: i32,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("iface", &self.iface)
            .field("peers", &self.peers)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

struct ThreadData {
    iface: Arc<TunSocket>,
    src_buf: Box<[u8]>,
    dst_buf: Box<[u8]>,
}

impl ThreadData {
    fn new(iface: Arc<TunSocket>) -> Self {
        Self {
            iface,
            src_buf: vec![0u8; MAX_UDP_SIZE].into_boxed_slice(),
            dst_buf: vec![0u8; MAX_UDP_SIZE].into_boxed_slice(),
        }
    }
}

impl DeviceHandle {
    /// Creates the device and starts `config.n_threads` event loop threads.
    pub fn new(name: &str, config: DeviceConfig) -> Result<Self, Error> {
        let n_threads = config.n_threads;
        let mut wg_interface = Device::new(name, config)?;
        wg_interface.open_listen_socket(0)?; // Start listening on a random port

        let interface_lock = Arc::new(Lock::new(wg_interface));

        let mut threads = vec![];

        for i in 0..n_threads {
            threads.push({
                let dev = Arc::clone(&interface_lock);
                thread::spawn(move || Self::event_loop(i, &dev))
            });
        }

        Ok(Self {
            device: interface_lock,
            threads,
        })
    }

    /// Blocks until all event loop threads exit.
    pub fn wait(&mut self) {
        while let Some(thread) = self.threads.pop() {
            if thread.join().is_err() {
                tracing::error!("Event loop thread panicked");
            }
        }
    }

    /// Removes files created by the device, such as the UAPI socket.
    pub fn clean(&mut self) {
        for path in &self.device.read().cleanup_paths {
            // attempt to remove any file we created in the work dir
            let _ = std::fs::remove_file(path);
        }
    }

    /// Opens an extra queue of the TUN interface for event loop thread `i`.
    #[cfg(target_os = "linux")]
    fn thread_iface(i: usize, device: &Lock<Device>) -> Arc<TunSocket> {
        let shared = Arc::clone(&device.read().iface);
        if i == 0 || !device.read().config.use_multi_queue {
            // For the first thread use the original iface
            return shared;
        }
        // For the rest create a new iface queue
        let queue = shared
            .name()
            .and_then(|name| TunSocket::new(&name))
            .and_then(TunSocket::set_non_blocking);
        match queue {
            Ok(iface) => {
                let iface = Arc::new(iface);
                let registered = device.read().register_iface_handler(Arc::clone(&iface));
                if let Err(e) = registered {
                    tracing::error!(message = "Failed to register TUN queue", error = ?e);
                }
                iface
            }
            Err(e) => {
                tracing::warn!(message = "Failed to open TUN queue, sharing queue 0", error = ?e);
                shared
            }
        }
    }

    fn event_loop(i: usize, device: &Lock<Device>) {
        #[cfg(target_os = "linux")]
        let mut thread_local = ThreadData::new(Self::thread_iface(i, device));

        #[cfg(not(target_os = "linux"))]
        let mut thread_local = {
            let _ = i;
            ThreadData::new(Arc::clone(&device.read().iface))
        };

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = device.read().uapi_fd;

        loop {
            // The event loop keeps a read lock on the device, because we assume write access is rarely needed
            let mut device_lock = device.read();
            let queue = Arc::clone(&device_lock.queue);

            loop {
                match queue.wait() {
                    WaitResult::Ok(handler) => {
                        let action = (*handler)(&mut device_lock, &mut thread_local);
                        match action {
                            Action::Continue => {}
                            Action::Yield => break,
                            Action::Exit => {
                                device_lock.trigger_exit();
                                return;
                            }
                        }
                    }
                    WaitResult::EoF(handler) => {
                        if uapi_fd >= 0 && uapi_fd == handler.fd() {
                            device_lock.trigger_exit();
                            return;
                        }
                        handler.cancel();
                    }
                    WaitResult::Error(e) => tracing::error!(message = "Poll error", error = ?e),
                }
            }
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.device.read().trigger_exit();
        self.clean();
    }
}

impl Device {
    /// Applies one UAPI peer section.
    fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError> {
        let Some((private_key, _)) = self.key_pair.as_ref() else {
            if update.remove {
                self.peers.remove(&update.public_key);
                return Ok(());
            }
            tracing::error!("Private key must be set before adding peers");
            return Ok(());
        };
        self.peers
            .apply(update, private_key, self.rate_limiter.as_ref())
    }

    /// Creates the TUN interface `name` and registers the event handlers.
    pub fn new(name: &str, config: DeviceConfig) -> Result<Self, Error> {
        let poll = EventPoll::<Handler>::new()?;

        // Create a tunnel device
        let iface = Arc::new(TunSocket::new(name)?.set_non_blocking()?);
        let mtu = iface.mtu()?;

        #[cfg(not(target_os = "linux"))]
        let uapi_fd = -1;
        #[cfg(target_os = "linux")]
        let uapi_fd = config.uapi_fd;

        let mut device = Self {
            queue: Arc::new(poll),
            iface,
            config,
            exit_notice: None,
            yield_notice: None,
            fwmark: None,
            key_pair: None,
            listen_port: 0,
            peers: PeerTable::default(),
            udp4: None,
            udp6: None,
            cleanup_paths: Vec::new(),
            mtu: AtomicUsize::new(mtu),
            rate_limiter: None,
            #[cfg(target_os = "linux")]
            uapi_fd,
        };

        if uapi_fd >= 0 {
            device.register_api_fd(uapi_fd)?;
        } else {
            device.register_api_handler()?;
        }
        device.register_iface_handler(Arc::clone(&device.iface))?;
        device.register_notifiers()?;
        device.register_timers()?;

        #[cfg(target_os = "macos")]
        {
            // Only for macOS write the actual socket name into WG_TUN_NAME_FILE
            if let Ok(name_file) = std::env::var("WG_TUN_NAME_FILE")
                && name == "utun"
            {
                std::fs::write(&name_file, device.iface.name()?.as_bytes())?;
                device.cleanup_paths.push(name_file);
            }
        }

        Ok(device)
    }

    fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
        // Binds the network facing interfaces
        // First close any existing open socket, and remove them from the event loop
        for s in [self.udp4.take(), self.udp6.take()].into_iter().flatten() {
            #[allow(unsafe_code, reason = "event removal while handlers are quiescent")]
            // SAFETY: this runs either before the event loop starts or under the device write
            // lock, which every event loop thread yields before it is granted, so no handler for
            // this fd is running.
            unsafe {
                self.queue.clear_event_by_fd(s.as_raw_fd());
            }
        }

        for peer in self.peers.peers() {
            peer.lock().shutdown_endpoint();
        }

        // Then open new sockets and bind to the port
        let udp_sock4 = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock4.set_reuse_address(true)?;
        udp_sock4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
        udp_sock4.set_nonblocking(true)?;

        if port == 0 {
            // Random port was assigned
            port = udp_sock4
                .local_addr()?
                .as_socket()
                .map(|a| a.port())
                .ok_or_else(|| Error::GetSockName("not an inet socket".to_owned()))?;
        }

        let udp_sock6 = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        udp_sock6.set_reuse_address(true)?;
        udp_sock6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into())?;
        udp_sock6.set_nonblocking(true)?;

        // The handler and the device share the socket, so the event registered for its fd can
        // be cleared again when the port changes.
        let udp_sock4 = Arc::new(UdpSocket::from(udp_sock4));
        let udp_sock6 = Arc::new(UdpSocket::from(udp_sock6));
        self.register_udp_handler(Arc::clone(&udp_sock4))?;
        self.register_udp_handler(Arc::clone(&udp_sock6))?;
        self.udp4 = Some(udp_sock4);
        self.udp6 = Some(udp_sock6);

        self.listen_port = port;

        Ok(())
    }

    fn set_key(&mut self, private_key: &x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(private_key);
        let key_pair = Some((private_key.clone(), public_key));

        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.key_pair.as_ref().map(|p| &p.1) {
            return;
        }

        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        for peer in self.peers.peers() {
            peer.lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            );
        }

        self.key_pair = key_pair;
        self.rate_limiter = Some(rate_limiter);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        self.fwmark = Some(mark);

        // First set fwmark on listeners
        for sock in [&self.udp4, &self.udp6].into_iter().flatten() {
            socket2::SockRef::from(sock.as_ref()).set_mark(mark)?;
        }

        // Then on all currently connected sockets
        for peer in self.peers.peers() {
            if let Some(ref sock) = peer.lock().endpoint().conn {
                sock.set_mark(mark)?;
            }
        }

        Ok(())
    }

    fn clear_peers(&mut self) {
        self.peers.clear();
    }

    fn register_notifiers(&mut self) -> Result<(), Error> {
        let yield_ev = self
            .queue
            // The notification event handler simply returns Action::Yield
            .new_notifier(Box::new(|_, _| Action::Yield))?;
        self.yield_notice = Some(yield_ev);

        let exit_ev = self
            .queue
            // The exit event handler simply returns Action::Exit
            .new_notifier(Box::new(|_, _| Action::Exit))?;
        self.exit_notice = Some(exit_ev);
        Ok(())
    }

    fn register_timers(&self) -> Result<(), Error> {
        self.queue.new_periodic_event(
            // Reset the rate limiter every second give or take
            Box::new(|d, _| {
                if let Some(r) = d.rate_limiter.as_ref() {
                    r.reset_count();
                }
                Action::Continue
            }),
            std::time::Duration::from_secs(1),
        )?;

        self.queue.new_periodic_event(
            // Execute the timed function of every peer in the list
            Box::new(|d, t| {
                let (Some(udp4), Some(udp6)) = (d.udp4.as_ref(), d.udp6.as_ref()) else {
                    return Action::Continue;
                };
                update_timers(&d.peers, &mut t.dst_buf, |addr, packet| {
                    let udp = if addr.is_ipv4() { udp4 } else { udp6 };
                    let _ = udp.send_to(packet, addr);
                });
                Action::Continue
            }),
            std::time::Duration::from_millis(250),
        )?;
        Ok(())
    }

    pub(crate) fn trigger_yield(&self) {
        if let Some(notice) = self.yield_notice.as_ref() {
            self.queue.trigger_notification(notice);
        }
    }

    pub(crate) fn trigger_exit(&self) {
        if let Some(notice) = self.exit_notice.as_ref() {
            self.queue.trigger_notification(notice);
        }
    }

    pub(crate) fn cancel_yield(&self) {
        if let Some(notice) = self.yield_notice.as_ref() {
            self.queue.stop_notification(notice);
        }
    }

    /// Connects a socket to `peer`'s new endpoint `addr`, if enabled.
    fn connect_peer(&self, peer: &SharedPeer, addr: SocketAddr) {
        if !self.config.use_connected_socket {
            return;
        }
        let sock = peer.lock().connect_endpoint(self.listen_port, self.fwmark);
        if let Ok(sock) = sock
            && let Err(e) = self.register_conn_handler(Arc::clone(peer), sock, addr)
        {
            tracing::error!(message = "Failed to register connected socket", error = ?e);
        }
    }

    fn register_udp_handler(&self, udp: Arc<UdpSocket>) -> Result<(), Error> {
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // Handler that handles anonymous packets over UDP
                let mut iter = MAX_ITR;
                let (Some((private_key, public_key)), Some(rate_limiter)) =
                    (d.key_pair.as_ref(), d.rate_limiter.as_ref())
                else {
                    // No key yet: drain and drop the datagrams.
                    while udp.recv_from(&mut t.src_buf).is_ok() {}
                    return Action::Continue;
                };

                let ctx = ListenContext {
                    peers: &d.peers,
                    private_key,
                    public_key,
                    rate_limiter,
                };

                // Loop while we have packets on the anonymous connection
                while let Ok((len, addr)) = udp.recv_from(&mut t.src_buf) {
                    let send = |packet: &[u8]| {
                        let _ = udp.send_to(packet, addr);
                    };
                    let roamed = receive_datagram(
                        &ctx,
                        &t.iface,
                        &mut t.src_buf,
                        &mut t.dst_buf,
                        len,
                        addr,
                        &send,
                    );
                    if let Some(peer) = roamed {
                        d.connect_peer(peer, addr);
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_conn_handler(
        &self,
        peer: SharedPeer,
        udp: socket2::Socket,
        peer_addr: SocketAddr,
    ) -> Result<(), Error> {
        let udp = UdpSocket::from(udp);
        self.queue.new_event(
            udp.as_raw_fd(),
            Box::new(move |d, t| {
                // The conn_handler handles packet received from a connected UDP socket, associated
                // with a known peer, this saves us the hustle of finding the right peer. If another
                // peer gets the same ip, it will be ignored until the socket does not expire.
                let send = |packet: &[u8]| {
                    let _ = udp.send(packet);
                };
                let mut iter = MAX_ITR;

                while let Ok(len) = udp.recv(&mut t.src_buf) {
                    let mut p = peer.lock();
                    let result =
                        p.tunnel
                            .decapsulate_in_place(Some(peer_addr), &mut t.src_buf, len);
                    if deliver(&d.peers, &t.iface, &peer, result, &send) == Some(true) {
                        flush_queue(&mut p.tunnel, &mut t.dst_buf, &send);
                    }

                    iter -= 1;
                    if iter == 0 {
                        break;
                    }
                }
                Action::Continue
            }),
        )?;
        Ok(())
    }

    fn register_iface_handler(&self, iface: Arc<TunSocket>) -> Result<(), Error> {
        self.queue.new_event(
            iface.as_raw_fd(),
            Box::new(move |d, t| {
                // The iface_handler handles packets received from the WireGuard virtual network
                // interface. The flow is as follows:
                // * Read a packet
                // * Determine peer based on packet destination ip
                // * Encapsulate the packet for the given peer
                // * Send encapsulated packet to the peer's endpoint
                // Packets are read straight into the encapsulation buffer, behind the room for
                // the data header, and sealed in place.
                let max_len = t.dst_buf.len() - DATA_HEADER_SZ - TAIL_ROOM;
                let mtu = d.mtu.load(Ordering::Relaxed).min(max_len);

                let (Some(udp4), Some(udp6)) = (d.udp4.as_ref(), d.udp6.as_ref()) else {
                    return Action::Continue;
                };

                for _ in 0..MAX_ITR {
                    let len = match iface.read(&mut t.dst_buf[DATA_HEADER_SZ..DATA_HEADER_SZ + mtu])
                    {
                        Ok(src) => src.len(),
                        Err(Error::IfaceRead(e)) => {
                            let ek = e.kind();
                            if ek == io::ErrorKind::Interrupted || ek == io::ErrorKind::WouldBlock {
                                break;
                            }
                            tracing::error!(message = "Fatal read error on tun interface", error = ?e);
                            return Action::Exit;
                        }
                        Err(e) => {
                            tracing::error!(message = "Unexpected error on tun interface", error = ?e);
                            return Action::Exit;
                        }
                    };

                    send_from_tun(&d.peers, &mut t.dst_buf, len, |peer, packet| {
                        let endpoint = peer.endpoint();
                        if let Some(conn) = endpoint.conn.as_ref() {
                            // Prefer to send using the connected socket
                            let _ = (&*conn).write(packet);
                        } else if let Some(addr) = endpoint.addr {
                            let udp = if addr.is_ipv4() { udp4 } else { udp6 };
                            let _ = udp.send_to(packet, addr);
                        } else {
                            tracing::error!("No endpoint");
                        }
                    });
                }
                Action::Continue
            }),
        )?;
        Ok(())
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
