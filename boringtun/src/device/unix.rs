// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The event-loop device for Linux and macOS: epoll/kqueue, TUN, UDP sockets.

use std::io::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::thread::JoinHandle;

use socket2::{Domain, Protocol, Type};

use super::dev_lock::{Lock, LockReadGuard};
use super::peer_table::{PeerTable, PeerTableError, PeerUpdate, SharedPeer};
use super::poll::{EventPoll, EventRef, WaitResult};
use super::tun::TunSocket;
use super::{
    DATA_HEADER_SZ, DeviceConfig, Error, HANDSHAKE_RATE_LIMIT, ListenContext, MAX_UDP_SIZE,
    TAIL_ROOM, deliver, flush_queue, receive_datagram, send_from_tun, update_timers,
};
use crate::noise::rate_limiter::RateLimiter;
use crate::x25519;

const MAX_ITR: usize = 100; // Number of packets to handle per handler call

// What the event loop should do after a handler returns
pub(super) enum Action {
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

/// A WireGuard interface: TUN device, UDP sockets and peers.
pub struct Device {
    pub(super) key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    pub(super) queue: Arc<EventPoll<Handler>>,

    pub(super) listen_port: u16,
    pub(super) fwmark: Option<u32>,

    pub(super) iface: Arc<TunSocket>,
    pub(super) udp4: Option<Arc<UdpSocket>>,
    pub(super) udp6: Option<Arc<UdpSocket>>,

    pub(super) yield_notice: Option<EventRef>,
    pub(super) exit_notice: Option<EventRef>,

    pub(super) peers: PeerTable,

    pub(super) config: DeviceConfig,

    pub(super) cleanup_paths: Vec<String>,

    pub(super) mtu: AtomicUsize,

    pub(super) rate_limiter: Option<Arc<RateLimiter>>,

    #[cfg(target_os = "linux")]
    pub(super) uapi_fd: i32,
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

pub(super) struct ThreadData {
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
    pub(super) fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError> {
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

    pub(super) fn open_listen_socket(&mut self, mut port: u16) -> Result<(), Error> {
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

    pub(super) fn set_key(&mut self, private_key: &x25519::StaticSecret) {
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
    pub(super) fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
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

    pub(super) fn clear_peers(&mut self) {
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

    pub(super) fn trigger_yield(&self) {
        if let Some(notice) = self.yield_notice.as_ref() {
            self.queue.trigger_notification(notice);
        }
    }

    pub(super) fn trigger_exit(&self) {
        if let Some(notice) = self.exit_notice.as_ref() {
            self.queue.trigger_notification(notice);
        }
    }

    pub(super) fn cancel_yield(&self) {
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
