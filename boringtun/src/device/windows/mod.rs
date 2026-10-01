// SPDX-License-Identifier: BSD-3-Clause

//! The Windows device: Wintun, UDP sockets and the UAPI named pipe, each served by blocking
//! threads that share the device state behind a read-write lock.
//!
//! - one thread reads packets from Wintun and sends them to peers,
//! - one thread per listen socket receives datagrams,
//! - one thread runs the peer timers every 250 ms,
//! - one thread serves the UAPI named pipe.
//!
//! The data path takes the read lock; UAPI requests take the write lock.

mod pipe;

use std::io::{BufReader, BufWriter, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use super::peer_table::{PeerTable, PeerTableError, PeerUpdate};
use super::tun::TunSocket;
use super::uapi::{self, UapiDevice};
use super::{
    DATA_HEADER_SZ, DeviceConfig, Error, HANDSHAKE_RATE_LIMIT, ListenContext, MAX_UDP_SIZE,
    TAIL_ROOM, receive_datagram, send_from_tun, update_timers,
};
use crate::noise::rate_limiter::RateLimiter;
use crate::x25519;

/// How often blocked socket reads wake up to notice shutdowns and port changes.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The state that the UAPI changes and the data path reads.
#[derive(Default)]
struct State {
    key_pair: Option<(x25519::StaticSecret, x25519::PublicKey)>,
    listen_port: u16,
    udp4: Option<Arc<UdpSocket>>,
    udp6: Option<Arc<UdpSocket>>,
    peers: PeerTable,
    rate_limiter: Option<Arc<RateLimiter>>,
}

impl State {
    /// The listen socket to use for `addr`.
    fn socket_for(&self, addr: SocketAddr) -> Option<&UdpSocket> {
        if addr.is_ipv4() {
            self.udp4.as_deref()
        } else {
            self.udp6.as_deref()
        }
    }
}

struct Shared {
    name: String,
    iface: TunSocket,
    state: RwLock<State>,
    exit: AtomicBool,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("name", &self.name)
            .field("exit", &self.exit)
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn exiting(&self) -> bool {
        self.exit.load(Ordering::Relaxed)
    }

    fn spawn(self: &Arc<Self>, name: &str, f: impl FnOnce(Arc<Self>) + Send + 'static) {
        let shared = Arc::clone(self);
        match thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || f(shared))
        {
            Ok(handle) => self.threads.lock().push(handle),
            Err(e) => {
                tracing::error!(message = "Failed to spawn thread", thread = name, error = ?e);
            }
        }
    }

    /// Stops every thread: Wintun reads fail, the pipe server is woken by a dummy client, and
    /// socket readers notice within `POLL_INTERVAL`.
    fn trigger_exit(&self) {
        if self.exit.swap(true, Ordering::Relaxed) {
            return;
        }
        self.iface.shutdown();
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe::path(&self.name));
    }
}

/// The device as seen by a UAPI request, under the write lock.
struct Configurator<'a> {
    shared: &'a Arc<Shared>,
    state: &'a mut State,
}

impl UapiDevice for Configurator<'_> {
    fn public_key(&self) -> Option<&x25519::PublicKey> {
        self.state.key_pair.as_ref().map(|(_, public)| public)
    }

    fn listen_port(&self) -> u16 {
        self.state.listen_port
    }

    fn fwmark(&self) -> Option<u32> {
        None
    }

    fn peers(&self) -> &PeerTable {
        &self.state.peers
    }

    fn set_key(&mut self, private_key: &x25519::StaticSecret) {
        let public_key = x25519::PublicKey::from(private_key);
        // x25519 (rightly) doesn't let us expose secret keys for comparison.
        // If the public keys are the same, then the private keys are the same.
        if Some(&public_key) == self.state.key_pair.as_ref().map(|p| &p.1) {
            return;
        }
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));
        for peer in self.state.peers.peers() {
            peer.lock().tunnel.set_static_private(
                private_key.clone(),
                public_key,
                Some(Arc::clone(&rate_limiter)),
            );
        }
        self.state.key_pair = Some((private_key.clone(), public_key));
        self.state.rate_limiter = Some(rate_limiter);
    }

    fn open_listen_socket(&mut self, port: u16) -> Result<(), Error> {
        let udp4 = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
        let port = udp4.local_addr()?.port();
        let udp6 = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0))?;
        let (udp4, udp6) = (Arc::new(udp4), Arc::new(udp6));
        for udp in [&udp4, &udp6] {
            udp.set_read_timeout(Some(POLL_INTERVAL))?;
            let udp = Arc::clone(udp);
            self.shared
                .spawn("nstun-udp", move |shared| udp_reader(&shared, &udp));
        }
        // The readers of the old sockets notice the change and exit.
        self.state.udp4 = Some(udp4);
        self.state.udp6 = Some(udp6);
        self.state.listen_port = port;
        Ok(())
    }

    fn set_fwmark(&mut self, _mark: u32) -> Result<(), Error> {
        Err(Error::SetSockOpt(
            "fwmark is not supported on Windows".to_owned(),
        ))
    }

    fn clear_peers(&mut self) {
        self.state.peers.clear();
    }

    fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError> {
        let Some((private_key, _)) = self.state.key_pair.as_ref() else {
            if update.remove {
                self.state.peers.remove(&update.public_key);
            } else {
                tracing::error!("Private key must be set before adding peers");
            }
            return Ok(());
        };
        self.state
            .peers
            .apply(update, private_key, self.state.rate_limiter.as_ref())
    }
}

/// A running device and its threads.
#[derive(Debug)]
pub struct DeviceHandle {
    shared: Arc<Shared>,
}

impl DeviceHandle {
    /// Creates the Wintun interface `name` and starts the device threads.
    ///
    /// `config.n_threads` and `config.use_connected_socket` do not apply on Windows.
    pub fn new(name: &str, config: DeviceConfig) -> Result<Self, Error> {
        let _ = config;
        let shared = Arc::new(Shared {
            name: name.to_owned(),
            iface: TunSocket::new(name)?,
            state: RwLock::new(State::default()),
            exit: AtomicBool::new(false),
            threads: Mutex::new(Vec::new()),
        });
        let pipe = pipe::PipeServer::new(&pipe::path(name)).map_err(Error::ApiSocket)?;

        {
            let mut state = shared.state.write();
            Configurator {
                shared: &shared,
                state: &mut state,
            }
            .open_listen_socket(0)?; // Start listening on a random port
        }
        shared.spawn("nstun-tun", |shared| tun_reader(&shared));
        shared.spawn("nstun-timers", |shared| timers(&shared));
        shared.spawn("nstun-uapi", move |shared| uapi_server(&shared, &pipe));
        exit_on_ctrl_c(&shared);

        Ok(Self { shared })
    }

    /// Blocks until all device threads exit.
    pub fn wait(&mut self) {
        loop {
            let next = self.shared.threads.lock().pop();
            let Some(thread) = next else {
                break;
            };
            if thread.join().is_err() {
                tracing::error!("Device thread panicked");
            }
        }
    }

    /// Nothing to clean up on Windows: the named pipe disappears with the process.
    pub const fn clean(&mut self) {}
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.shared.trigger_exit();
    }
}

/// Reads packets from Wintun, encapsulates them, and sends them to the peers.
fn tun_reader(shared: &Shared) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let max_len = buf.len() - DATA_HEADER_SZ - TAIL_ROOM;
    while !shared.exiting() {
        let len = match shared
            .iface
            .read(&mut buf[DATA_HEADER_SZ..DATA_HEADER_SZ + max_len])
        {
            Ok(packet) => packet.len(),
            Err(e) => {
                if !shared.exiting() {
                    tracing::error!(message = "Fatal read error on tun interface", error = ?e);
                    shared.trigger_exit();
                }
                return;
            }
        };
        let state = shared.state.read();
        send_from_tun(&state.peers, &mut buf, len, |peer, packet| {
            let Some(addr) = peer.endpoint().addr else {
                tracing::error!("No endpoint");
                return;
            };
            if let Some(udp) = state.socket_for(addr) {
                let _ = udp.send_to(packet, addr);
            }
        });
    }
}

/// Receives datagrams on one listen socket until the device exits or the socket is replaced.
fn udp_reader(shared: &Shared, udp: &Arc<UdpSocket>) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let mut scratch = vec![0u8; MAX_UDP_SIZE];
    while !shared.exiting() {
        let received = udp.recv_from(&mut buf);
        let state = shared.state.read();
        let current = [&state.udp4, &state.udp6]
            .into_iter()
            .flatten()
            .any(|s| Arc::ptr_eq(s, udp));
        if !current {
            return;
        }
        let (len, addr) = match received {
            Ok(received) => received,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => {
                // Includes WSAECONNRESET after an ICMP port unreachable.
                tracing::debug!(message = "UDP receive error", error = ?e);
                continue;
            }
        };
        let (Some((private_key, public_key)), Some(rate_limiter)) =
            (state.key_pair.as_ref(), state.rate_limiter.as_deref())
        else {
            continue;
        };
        let ctx = ListenContext {
            peers: &state.peers,
            private_key,
            public_key,
            rate_limiter,
        };
        let send = |packet: &[u8]| {
            let _ = udp.send_to(packet, addr);
        };
        receive_datagram(
            &ctx,
            &shared.iface,
            &mut buf,
            &mut scratch,
            len,
            addr,
            &send,
        );
    }
}

/// Runs the peer timers every 250 ms and resets the rate limiter every second.
fn timers(shared: &Shared) {
    let mut scratch = vec![0u8; MAX_UDP_SIZE];
    let mut last_reset = Instant::now();
    while !shared.exiting() {
        thread::sleep(POLL_INTERVAL);
        let state = shared.state.read();
        if last_reset.elapsed() >= Duration::from_secs(1) {
            if let Some(rate_limiter) = state.rate_limiter.as_ref() {
                rate_limiter.reset_count();
            }
            last_reset = Instant::now();
        }
        update_timers(&state.peers, &mut scratch, |addr, packet| {
            if let Some(udp) = state.socket_for(addr) {
                let _ = udp.send_to(packet, addr);
            }
        });
    }
}

/// Serves UAPI requests on the named pipe until the device exits.
fn uapi_server(shared: &Arc<Shared>, pipe: &pipe::PipeServer) {
    while !shared.exiting() {
        let conn = match pipe.accept() {
            Ok(conn) => conn,
            Err(e) => {
                if !shared.exiting() {
                    tracing::error!(message = "UAPI pipe error", error = ?e);
                    thread::sleep(POLL_INTERVAL);
                }
                continue;
            }
        };
        let mut reader = BufReader::new(&conn);
        let mut writer = BufWriter::new(&conn);
        while !shared.exiting()
            && uapi::serve(&mut reader, &mut writer, |request, r, w| {
                let mut state = shared.state.write();
                let mut device = Configurator {
                    shared,
                    state: &mut state,
                };
                match request {
                    uapi::Request::Get => uapi::get(w, &device),
                    uapi::Request::Set => uapi::set(r, &mut device),
                }
            })
        {}
    }
}

/// Devices to stop on Ctrl-C, Ctrl-Break, or console close.
static CTRL_C_DEVICES: Mutex<Vec<Weak<Shared>>> = Mutex::new(Vec::new());

fn exit_on_ctrl_c(shared: &Arc<Shared>) {
    static INSTALLED: OnceLock<bool> = OnceLock::new();

    CTRL_C_DEVICES.lock().push(Arc::downgrade(shared));
    let installed = *INSTALLED.get_or_init(|| {
        #[allow(unsafe_code, reason = "installing a console control handler")]
        // SAFETY: `on_console_event` is a valid handler for the whole process lifetime.
        let ok = unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_console_event), 1)
        };
        ok != 0
    });
    if !installed {
        tracing::warn!("Could not install the Ctrl-C handler");
    }
}

extern "system" fn on_console_event(_ctrl_type: u32) -> windows_sys::core::BOOL {
    let devices = std::mem::take(&mut *CTRL_C_DEVICES.lock());
    for shared in devices.iter().filter_map(Weak::upgrade) {
        shared.trigger_exit();
    }
    1
}
