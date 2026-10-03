//! The protocol core: `get=1` and `set=1` against an engine handle.

use std::fmt::Write as _;
use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, Ecn, EngineHandle, Path, Peer, PeerStats, TransportId, UdpTransport};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::key::parse_key;

// The UAPI reports errors as Linux errno values on every platform.
const EIO: i32 = 5;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EPROTO: i32 = 71;
const EADDRINUSE: i32 = 98;

/// The id of the UDP transport the UAPI binds; every `endpoint=` path uses it.
pub const TRANSPORT_ID: TransportId = TransportId::new(0);

/// The network settings the UAPI owns.
#[derive(Debug, Default)]
struct NetState {
    /// The port of the installed transport, `None` before the first bind.
    port: Option<u16>,
    /// The firewall mark of the transport, `None` when unset (or set to 0).
    fwmark: Option<u32>,
    /// Whether the transport under [`TRANSPORT_ID`] is not a UDP transport the UAPI owns,
    /// so the UAPI never replaces it.
    external: bool,
}

/// Serves the `wg` UAPI for one engine.
///
/// Cloning is cheap; clones share the network settings, and `set` requests are applied one
/// at a time.
///
/// `listen_port=N` binds a dual-stack `[::]:N` transport (0 picks a free port) and installs
/// it with [`EngineHandle::add_transport`] the first time and
/// [`EngineHandle::replace_transport`] afterwards; repeating the current port is a no-op. `fwmark=M` rebinds the transport on its
/// current port with the mark (Linux and Android only; 0 removes it). Rebinding on the
/// port the current transport holds first moves the engine to a temporary ephemeral
/// transport to release the port.
///
/// The UAPI only rebinds a UDP transport it owns. Over an engine whose transport under
/// [`TRANSPORT_ID`] is something else (a relay, a WebSocket carrier), built with
/// [`Uapi::with_external_transport`], it never replaces that transport: repeating the
/// reported `listen_port` or `fwmark` is a no-op, and any other value fails the request
/// with `EADDRINUSE` (98) and logs the reason.
#[derive(Debug, Clone)]
pub struct Uapi {
    handle: EngineHandle,
    net: Arc<Mutex<NetState>>,
}

impl Uapi {
    /// A UAPI over `handle`, with no transport bound yet (see [`Uapi::bind_transport`]).
    pub fn new(handle: EngineHandle) -> Self {
        Self {
            handle,
            net: Arc::new(Mutex::new(NetState::default())),
        }
    }

    /// A UAPI over `handle`, whose engine already runs the UAPI's transport (id
    /// [`TRANSPORT_ID`], as [`udp_transport`] binds it) on `port`.
    ///
    /// Use it for an engine built with that transport, since an engine needs one to build.
    pub fn with_listen_port(handle: EngineHandle, port: u16) -> Self {
        Self {
            handle,
            net: Arc::new(Mutex::new(NetState {
                port: Some(port),
                fwmark: None,
                external: false,
            })),
        }
    }

    /// A UAPI over `handle`, whose engine runs a transport under [`TRANSPORT_ID`] that is
    /// not a UDP transport the UAPI owns (a relay or a WebSocket carrier, say); `get`
    /// reports `port` as its listen port.
    ///
    /// The UAPI never replaces that transport: a `listen_port=` or `fwmark=` other than the
    /// reported one fails with `EADDRINUSE`, and so does [`Uapi::bind_transport`].
    pub fn with_external_transport(handle: EngineHandle, port: u16) -> Self {
        Self {
            handle,
            net: Arc::new(Mutex::new(NetState {
                port: Some(port),
                fwmark: None,
                external: true,
            })),
        }
    }

    /// The engine handle requests are applied to.
    pub const fn handle(&self) -> &EngineHandle {
        &self.handle
    }

    /// Binds the transport to `port` (0 picks a free port) as `listen_port=` does, and
    /// returns the bound port.
    ///
    /// Use it to add the UAPI's transport to an engine that runs without it. Fails on a
    /// UAPI built with [`Uapi::with_external_transport`].
    pub async fn bind_transport(&self, port: u16) -> io::Result<u16> {
        let mut net = self.net.lock().await;
        let fwmark = net.fwmark;
        self.rebind(&mut net, port, fwmark).await?;
        Ok(net.port.unwrap_or_default())
    }

    /// Reads one request from `reader` and writes the response to `writer`.
    ///
    /// Returns whether the connection can serve another request: `false` once `reader` is
    /// at its end, and after an error response, since the rest of a failed request cannot
    /// be parsed reliably.
    pub async fn handle_request<R, W>(&self, reader: &mut R, writer: &mut W) -> io::Result<bool>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let Some(command) = read_line(reader).await? else {
            return Ok(false);
        };
        let (status, body) = match command.as_str() {
            // Only two commands are legal according to the protocol, get=1 and set=1.
            "get=1" => {
                // The request ends with an empty line, which carries no settings.
                while read_line(reader)
                    .await?
                    .is_some_and(|line| !line.is_empty())
                {}
                match self.get().await {
                    Ok(body) => (0, body),
                    Err(errno) => (errno, String::new()),
                }
            }
            "set=1" => {
                let mut net = self.net.lock().await;
                let status = match self.set(reader, &mut net).await {
                    Ok(()) => 0,
                    Err(errno) => errno,
                };
                (status, String::new())
            }
            _ => (EIO, String::new()),
        };
        // The protocol requires to return an error code as the response, or zero on success
        writer
            .write_all(format!("{body}errno={status}\n\n").as_bytes())
            .await?;
        writer.flush().await?;
        Ok(status == 0)
    }

    /// The `get` response, without the final `errno` line.
    async fn get(&self) -> Result<String, i32> {
        let (port, fwmark) = {
            let net = self.net.lock().await;
            (net.port, net.fwmark)
        };
        let private_key = self.handle.private_key().await.map_err(|_| EIO)?;
        let peers = self.handle.peers().await.map_err(|_| EIO)?;
        Ok(write_config(
            private_key.as_ref(),
            port,
            fwmark,
            &peers,
            SystemTime::now(),
        ))
    }

    /// Reads and applies a `set` request.
    async fn set<R: AsyncBufRead + Unpin>(
        &self,
        reader: &mut R,
        net: &mut NetState,
    ) -> Result<(), i32> {
        let mut section: Option<PeerSection> = None;
        while let Some(line) = read_line(reader).await.map_err(|_| EIO)? {
            if line.is_empty() {
                break; // Done
            }
            let Some((key, val)) = line.split_once('=') else {
                return Err(EPROTO);
            };
            if key == "public_key" {
                // Indicates a new peer section. Commit changes for the current peer; every
                // section starts fresh, so settings never leak into the next peer.
                let public_key = PublicKey::from(parse_key(val).ok_or(EINVAL)?);
                if let Some(done) = section.replace(PeerSection::new(public_key)) {
                    self.apply_peer(done).await?;
                }
            } else if let Some(section) = &mut section {
                section.set(key, val)?;
            } else {
                self.set_interface(net, key, val).await?;
            }
        }
        if let Some(done) = section {
            self.apply_peer(done).await?;
        }
        Ok(())
    }

    /// Applies one interface setting.
    async fn set_interface(&self, net: &mut NetState, key: &str, val: &str) -> Result<(), i32> {
        match key {
            "private_key" => {
                let key = parse_key(val).ok_or(EINVAL)?;
                self.handle
                    .set_private_key(StaticSecret::from(key))
                    .await
                    .map_err(|_| EIO)
            }
            "listen_port" => {
                let port = val.parse::<u16>().map_err(|_| EINVAL)?;
                if port != 0 && net.port == Some(port) {
                    return Ok(());
                }
                let fwmark = net.fwmark;
                self.rebind(net, port, fwmark).await.map_err(|e| {
                    tracing::error!(message = "Failed to bind the listen port", port, error = ?e);
                    EADDRINUSE
                })
            }
            "fwmark" => {
                let mark = val.parse::<u32>().map_err(|_| EINVAL)?;
                let fwmark = (mark != 0).then_some(mark);
                if fwmark == net.fwmark {
                    return Ok(());
                }
                let result = match net.port {
                    Some(port) => self.rebind(net, port, fwmark).await,
                    None => check_fwmark_support(fwmark).map(|()| net.fwmark = fwmark),
                };
                result.map_err(|e| {
                    tracing::error!(message = "Failed to set the fwmark", mark, error = ?e);
                    EADDRINUSE
                })
            }
            "replace_peers" => match val.parse::<bool>() {
                Ok(true) => self.handle.remove_all_peers().await.map_err(|_| EIO),
                Ok(false) => Ok(()),
                Err(_) => Err(EINVAL),
            },
            _ => Err(EINVAL),
        }
    }

    /// Applies one peer section.
    async fn apply_peer(&self, section: PeerSection) -> Result<(), i32> {
        let key = section.peer.public_key;
        if section.remove {
            return self.handle.remove_peer(key).await.map_err(|_| EIO);
        }
        if section.update_only && self.handle.peer_id(key).await.map_err(|_| EIO)?.is_none() {
            return Ok(());
        }
        if self.handle.private_key().await.map_err(|_| EIO)?.is_none() {
            tracing::error!(message = "Failed to update peer", error = "no private key");
            return Err(ENOSPC);
        }
        self.handle
            .add_or_update_peer(section.peer)
            .await
            .map_err(|_| EIO)
    }

    /// Binds a transport to `port` with `fwmark` and installs it.
    async fn rebind(&self, net: &mut NetState, port: u16, fwmark: Option<u32>) -> io::Result<()> {
        if net.external {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the transport is not a UDP transport the UAPI owns",
            ));
        }
        check_fwmark_support(fwmark)?;
        if port != 0 && net.port == Some(port) {
            // The current transport holds the port: move to a temporary one to release it.
            let parked = udp_transport(0)?;
            net.port = Some(parked.local_addr().port());
            self.install(parked, true).await?;
        }
        let transport = udp_transport(port)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(mark) = fwmark {
            transport.set_fwmark(mark)?;
        }
        let bound = transport.local_addr().port();
        self.install(transport, net.port.is_some()).await?;
        net.port = Some(bound);
        net.fwmark = fwmark;
        Ok(())
    }

    /// Adds `transport` to the engine, or replaces the one already `installed`.
    async fn install(&self, transport: UdpTransport, installed: bool) -> io::Result<()> {
        let result = if installed {
            self.handle.replace_transport(transport).await
        } else {
            self.handle.add_transport(transport).await
        };
        result.map_err(io::Error::other)
    }
}

/// The settings of one peer section of a `set` request.
struct PeerSection {
    peer: Peer,
    remove: bool,
    update_only: bool,
}

impl PeerSection {
    const fn new(public_key: PublicKey) -> Self {
        Self {
            peer: Peer::new(public_key),
            remove: false,
            update_only: false,
        }
    }

    /// Applies one peer setting.
    fn set(&mut self, key: &str, val: &str) -> Result<(), i32> {
        match key {
            "remove" => self.remove = parse_bool(val)?,
            "update_only" => self.update_only = parse_bool(val)?,
            // An all-zero key removes the preshared key.
            "preshared_key" => self.peer.preshared_key = Some(parse_key(val).ok_or(EINVAL)?),
            "endpoint" => {
                let addr = val.parse::<SocketAddr>().map_err(|_| EINVAL)?;
                self.peer.path = Some(Path {
                    transport: TRANSPORT_ID,
                    addr,
                    ecn: Ecn::NotEct,
                });
            }
            // 0 disables the keepalive.
            "persistent_keepalive_interval" => {
                self.peer.persistent_keepalive = Some(val.parse::<u16>().map_err(|_| EINVAL)?);
            }
            "replace_allowed_ips" => self.peer.replace_allowed_ips = parse_bool(val)?,
            "allowed_ip" => self
                .peer
                .allowed_ips
                .push(val.parse::<AllowedIp>().map_err(|_| EINVAL)?),
            "protocol_version" => match val.parse::<u32>() {
                Ok(1) => {} // Only version 1 is legal
                _ => return Err(EINVAL),
            },
            _ => return Err(EINVAL),
        }
        Ok(())
    }
}

fn parse_bool(val: &str) -> Result<bool, i32> {
    val.parse::<bool>().map_err(|_| EINVAL)
}

/// Reads one line without its newline; `None` at the end of the input.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Option<String>> {
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    if line.ends_with('\n') {
        line.pop();
    }
    Ok(Some(line))
}

/// Binds the UAPI's transport: id [`TRANSPORT_ID`] on a dual-stack `[::]:port` (0 picks a
/// free port), as `listen_port=` does.
///
/// Hand it to [`EngineBuilder::transport`] and the built engine's handle to
/// [`Uapi::with_listen_port`] with its port.
///
/// [`EngineBuilder::transport`]: nsplane::EngineBuilder::transport
pub fn udp_transport(port: u16) -> io::Result<UdpTransport> {
    UdpTransport::bind(TRANSPORT_ID, (Ipv6Addr::UNSPECIFIED, port).into())
}

/// Fails if `fwmark` is set on a platform without firewall marks.
fn check_fwmark_support(fwmark: Option<u32>) -> io::Result<()> {
    if cfg!(any(target_os = "linux", target_os = "android")) || fwmark.is_none() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fwmark is not supported on this platform",
        ))
    }
}

/// Unix time of a handshake that happened `elapsed` before `now`.
fn last_handshake_unix(elapsed: Duration, now: SystemTime) -> (u64, u32) {
    let at = now
        .checked_sub(elapsed)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .unwrap_or_default();
    (at.as_secs(), at.subsec_nanos())
}

/// Formats the `get` response, without the final `errno` line.
fn write_config(
    private_key: Option<&StaticSecret>,
    port: Option<u16>,
    fwmark: Option<u32>,
    peers: &[PeerStats],
    now: SystemTime,
) -> String {
    // Writing to a `String` cannot fail.
    let mut out = String::new();
    if let Some(key) = private_key {
        let _ = writeln!(out, "private_key={}", hex::encode(key.to_bytes()));
    }
    if let Some(port) = port {
        let _ = writeln!(out, "listen_port={port}");
    }
    if let Some(fwmark) = fwmark {
        let _ = writeln!(out, "fwmark={fwmark}");
    }
    for peer in peers {
        let _ = writeln!(
            out,
            "public_key={}",
            hex::encode(peer.public_key.as_bytes())
        );
        if let Some(key) = peer.preshared_key {
            let _ = writeln!(out, "preshared_key={}", hex::encode(key));
        }
        let _ = writeln!(out, "protocol_version=1");
        if let Some(path) = peer.path {
            let _ = writeln!(out, "endpoint={}", path.addr);
        }
        // The UAPI reports the wall-clock time of the handshake, not its age; 0 for none.
        let (secs, nsecs) = peer
            .last_handshake
            .map_or((0, 0), |elapsed| last_handshake_unix(elapsed, now));
        let _ = writeln!(out, "last_handshake_time_sec={secs}");
        let _ = writeln!(out, "last_handshake_time_nsec={nsecs}");
        let _ = writeln!(out, "rx_bytes={}", peer.rx);
        let _ = writeln!(out, "tx_bytes={}", peer.tx);
        let _ = writeln!(
            out,
            "persistent_keepalive_interval={}",
            peer.persistent_keepalive.unwrap_or(0)
        );
        for ip in &peer.allowed_ips {
            let _ = writeln!(out, "allowed_ip={}/{}", ip.addr, ip.cidr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use nsplane::{ChannelSink, ChannelSource, ChannelTransport, Engine, EngineBuilder, Transport};

    use super::*;

    /// An engine on in-memory packet ends running `transport`, with the packet ends kept
    /// open.
    fn engine<T: Transport>(transport: T) -> (Engine, impl Sized) {
        let (source, local, mtu) = ChannelSource::new(16, 1420);
        let (sink, delivered) = ChannelSink::new(16);
        let engine = EngineBuilder::new(source, sink)
            .transport(transport)
            .build()
            .unwrap();
        (engine, (local, mtu, delivered))
    }

    /// The response to `request`.
    async fn request(uapi: &Uapi, request: &str) -> String {
        let mut reader = request.as_bytes();
        let mut out = Vec::new();
        uapi.handle_request(&mut reader, &mut out).await.unwrap();
        String::from_utf8(out).unwrap()
    }

    /// The listen port `get` reports.
    async fn listen_port(uapi: &Uapi) -> Option<u16> {
        let config = request(uapi, "get=1\n\n").await;
        config
            .lines()
            .find_map(|line| line.strip_prefix("listen_port="))
            .map(|port| port.parse().unwrap())
    }

    /// Whether `port` can be bound as the UAPI binds it.
    fn port_is_free(port: u16) -> bool {
        udp_transport(port).is_ok()
    }

    #[tokio::test]
    async fn owned_transport_is_rebound() {
        let transport = udp_transport(0).unwrap();
        let first = transport.local_addr().port();
        let (engine, _ends) = engine(transport);
        let uapi = Uapi::with_listen_port(engine.handle(), first);

        // Repeating the port keeps the transport.
        assert_eq!(
            request(&uapi, &format!("set=1\nlisten_port={first}\n\n")).await,
            "errno=0\n\n"
        );
        assert!(!port_is_free(first));

        // A new port replaces the transport and releases the old one.
        assert_eq!(
            request(&uapi, "set=1\nlisten_port=0\n\n").await,
            "errno=0\n\n"
        );
        let second = listen_port(&uapi).await.unwrap();
        assert_ne!(second, first);
        assert!(!port_is_free(second));
        assert!(port_is_free(first));

        // Rebinding on the held port parks the engine on another one to release it.
        assert_eq!(uapi.bind_transport(second).await.unwrap(), second);
        assert_eq!(listen_port(&uapi).await, Some(second));
        assert!(!port_is_free(second));
    }

    #[tokio::test]
    async fn new_uapi_binds_the_transport() {
        let (engine, _ends) = engine(udp_transport(0).unwrap());
        // Leave the engine without the UAPI's transport, as `Uapi::new` expects.
        engine
            .handle()
            .remove_transport(TRANSPORT_ID)
            .await
            .unwrap();
        let uapi = Uapi::new(engine.handle());
        assert_eq!(listen_port(&uapi).await, None);
        let port = uapi.bind_transport(0).await.unwrap();
        assert_eq!(listen_port(&uapi).await, Some(port));
        assert!(!port_is_free(port));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN"]
    async fn owned_transport_is_rebound_with_a_fwmark() {
        let transport = udp_transport(0).unwrap();
        let port = transport.local_addr().port();
        let (engine, _ends) = engine(transport);
        let uapi = Uapi::with_listen_port(engine.handle(), port);

        assert_eq!(request(&uapi, "set=1\nfwmark=7\n\n").await, "errno=0\n\n");
        let config = request(&uapi, "get=1\n\n").await;
        assert!(
            config.contains(&format!("listen_port={port}\nfwmark=7\n")),
            "{config}"
        );
        assert!(!port_is_free(port));
    }

    #[tokio::test]
    async fn external_transport_is_never_replaced() {
        let relay = SocketAddr::from(([192, 0, 2, 1], 1000));
        let far = SocketAddr::from(([192, 0, 2, 2], 1000));
        let (near, far_end) =
            ChannelTransport::pair(16, (TRANSPORT_ID, relay), (TRANSPORT_ID, far));
        let (engine, _ends) = engine(near);
        let uapi = Uapi::with_external_transport(engine.handle(), 51820);
        let to_engine = Path {
            transport: TRANSPORT_ID,
            addr: relay,
            ecn: Ecn::NotEct,
        };

        // The reported settings are no-ops; anything else fails with EADDRINUSE.
        for (setting, errno) in [
            ("listen_port=51820", 0),
            ("fwmark=0", 0),
            ("listen_port=51821", EADDRINUSE),
            ("listen_port=0", EADDRINUSE),
            ("fwmark=7", EADDRINUSE),
        ] {
            assert_eq!(
                request(&uapi, &format!("set=1\n{setting}\n\n")).await,
                format!("errno={errno}\n\n"),
                "{setting}"
            );
            // The engine still runs the channel transport: its receiving end is open.
            far_end.send(b"datagram", &to_engine).await.unwrap();
        }
        assert!(uapi.bind_transport(0).await.is_err());
        far_end.send(b"datagram", &to_engine).await.unwrap();

        let config = request(&uapi, "get=1\n\n").await;
        assert_eq!(config, "listen_port=51820\nerrno=0\n\n");
    }

    #[test]
    fn last_handshake_is_reported_as_unix_time() {
        let now = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_100, 500);
        let (secs, nsecs) = last_handshake_unix(Duration::new(100, 0), now);
        assert_eq!((secs, nsecs), (1_700_000_000, 500));
        // A handshake before the epoch cannot be represented and reports 0.
        assert_eq!(
            last_handshake_unix(Duration::new(200, 0), SystemTime::UNIX_EPOCH),
            (0, 0)
        );
    }

    #[test]
    fn config_reports_the_handshake_as_unix_time() {
        let now = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_100, 500);
        let peer = PeerStats {
            peer: nsplane::PeerId::new(1),
            public_key: PublicKey::from([1; 32]),
            path: None,
            allowed_ips: Vec::new(),
            preshared_key: None,
            persistent_keepalive: None,
            rx: 3,
            tx: 4,
            data_rx: 0,
            data_tx: 0,
            last_handshake: Some(Duration::new(100, 0)),
        };
        let config = write_config(None, None, None, &[peer], now);
        assert!(config.contains("last_handshake_time_sec=1700000000\n"));
        assert!(config.contains("last_handshake_time_nsec=500\n"));
        assert!(config.contains("rx_bytes=3\ntx_bytes=4\n"));
        assert!(config.contains("persistent_keepalive_interval=0\n"));
    }
}
