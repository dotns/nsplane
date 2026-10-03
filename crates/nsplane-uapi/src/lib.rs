//! The `wg` cross-platform configuration protocol (UAPI) over an nsplane engine.
//!
//! [`Uapi`] answers `get=1` and `set=1` requests by reading and changing a running
//! [`nsplane::Engine`] through its [`EngineHandle`](nsplane::EngineHandle). It owns the network
//! side of the engine: `listen_port` and `fwmark` bind a new [`UdpTransport`] with id
//! [`TRANSPORT_ID`] and install it with
//! [`EngineHandle::replace_transport`](nsplane::EngineHandle::replace_transport) (or
//! [`EngineHandle::add_transport`](nsplane::EngineHandle::add_transport) when the engine
//! does not run it yet). Other transports of the engine are left alone.
//!
//! The UAPI only rebinds a UDP transport it owns: one it bound itself ([`Uapi::new`] with
//! [`Uapi::bind_transport`] or `listen_port=`) or one the engine was built with
//! ([`Uapi::with_listen_port`], over [`udp_transport`]). When the transport under
//! [`TRANSPORT_ID`] is something else, such as a relay or a WebSocket carrier, build the
//! UAPI with [`Uapi::with_external_transport`]: it never replaces that transport, treats a
//! `listen_port=` or `fwmark=` equal to the reported value as a no-op, and fails any other
//! value with `EADDRINUSE` (98), logging why. `get=1` still reports the listen port.
//!
//! [`Uapi::handle_request`] serves one request over any async reader and writer.
//! [`UapiListener`] binds the endpoint that the `wg` tool talks to: on Unix the standard
//! socket `/var/run/wireguard/<iface>.sock` (`socket_path`), on Windows the named pipe
//! `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>` that wireguard-windows
//! uses (`pipe_path`). [`Uapi::serve`] accepts connections on it on both platforms, and on
//! Unix `Uapi::serve_stream` serves a single already-connected stream.
//!
//! ```no_run
//! # async fn run() -> std::io::Result<()> {
//! use nsplane::{ChannelSink, ChannelSource, EngineBuilder};
//! use nsplane_uapi::{Uapi, UapiListener, udp_transport};
//!
//! let (source, _local, _mtu) = ChannelSource::new(1024, 1420);
//! let (sink, _delivered) = ChannelSink::new(1024);
//! let transport = udp_transport(0)?;
//! let port = transport.local_addr().port();
//! let engine = EngineBuilder::new(source, sink)
//!     .transport(transport)
//!     .build()
//!     .map_err(std::io::Error::other)?;
//! let uapi = Uapi::with_listen_port(engine.handle(), port);
//! uapi.serve(UapiListener::bind("wg0")?).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`UdpTransport`]: nsplane::UdpTransport

#![forbid(unsafe_code)]

mod key;
#[cfg(unix)]
mod listener;
#[cfg(windows)]
mod pipe;
mod uapi;

#[cfg(unix)]
pub use listener::{UapiListener, socket_path};
#[cfg(windows)]
pub use pipe::{UapiListener, pipe_path};
pub use uapi::{TRANSPORT_ID, Uapi, udp_transport};

#[cfg(any(unix, windows))]
mod serve {
    use std::future::{Future, poll_fn};
    use std::io;
    use std::pin::pin;
    use std::task::Poll;

    use tokio::io::{AsyncRead, AsyncWrite, BufReader};
    use tokio::sync::broadcast::error::RecvError;
    use tokio::task::JoinSet;

    use crate::{Uapi, UapiListener};

    impl Uapi {
        /// Accepts connections on `listener` and serves each on its own task, request after
        /// request, until the engine shuts down.
        ///
        /// On return, and when this future is dropped, the connection tasks are aborted and
        /// the listener is closed (on Unix its socket file is removed).
        pub async fn serve(&self, mut listener: UapiListener) -> io::Result<()> {
            let mut events = self.handle().subscribe().await.map_err(io::Error::other)?;
            let mut stopped = pin!(async move {
                // The event channel closes when the engine stops.
                while !matches!(events.recv().await, Err(RecvError::Closed)) {}
            });
            let mut connections = JoinSet::new();
            // Accepting mutates the listener on Windows (it replaces the waiting pipe instance).
            let listener = &mut listener;
            loop {
                let mut accept = pin!(listener.accept());
                let accepted = poll_fn(|cx| {
                    if stopped.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(None);
                    }
                    accept.as_mut().poll(cx).map(Some)
                })
                .await;
                match accepted {
                    None => return Ok(()),
                    Some(Ok((reader, writer))) => {
                        while connections.try_join_next().is_some() {}
                        let uapi = self.clone();
                        connections
                            .spawn(async move { uapi.serve_connection(reader, writer).await });
                    }
                    Some(Err(e)) => {
                        tracing::warn!(message = "Failed to accept a UAPI connection", error = ?e);
                    }
                }
            }
        }

        /// Serves requests on the two halves of one connection, request after request, until
        /// the client closes it or a request fails.
        pub(crate) async fn serve_connection<R, W>(&self, reader: R, mut writer: W)
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            let mut reader = BufReader::new(reader);
            loop {
                match self.handle_request(&mut reader, &mut writer).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(e) => {
                        tracing::debug!(message = "UAPI connection failed", error = ?e);
                        return;
                    }
                }
            }
        }
    }
}
