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
//! [`Uapi::handle_request`] serves one request over any async reader and writer. On Unix,
//! [`UapiListener`] binds the standard socket `/var/run/wireguard/<iface>.sock` that the
//! `wg` tool talks to, and [`Uapi::serve`] accepts connections on it. Windows has no
//! listener yet (no named pipe); the protocol core still works there.
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
mod uapi;

#[cfg(unix)]
pub use listener::{UapiListener, socket_path};
pub use uapi::{TRANSPORT_ID, Uapi, udp_transport};
