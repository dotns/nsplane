// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::device::Error;
use crate::noise::{Tunn, TunnResult};

#[derive(Default, Debug)]
/// Where to send packets for a peer.
pub struct Endpoint {
    /// Last known address of the peer.
    pub addr: Option<SocketAddr>,
    /// Connected socket to `addr`, if enabled.
    pub conn: Option<socket2::Socket>,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field("index", &self.index)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// A peer of a device: its tunnel and endpoint. Allowed IPs live in the device's routing table.
pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    preshared_key: Option<[u8; 32]>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
/// A network in CIDR notation.
pub struct AllowedIP {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length.
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(Self { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(Self { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    /// Creates a peer around `tunnel`.
    pub const fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            preshared_key,
        }
    }

    /// Replaces the preshared key; the next handshake uses it.
    pub const fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel.set_preshared_key(preshared_key);
    }

    /// Sets the persistent keepalive interval in seconds; `0` disables it.
    pub fn set_persistent_keepalive(&mut self, interval: u16) {
        self.tunnel
            .set_persistent_keepalive((interval > 0).then_some(interval));
    }

    /// Runs the timers of the tunnel; see [`Tunn::update_timers`].
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    /// Returns the current endpoint.
    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    /// Closes the connected socket, if any.
    pub fn shutdown_endpoint(&self) {
        let conn = self.endpoint.write().conn.take();
        if let Some(conn) = conn {
            tracing::info!("Disconnecting from endpoint");
            let _ = conn.shutdown(Shutdown::Both);
        }
    }

    /// Updates the endpoint address, closing a socket connected to the old one.
    pub fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                let _ = conn.shutdown(Shutdown::Both);
            }

            endpoint.addr = Some(addr);
        }
    }

    /// Opens a UDP socket bound to `port` and connected to the endpoint.
    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let Some(addr) = endpoint.addr else {
            return Err(Error::Connect("No endpoint".to_owned()));
        };

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        let _ = fwmark;
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?addr
        );

        endpoint.conn = Some(udp_conn.try_clone()?);
        drop(endpoint);

        Ok(udp_conn)
    }

    /// Time since the current session was established.
    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    /// The persistent keepalive interval in seconds.
    pub const fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    /// The preshared key, if set.
    pub const fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    /// The index the tunnel uses for its sessions.
    pub const fn index(&self) -> u32 {
        self.index
    }
}
