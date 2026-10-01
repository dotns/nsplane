// SPDX-License-Identifier: BSD-3-Clause

//! Wintun interface. `wintun.dll` must sit next to the executable (or on the DLL search path).

use std::sync::Arc;

use wintun_bindings::{Adapter, MAX_RING_CAPACITY, Session};

use crate::device::Error;

/// A Wintun adapter with a running session.
pub struct TunSocket {
    adapter: Arc<Adapter>,
    session: Arc<Session>,
    name: String,
}

impl std::fmt::Debug for TunSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunSocket")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

fn wintun_error(e: impl std::fmt::Display) -> Error {
    Error::Wintun(e.to_string())
}

impl TunSocket {
    /// Opens the Wintun adapter `name`, creating it if needed, and starts a session.
    pub fn new(name: &str) -> Result<Self, Error> {
        #[allow(unsafe_code, reason = "loading the Wintun driver library")]
        // SAFETY: `wintun.dll` is the signed Wintun library; loading it runs no code beyond its
        // DLL initialization, and the returned function table is only used through the safe
        // wrappers of `wintun-bindings`.
        let wintun = unsafe { wintun_bindings::load() }.map_err(wintun_error)?;
        let adapter = Adapter::open(&wintun, name)
            .or_else(|_| Adapter::create(&wintun, name, "nstun", None))
            .map_err(wintun_error)?;
        let session = adapter
            .start_session(MAX_RING_CAPACITY)
            .map_err(wintun_error)?;
        Ok(Self {
            adapter,
            session,
            name: name.to_owned(),
        })
    }

    /// The interface name.
    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// The current MTU of the interface.
    pub fn mtu(&self) -> Result<usize, Error> {
        self.adapter.get_mtu().map_err(wintun_error)
    }

    /// Blocks until a packet arrives and reads it into `dst`; fails once the session is shut
    /// down.
    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let n = self.session.recv(dst).map_err(Error::IfaceRead)?;
        Ok(&mut dst[..n])
    }

    /// Writes an IPv4 packet; returns the number of bytes written.
    pub fn write4(&self, src: &[u8]) -> usize {
        self.session.send(src).unwrap_or(0)
    }

    /// Writes an IPv6 packet; returns the number of bytes written.
    pub fn write6(&self, src: &[u8]) -> usize {
        self.session.send(src).unwrap_or(0)
    }

    /// Wakes up and fails all blocked and future reads.
    pub fn shutdown(&self) {
        let _ = self.session.shutdown();
    }
}
