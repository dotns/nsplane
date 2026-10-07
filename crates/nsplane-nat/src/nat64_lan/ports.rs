//! SNAT port reservation: [`SnatPorts`] and its in-memory [`DefaultSnatPorts`].

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Mutex, PoisonError};

/// The SNAT ports (and ICMP echo identifiers) of [`Nat64Lan`](crate::Nat64Lan)
/// flows, owned by the caller.
///
/// A new flow takes a [`candidate`](Self::candidate) port and keeps it only
/// if [`reserve`](Self::reserve) succeeds; the reservation lasts for the
/// flow's lifetime and is given back with [`release`](Self::release) exactly
/// once, whenever the flow goes: removed with
/// [`Nat64Lan::remove_flow`](crate::Nat64Lan::remove_flow), expired, or
/// evicted from the full flow table. `protocol` is the IPv4 protocol of the
/// flow (6, 17 or 1).
///
/// `reserve` and `release` may run under the flow table's lock, so they must
/// be fast and must not call back into the [`Nat64Lan`](crate::Nat64Lan).
/// An implementation can couple reservations to host sockets.
pub trait SnatPorts: Send + Sync + 'static {
    /// Reserves `snat` for a new flow; `false` when it is taken.
    fn reserve(&self, protocol: u8, snat: SocketAddrV4) -> bool;

    /// Releases a reservation made by [`reserve`](Self::reserve).
    fn release(&self, protocol: u8, snat: SocketAddrV4);

    /// The port to try next for a new flow from `snat_source`; `seq` grows by
    /// one with every candidate the [`Nat64Lan`](crate::Nat64Lan) asks for.
    ///
    /// The default is a round robin over the upper half of the port range:
    /// `32768 + seq % 32768`.
    fn candidate(&self, protocol: u8, snat_source: Ipv4Addr, seq: u32) -> u16 {
        let _ = (protocol, snat_source);
        let [.., hi, lo] = (seq % 32768).to_be_bytes();
        32768 + u16::from_be_bytes([hi, lo])
    }
}

/// The default [`SnatPorts`]: an in-memory set of reserved
/// `(snat_source, port)` pairs, shared by all protocols.
#[derive(Debug, Default)]
pub struct DefaultSnatPorts {
    reserved: Mutex<HashSet<SocketAddrV4>>,
}

impl DefaultSnatPorts {
    /// An allocator with nothing reserved.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of reserved ports.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no port is reserved.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<SocketAddrV4>> {
        self.reserved.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl SnatPorts for DefaultSnatPorts {
    fn reserve(&self, _protocol: u8, snat: SocketAddrV4) -> bool {
        self.lock().insert(snat)
    }

    fn release(&self, _protocol: u8, snat: SocketAddrV4) {
        self.lock().remove(&snat);
    }
}
