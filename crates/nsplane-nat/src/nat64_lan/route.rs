//! [`LanRoute`]: one `mapped` IPv6 /96 to `real` IPv4 prefix mapping.

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

/// Why a [`LanRoute`] or a [`Nat64Lan`](crate::Nat64Lan) setting was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Nat64LanError {
    /// The `mapped` prefix is not a /96 with zero low 32 bits.
    #[error("mapped prefix must be a /96 with zero low 32 bits")]
    MappedPrefix,
    /// The `real` prefix is longer than 32 bits or has host bits set.
    #[error("real prefix must be a valid IPv4 prefix without host bits")]
    RealPrefix,
}

/// A route of [`Nat64Lan`](crate::Nat64Lan): IPv6 destinations inside
/// `mapped` reach the IPv4 address in their low 32 bits, provided it is a
/// safe address inside `real`, with their source rewritten to `snat_source`.
///
/// Prefixes are `(address, length)` pairs, like
/// [`LanPrefix`](crate::LanPrefix). Build routes with [`LanRoute::new`]; a
/// route built from the public fields directly is only as valid as those
/// fields, and [`resolve`](Self::resolve) never reaches outside them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LanRoute {
    /// The IPv6 /96 prefix peers address the LAN through.
    pub mapped: (Ipv6Addr, u8),
    /// The IPv4 LAN prefix reachable through the route.
    pub real: (Ipv4Addr, u8),
    /// The IPv4 source of translated packets; LAN hosts reply to it.
    pub snat_source: Ipv4Addr,
}

impl LanRoute {
    /// A validated route: `mapped` must be a /96
    /// with zero low 32 bits and `real` an IPv4 prefix without host bits.
    ///
    /// # Errors
    ///
    /// [`Nat64LanError::MappedPrefix`] or [`Nat64LanError::RealPrefix`].
    pub fn new(
        mapped: (Ipv6Addr, u8),
        real: (Ipv4Addr, u8),
        snat_source: Ipv4Addr,
    ) -> Result<Self, Nat64LanError> {
        if mapped.1 != 96 || u128::from(mapped.0) & u128::from(u32::MAX) != 0 {
            return Err(Nat64LanError::MappedPrefix);
        }
        if real.1 > 32 || u32::from(real.0) & !mask4(real.1) != 0 {
            return Err(Nat64LanError::RealPrefix);
        }
        Ok(Self {
            mapped,
            real,
            snat_source,
        })
    }

    /// The LAN address `dst` maps to: `dst` must be inside `mapped`, and the
    /// IPv4 address in its low 32 bits inside `real` and a safe LAN target
    /// (not unspecified, loopback, link-local, multicast, the limited
    /// broadcast, nor the broadcast address of `real` when it is a /30 or
    /// shorter).
    pub fn resolve(&self, dst: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.maps(dst) {
            return None;
        }
        let [.., a, b, c, d] = dst.octets();
        let target = Ipv4Addr::new(a, b, c, d);
        let (real, len) = self.real;
        let mask = mask4(len);
        (u32::from(target) & mask == u32::from(real) & mask && safe_lan_target(target, self.real))
            .then_some(target)
    }

    /// Whether `dst` is inside `mapped`.
    pub(super) fn maps(&self, dst: Ipv6Addr) -> bool {
        let (mapped, len) = self.mapped;
        let mask = mask6(len);
        u128::from(dst) & mask == u128::from(mapped) & mask
    }
}

/// The netmask of an IPv4 prefix of `len` bits (all ones past 32).
fn mask4(len: u8) -> u32 {
    u32::MAX
        .checked_shl(32_u32.saturating_sub(u32::from(len)))
        .unwrap_or(0)
}

/// The netmask of an IPv6 prefix of `len` bits (all ones past 128).
fn mask6(len: u8) -> u128 {
    u128::MAX
        .checked_shl(128_u32.saturating_sub(u32::from(len)))
        .unwrap_or(0)
}

/// Whether `address` is a safe LAN target inside `real`; see [`LanRoute::resolve`].
fn safe_lan_target(address: Ipv4Addr, (real, len): (Ipv4Addr, u8)) -> bool {
    let broadcast = Ipv4Addr::from(u32::from(real) | !mask4(len));
    !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
        && (len > 30 || address != broadcast)
}
