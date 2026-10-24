//! Bounds-checked big-endian reader over a byte slice.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::MacAddr;

/// Consumes fields from the front of a slice; every read returns `None` past the end.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, tail) = self.bytes.split_first_chunk::<N>()?;
        self.bytes = tail;
        Some(*head)
    }

    pub(crate) fn slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.bytes.split_at_checked(len)?;
        self.bytes = tail;
        Some(head)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[b]| b)
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn ipv4(&mut self) -> Option<Ipv4Addr> {
        self.array::<4>().map(Ipv4Addr::from)
    }

    pub(crate) fn ipv6(&mut self) -> Option<Ipv6Addr> {
        self.array::<16>().map(Ipv6Addr::from)
    }

    pub(crate) fn mac(&mut self) -> Option<MacAddr> {
        self.array().map(MacAddr)
    }

    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}
