//! Linux and Android TUN backend: `/dev/net/tun` with `IFF_NO_PI`, so every read and
//! write is one raw IP packet.
//!
//! Adapted from the upstream TUN device layer (see `LICENSE.md`).
#![allow(unsafe_code, reason = "TUN ioctls and raw fd I/O")]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use libc::{IFF_NO_PI, IFF_TUN, IFNAMSIZ, SIOCGIFMTU, TUNGETIFF, TUNSETIFF, c_int, c_short, ioctl};

use crate::unix::{cvt, cvt_len, ioctl_socket};

/// `struct ifreq`: the interface name followed by a 24-byte union.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: IfReqData,
}

/// The members of the `ifreq` union used here, padded to the kernel's size.
#[repr(C)]
union IfReqData {
    flags: c_short,
    mtu: c_int,
    _size: [u64; 3],
}

impl IfReq {
    /// An `ifreq` naming `name`; the union is zeroed.
    fn new(name: &str) -> io::Result<Self> {
        let mut ifr = Self {
            name: [0; IFNAMSIZ],
            data: IfReqData { _size: [0; 3] },
        };
        let bytes = name.as_bytes();
        if bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid interface name {name:?}"),
            ));
        }
        ifr.name[..bytes.len()].copy_from_slice(bytes);
        Ok(ifr)
    }

    /// The interface name up to the first NUL.
    fn name(&self) -> io::Result<String> {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
        String::from_utf8(self.name[..len].to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Opens `/dev/net/tun` and attaches it to the TUN interface `name` (`""` or a
/// `%d` pattern lets the kernel pick the name).
pub(crate) fn create(name: &str) -> io::Result<OwnedFd> {
    let fd = OwnedFd::from(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?,
    );
    let mut ifr = IfReq::new(name)?;
    ifr.data.flags = c_short::try_from(IFF_TUN | IFF_NO_PI)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: TUNSETIFF reads and writes the `ifreq` that lives for the duration of the
    // call; `IfReq` matches the kernel's 40-byte layout.
    cvt(unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut ifr) })?;
    Ok(fd)
}

/// The name of the interface `fd` is attached to (`TUNGETIFF`); fails with the OS error
/// for an fd that is not a TUN device.
pub(crate) fn name(fd: BorrowedFd<'_>) -> io::Result<String> {
    let mut ifr = IfReq::new("")?;
    // SAFETY: TUNGETIFF writes into the `ifreq` that lives for the duration of the call.
    cvt(unsafe { ioctl(fd.as_raw_fd(), TUNGETIFF, &raw mut ifr) })?;
    ifr.name()
}

/// The MTU of the interface `name` (`SIOCGIFMTU`).
pub(crate) fn mtu(name: &str) -> io::Result<u16> {
    let sock = ioctl_socket()?;
    let mut ifr = IfReq::new(name)?;
    // SAFETY: SIOCGIFMTU writes into the `ifreq` that lives for the duration of the call.
    cvt(unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU as _, &raw mut ifr) })?;
    // SAFETY: the union was fully zero-initialised and SIOCGIFMTU set `mtu`; every bit
    // pattern is a valid `c_int`.
    let mtu = unsafe { ifr.data.mtu };
    u16::try_from(mtu).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads one packet into `packet`; returns its length (`0` at end of stream).
pub(crate) fn read(fd: BorrowedFd<'_>, packet: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `packet` is valid for writes of `packet.len()` bytes.
    cvt_len(unsafe { libc::read(fd.as_raw_fd(), packet.as_mut_ptr().cast(), packet.len()) })
}

/// Writes one packet; returns the number of bytes written.
pub(crate) fn write(fd: BorrowedFd<'_>, packet: &[u8]) -> io::Result<usize> {
    // SAFETY: `packet` is valid for reads of `packet.len()` bytes.
    cvt_len(unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) })
}
