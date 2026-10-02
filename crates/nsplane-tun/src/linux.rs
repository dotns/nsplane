//! Linux and Android TUN backend: `/dev/net/tun` with `IFF_NO_PI`, so every read and
//! write is one raw IP packet, optionally preceded by a virtio-net header
//! (`IFF_VNET_HDR`) when the device uses segmentation offloads.
//!
//! Adapted from the upstream TUN device layer (see `LICENSE.md`).
#![allow(unsafe_code, reason = "TUN ioctls and raw fd I/O")]

use std::fs::OpenOptions;
use std::io::{self, IoSlice};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use libc::{
    EINVAL, IFF_NO_PI, IFF_TUN, IFF_VNET_HDR, IFNAMSIZ, SIOCGIFMTU, TUN_F_CSUM, TUN_F_TSO4,
    TUN_F_TSO6, TUN_F_USO4, TUN_F_USO6, TUNGETIFF, TUNSETIFF, TUNSETOFFLOAD, c_int, c_short,
    c_uint, c_ulong, ioctl,
};

use crate::tun::Offload;
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
    open(name, IFF_TUN | IFF_NO_PI)
}

/// Like [`create`], but with a virtio-net header on every packet and TCP (and, if the
/// kernel accepts it, UDP) segmentation offload enabled. Falls back to the plain device
/// of [`create`] if the kernel supports neither the header nor the offloads.
pub(crate) fn create_offload(name: &str) -> io::Result<(OwnedFd, Offload)> {
    match open(name, IFF_TUN | IFF_NO_PI | IFF_VNET_HDR) {
        Ok(fd) => match set_offload(&fd) {
            Ok(uso) => {
                tracing::debug!(name, uso, "TUN device with vnet header and TSO");
                return Ok((
                    fd,
                    Offload {
                        vnet_hdr: true,
                        tso: true,
                        uso,
                    },
                ));
            }
            // Closing the fd removes the interface, so the plain device below can take
            // the same name.
            Err(e) => tracing::debug!(name, "TUNSETOFFLOAD failed ({e}), using a plain TUN device"),
        },
        Err(e) if e.raw_os_error() == Some(EINVAL) => {
            tracing::debug!(
                name,
                "IFF_VNET_HDR rejected ({e}), using a plain TUN device"
            );
        }
        Err(e) => return Err(e),
    }
    Ok((create(name)?, Offload::default()))
}

/// Opens `/dev/net/tun` and attaches it to the TUN interface `name` with `flags`.
fn open(name: &str, flags: c_int) -> io::Result<OwnedFd> {
    let fd = OwnedFd::from(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?,
    );
    let mut ifr = IfReq::new(name)?;
    ifr.data.flags =
        c_short::try_from(flags).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: TUNSETIFF reads and writes the `ifreq` that lives for the duration of the
    // call; `IfReq` matches the kernel's 40-byte layout.
    cvt(unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut ifr) })?;
    Ok(fd)
}

/// Enables checksum and TCP segmentation offload, plus UDP segmentation offload if the
/// kernel accepts it (Linux 6.2+; older kernels reject the flags with `EINVAL`).
/// Returns whether UDP segmentation offload is on.
fn set_offload(fd: &OwnedFd) -> io::Result<bool> {
    let tso = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    let set = |flags: c_uint| {
        // SAFETY: TUNSETOFFLOAD takes its flags by value; no pointer arguments.
        cvt(unsafe { ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, c_ulong::from(flags)) })
    };
    match set(tso | TUN_F_USO4 | TUN_F_USO6) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(EINVAL) => set(tso).map(|_| false),
        Err(e) => Err(e),
    }
}

/// The interface name and flags of the TUN device `fd` is attached to (`TUNGETIFF`).
fn get_iff(fd: BorrowedFd<'_>) -> io::Result<IfReq> {
    let mut ifr = IfReq::new("")?;
    // SAFETY: TUNGETIFF writes into the `ifreq` that lives for the duration of the call.
    cvt(unsafe { ioctl(fd.as_raw_fd(), TUNGETIFF, &raw mut ifr) })?;
    Ok(ifr)
}

/// The name of the interface `fd` is attached to (`TUNGETIFF`); fails with the OS error
/// for an fd that is not a TUN device.
pub(crate) fn name(fd: BorrowedFd<'_>) -> io::Result<String> {
    get_iff(fd)?.name()
}

/// Whether the TUN device `fd` is attached to carries a virtio-net header on every
/// packet (`IFF_VNET_HDR`, from `TUNGETIFF`); fails with the OS error for an fd that is
/// not a TUN device.
pub(crate) fn vnet_hdr(fd: BorrowedFd<'_>) -> io::Result<bool> {
    let ifr = get_iff(fd)?;
    // SAFETY: the union was fully zero-initialised and TUNGETIFF set `flags`; every bit
    // pattern is a valid `c_short`.
    let flags = unsafe { ifr.data.flags };
    Ok(c_int::from(flags) & IFF_VNET_HDR != 0)
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

/// Writes the concatenation of `parts` as one packet (`writev`); returns the number of
/// bytes written.
pub(crate) fn writev(fd: BorrowedFd<'_>, parts: &[IoSlice<'_>]) -> io::Result<usize> {
    let count =
        c_int::try_from(parts.len()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `IoSlice` is ABI-compatible with `struct iovec` on Unix, and every slice
    // is valid for reads of its length for the duration of the call.
    cvt_len(unsafe { libc::writev(fd.as_raw_fd(), parts.as_ptr().cast(), count) })
}
