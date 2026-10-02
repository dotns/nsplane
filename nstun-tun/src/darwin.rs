//! macOS and iOS utun backend: a `PF_SYSTEM` control socket whose packets carry a
//! 4-byte address-family header.
//!
//! Adapted from `boringtun/src/device/tun_darwin.rs`.
#![allow(unsafe_code, reason = "utun control socket syscalls")]

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use libc::{
    AF_SYS_CONTROL, AF_SYSTEM, IF_NAMESIZE, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL,
    UTUN_OPT_IFNAME, c_int, c_ulong, connect, getsockopt, ioctl, iovec, readv, sockaddr_ctl,
    socket, socklen_t, writev,
};

use crate::unix::{cvt, cvt_len, ioctl_socket};
use crate::utun::{af_header, parse_utun_name};

const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";
const CTLIOCGINFO: c_ulong = 0xc064_4e03;
const SIOCGIFMTU: c_ulong = 0xc020_6933;

// The utun helpers hard-code Darwin's address families.
const _: () = assert!(libc::AF_INET == 2 && libc::AF_INET6 == 30);

/// `struct ctl_info`.
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

/// `struct ifreq`: the interface name followed by a 16-byte union.
#[repr(C)]
struct IfReq {
    name: [u8; IF_NAMESIZE],
    data: IfReqData,
}

/// The members of the `ifreq` union used here, padded to the kernel's size.
#[repr(C)]
union IfReqData {
    mtu: c_int,
    _size: [u8; 16],
}

/// Opens the utun interface `name` (`utun` lets the kernel pick the unit).
pub(crate) fn create(name: &str) -> io::Result<OwnedFd> {
    let unit = parse_utun_name(name)?;

    // SAFETY: plain syscall without pointer arguments.
    let fd = cvt(unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) })?;
    // SAFETY: `socket` returned a new fd that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut info = CtlInfo {
        ctl_id: 0,
        ctl_name: [0; 96],
    };
    info.ctl_name[..CTRL_NAME.len()].copy_from_slice(CTRL_NAME);
    // SAFETY: CTLIOCGINFO reads and writes the `ctl_info` that lives for the call.
    cvt(unsafe { ioctl(fd.as_raw_fd(), CTLIOCGINFO, &raw mut info) })?;

    let addr = sockaddr_ctl {
        sc_len: u8::try_from(size_of::<sockaddr_ctl>()).unwrap_or(u8::MAX),
        sc_family: u8::try_from(AF_SYSTEM).unwrap_or(u8::MAX),
        ss_sysaddr: u16::try_from(AF_SYS_CONTROL).unwrap_or(u16::MAX),
        sc_id: info.ctl_id,
        sc_unit: unit,
        sc_reserved: Default::default(),
    };
    let addr_len = socklen_t::try_from(size_of::<sockaddr_ctl>()).unwrap_or(socklen_t::MAX);
    // SAFETY: `addr` is a valid `sockaddr_ctl` of `addr_len` bytes.
    cvt(unsafe { connect(fd.as_raw_fd(), (&raw const addr).cast(), addr_len) })?;
    Ok(fd)
}

/// The utun interface name of `fd` (`UTUN_OPT_IFNAME`); fails with the OS error for a
/// socket that is not a utun control socket.
pub(crate) fn name(fd: BorrowedFd<'_>) -> io::Result<String> {
    let mut name = [0u8; IF_NAMESIZE];
    let mut len = socklen_t::try_from(name.len()).unwrap_or(0);
    // SAFETY: `name` is valid for writes of `len` bytes and `len` outlives the call.
    cvt(unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &raw mut len,
        )
    })?;
    let len = usize::try_from(len).unwrap_or(0).min(name.len());
    let name = &name[..len];
    let name = name.split(|&b| b == 0).next().unwrap_or(name);
    String::from_utf8(name.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// The MTU of the interface `name` (`SIOCGIFMTU`).
pub(crate) fn mtu(name: &str) -> io::Result<u16> {
    let bytes = name.as_bytes();
    if bytes.len() >= IF_NAMESIZE || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {name:?}"),
        ));
    }
    let mut ifr = IfReq {
        name: [0; IF_NAMESIZE],
        data: IfReqData { _size: [0; 16] },
    };
    ifr.name[..bytes.len()].copy_from_slice(bytes);

    let sock = ioctl_socket()?;
    // SAFETY: SIOCGIFMTU writes into the `ifreq` that lives for the duration of the call.
    cvt(unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU, &raw mut ifr) })?;
    // SAFETY: the union was fully zero-initialised and SIOCGIFMTU set `mtu`; every bit
    // pattern is a valid `c_int`.
    let mtu = unsafe { ifr.data.mtu };
    u16::try_from(mtu).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Reads one frame, scattering the AF header into a scratch array and the packet
/// straight into `packet`; returns the packet length (`0` at end of stream).
pub(crate) fn read(fd: BorrowedFd<'_>, packet: &mut [u8]) -> io::Result<usize> {
    let mut header = [0u8; 4];
    let iov = [
        iovec {
            iov_base: header.as_mut_ptr().cast(),
            iov_len: header.len(),
        },
        iovec {
            iov_base: packet.as_mut_ptr().cast(),
            iov_len: packet.len(),
        },
    ];
    // SAFETY: both iovecs reference live, writable buffers of the given lengths.
    let n = cvt_len(unsafe { readv(fd.as_raw_fd(), iov.as_ptr(), 2) })?;
    match n {
        0 => Ok(0),
        n if n <= header.len() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun frame without a packet",
        )),
        n => Ok(n - header.len()),
    }
}

/// Writes one packet behind the AF header chosen from its IP version; returns the
/// number of bytes written including the header.
pub(crate) fn write(fd: BorrowedFd<'_>, packet: &[u8]) -> io::Result<usize> {
    let header = af_header(packet).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet is neither IPv4 nor IPv6",
        )
    })?;
    let iov = [
        iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: header.len(),
        },
        iovec {
            iov_base: packet.as_ptr().cast_mut().cast(),
            iov_len: packet.len(),
        },
    ];
    // SAFETY: both iovecs reference live buffers of the given lengths; writev only
    // reads from them.
    cvt_len(unsafe { writev(fd.as_raw_fd(), iov.as_ptr(), 2) })
}
