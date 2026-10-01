// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Linux TUN device (`/dev/net/tun`).
#![allow(unsafe_code, reason = "TUN ioctls and raw fd I/O")]

use super::Error;
use libc::{
    F_GETFL, F_SETFL, IF_NAMESIZE, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TUN, IFNAMSIZ, O_NONBLOCK,
    O_RDWR, SIOCGIFMTU, c_int, c_short, c_uchar, fcntl, ioctl, open, read, sockaddr, sockaddr_in,
    write,
};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const TUNSETIFF: u64 = 0x4004_54ca;

#[repr(C)]
#[allow(dead_code, reason = "mirrors the C union layout")]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

impl ifreq {
    fn new(name: &str, ifru: IfrIfru) -> Result<Self, Error> {
        let iface_name = name.as_bytes();
        let mut ifr = Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: ifru,
        };
        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }
        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);
        Ok(ifr)
    }
}

#[derive(Debug)]
/// A Linux TUN interface.
pub struct TunSocket {
    fd: OwnedFd,
    name: String,
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl TunSocket {
    fn write(&self, buf: &[u8]) -> usize {
        // SAFETY: `buf` is valid for reads of `buf.len()` bytes.
        let n = unsafe { write(self.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
        usize::try_from(n).unwrap_or(0)
    }

    /// Opens the TUN interface `name`, or adopts the fd if `name` is a number.
    pub fn new(name: &str) -> Result<Self, Error> {
        // If the provided name appears to be a FD, use that.
        if let Ok(fd) = name.parse::<RawFd>() {
            // SAFETY: the caller passes the number of an open TUN fd that it hands over to us.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            return Ok(Self {
                fd,
                name: name.to_string(),
            });
        }

        // SAFETY: the path is a valid NUL-terminated string.
        let fd = match unsafe { open(c"/dev/net/tun".as_ptr(), O_RDWR) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            // SAFETY: `open` returned a new fd that nothing else owns.
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the TUN flags fit in a c_short"
        )]
        let ifr = ifreq::new(
            name,
            IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE) as c_short,
            },
        )?;

        // SAFETY: TUNSETIFF reads an `ifreq` that lives for the duration of the call.
        if unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF as _, &raw const ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let name = name.to_string();
        Ok(Self { fd, name })
    }

    /// Switches the fd to non-blocking mode.
    pub fn set_non_blocking(self) -> Result<Self, Error> {
        // SAFETY: fcntl on an owned fd without pointer arguments.
        match unsafe { fcntl(self.as_raw_fd(), F_GETFL) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            // SAFETY: as above.
            flags => match unsafe { fcntl(self.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(io::Error::last_os_error())),
                _ => Ok(self),
            },
        }
    }

    /// The interface name.
    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        if self.name.parse::<RawFd>().is_ok() {
            return Ok(1500);
        }

        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .map_err(Error::Socket)?;
        let mut ifr = ifreq::new(&self.name, IfrIfru { ifru_mtu: 0 })?;
        debug_assert_eq!(IF_NAMESIZE, IFNAMSIZ);

        // SAFETY: SIOCGIFMTU writes into the `ifreq` that lives for the duration of the call.
        if unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU as _, &raw mut ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        // SAFETY: SIOCGIFMTU initialized the `ifru_mtu` member.
        let mtu = unsafe { ifr.ifr_ifru.ifru_mtu };
        usize::try_from(mtu).map_err(|_| Error::IOCtl(io::Error::from(io::ErrorKind::InvalidData)))
    }

    /// Writes an IPv4 packet; returns the number of bytes written.
    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    /// Writes an IPv6 packet; returns the number of bytes written.
    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    /// Reads one packet into `dst`.
    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        // SAFETY: `dst` is valid for writes of `dst.len()` bytes.
        let n = unsafe { read(self.as_raw_fd(), dst.as_mut_ptr().cast(), dst.len()) };
        usize::try_from(n).map_or_else(
            |_| Err(Error::IfaceRead(io::Error::last_os_error())),
            |n| Ok(&mut dst[..n]),
        )
    }
}
