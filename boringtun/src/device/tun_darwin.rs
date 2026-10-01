// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! macOS utun interface.
#![allow(unsafe_code, reason = "utun control socket syscalls")]

use super::Error;
use libc::{
    AF_INET, AF_INET6, AF_SYS_CONTROL, AF_SYSTEM, F_GETFL, F_SETFL, IF_NAMESIZE, O_NONBLOCK,
    PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, c_int, c_short, c_uchar, connect,
    fcntl, getsockopt, ioctl, iovec, msghdr, recvmsg, sendmsg, sockaddr, sockaddr_ctl, sockaddr_in,
    socket, socklen_t,
};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::null_mut;

const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";

#[repr(C)]
#[allow(non_camel_case_types)]
struct ctl_info {
    ctl_id: u32,
    ctl_name: [c_uchar; 96],
}

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
    ifr_name: [c_uchar; IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

const CTLIOCGINFO: u64 = 0x0000_0000_c064_4e03;
const SIOCGIFMTU: u64 = 0x0000_0000_c020_6933;

/// A macOS utun interface.
#[derive(Debug)]
pub struct TunSocket {
    fd: OwnedFd,
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Parses `utun[0-9]*` into the control unit number (`utun` alone means "any", unit 0).
pub fn parse_utun_name(name: &str) -> Result<u32, Error> {
    let Some(idx) = name.strip_prefix("utun") else {
        return Err(Error::InvalidTunnelName);
    };

    if idx.is_empty() {
        // The name is simply "utun"
        return Ok(0);
    }
    // Everything past utun should represent an integer index
    idx.parse::<u32>()
        .ok()
        .and_then(|x| x.checked_add(1))
        .ok_or(Error::InvalidTunnelName)
}

/// The 4-byte utun packet header for an address family.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "AF_* fit in a byte"
)]
const fn af_header(af: c_int) -> [u8; 4] {
    [0, 0, 0, af as u8]
}

impl TunSocket {
    fn write(&self, src: &[u8], mut hdr: [u8; 4]) -> usize {
        let mut iov = [
            iovec {
                iov_base: hdr.as_mut_ptr().cast(),
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: src.as_ptr().cast_mut().cast(),
                iov_len: src.len(),
            },
        ];

        let msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: 2,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        // SAFETY: `msg_hdr` points at two iovecs that reference live buffers; sendmsg only
        // reads from them.
        let n = unsafe { sendmsg(self.as_raw_fd(), &raw const msg_hdr, 0) };
        usize::try_from(n).unwrap_or(0)
    }

    /// Opens the utun interface `name` (`utun` lets the kernel pick the unit).
    pub fn new(name: &str) -> Result<Self, Error> {
        let idx = parse_utun_name(name)?;

        // SAFETY: plain syscall without pointer arguments.
        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            // SAFETY: `socket` returned a new fd that nothing else owns.
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        info.ctl_name[..CTRL_NAME.len()].copy_from_slice(CTRL_NAME);

        // SAFETY: CTLIOCGINFO reads and writes the `ctl_info` that lives for the call.
        if unsafe { ioctl(fd.as_raw_fd(), CTLIOCGINFO, &raw mut info) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        #[allow(
            clippy::cast_possible_truncation,
            reason = "constants fit their C types"
        )]
        let addr = sockaddr_ctl {
            sc_len: size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: idx,
            sc_reserved: Default::default(),
        };

        #[allow(clippy::cast_possible_truncation, reason = "sockaddr_ctl is 32 bytes")]
        let addr_len = size_of::<sockaddr_ctl>() as socklen_t;
        // SAFETY: `addr` is a valid sockaddr_ctl of `addr_len` bytes.
        if unsafe { connect(fd.as_raw_fd(), (&raw const addr).cast(), addr_len) } < 0 {
            let mut err_string = io::Error::last_os_error().to_string();
            err_string.push_str("(did you run with sudo?)");
            return Err(Error::Connect(err_string));
        }

        Ok(Self { fd })
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

    /// The interface name chosen by the kernel.
    pub fn name(&self) -> Result<String, Error> {
        let mut tunnel_name = [0u8; 256];
        #[allow(clippy::cast_possible_truncation, reason = "256 fits in socklen_t")]
        let mut tunnel_name_len = tunnel_name.len() as socklen_t;
        // SAFETY: `tunnel_name` is valid for writes of `tunnel_name_len` bytes.
        if unsafe {
            getsockopt(
                self.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                tunnel_name.as_mut_ptr().cast(),
                &raw mut tunnel_name_len,
            )
        } < 0
            || tunnel_name_len == 0
        {
            return Err(Error::GetSockOpt(io::Error::last_os_error()));
        }

        let len = usize::try_from(tunnel_name_len - 1).unwrap_or(0);
        Ok(String::from_utf8_lossy(&tunnel_name[..len]).to_string())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
            .map_err(Error::Socket)?;

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };
        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }
        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        // SAFETY: SIOCGIFMTU writes into the `ifreq` that lives for the duration of the call.
        if unsafe { ioctl(sock.as_raw_fd(), SIOCGIFMTU, &raw mut ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        // SAFETY: SIOCGIFMTU initialized the `ifru_mtu` member.
        let mtu = unsafe { ifr.ifr_ifru.ifru_mtu };
        usize::try_from(mtu).map_err(|_| Error::IOCtl(io::Error::from(io::ErrorKind::InvalidData)))
    }

    /// Writes an IPv4 packet; returns the number of bytes written.
    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src, af_header(AF_INET))
    }

    /// Writes an IPv6 packet; returns the number of bytes written.
    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src, af_header(AF_INET6))
    }

    /// Reads one packet into `dst`.
    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let mut hdr = [0u8; 4];

        let mut iov = [
            iovec {
                iov_base: hdr.as_mut_ptr().cast(),
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: dst.as_mut_ptr().cast(),
                iov_len: dst.len(),
            },
        ];

        let mut msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: iov.as_mut_ptr(),
            msg_iovlen: 2,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        // SAFETY: `msg_hdr` points at two iovecs over live, writable buffers.
        let n = unsafe { recvmsg(self.as_raw_fd(), &raw mut msg_hdr, 0) };
        match usize::try_from(n) {
            Err(_) => Err(Error::IfaceRead(io::Error::last_os_error())),
            Ok(0..=4) => Ok(&mut dst[..0]),
            Ok(n) => Ok(&mut dst[..n - 4]),
        }
    }
}
