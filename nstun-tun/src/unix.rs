//! Fd helpers shared by the Unix TUN backends.
#![allow(unsafe_code, reason = "fcntl and socket syscalls on raw fds")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{AF_INET, F_GETFL, F_SETFL, O_NONBLOCK, SOCK_DGRAM, c_int, fcntl, socket, ssize_t};

/// Maps a `-1` syscall return to the current OS error.
pub(crate) fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Maps a negative `ssize_t` syscall return to the current OS error.
pub(crate) fn cvt_len(ret: ssize_t) -> io::Result<usize> {
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

/// Switches `fd` to non-blocking mode.
pub(crate) fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: F_GETFL on an fd we own; no pointer arguments.
    let flags = cvt(unsafe { fcntl(fd.as_raw_fd(), F_GETFL) })?;
    // SAFETY: F_SETFL on an fd we own; no pointer arguments.
    cvt(unsafe { fcntl(fd.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) })?;
    Ok(())
}

/// Opens an `AF_INET` datagram socket to issue interface ioctls on.
pub(crate) fn ioctl_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain syscall without pointer arguments.
    let fd = cvt(unsafe { socket(AF_INET, SOCK_DGRAM, 0) })?;
    // SAFETY: `socket` returned a new fd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
