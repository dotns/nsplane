//! Fd helpers shared by the Unix TUN backends.
#![allow(unsafe_code, reason = "fcntl and socket syscalls on raw fds")]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{
    AF_INET, F_GETFD, F_GETFL, F_SETFL, O_NONBLOCK, SOCK_DGRAM, c_int, fcntl, socket, ssize_t,
};

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

/// Takes ownership of the raw fd `fd`, for fds passed in by number (a parent process,
/// `--tun-fd`, `--uapi-fd`).
///
/// Ownership rules: the call takes ownership of `fd`. It must be an fd the process
/// inherited or otherwise owns, and nothing else may use or close it afterwards; it is
/// closed when the returned [`OwnedFd`] drops. Adopting the same number twice, or an fd
/// that other code still uses, closes it under that code.
///
/// A negative number fails with [`io::ErrorKind::InvalidInput`]; a number that is not an
/// open fd fails with the OS error of `fcntl(F_GETFD)` (`EBADF`). Neither adopts
/// anything.
pub fn adopt_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("negative fd {fd}"),
        ));
    }
    // SAFETY: F_GETFD only reads the fd's flags; no pointer arguments, and an fd that is
    // not open yields EBADF.
    cvt(unsafe { fcntl(fd, F_GETFD) })?;
    // SAFETY: `fd` is open, and the caller hands over its ownership per the documented
    // rules, so nothing else closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
