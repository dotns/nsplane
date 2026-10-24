//! Linux TAP transport: `/dev/net/tun` with `IFF_TAP | IFF_NO_PI`, so every read and write
//! is one raw ethernet frame.

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;

use libc::{EIO, F_GETFL, F_SETFL, IFF_NO_PI, IFF_TAP, IFNAMSIZ, O_NONBLOCK, TUNSETIFF, c_short};
use tokio::io::unix::AsyncFd;

use crate::transport::{FrameRead, FrameWrite};

/// `struct ifreq` with the flags member of its union, padded to the kernel's 40 bytes.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: c_short,
    _pad: [u8; 22],
}

/// A TAP device carrying the guest's frames.
#[derive(Debug)]
pub struct TapDevice {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl TapDevice {
    /// Opens `/dev/net/tun` and attaches it to the TAP interface `name`, creating it if it
    /// does not exist (`""` or a `%d` pattern lets the kernel pick the name).
    ///
    /// Needs `CAP_NET_ADMIN`.
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime with I/O enabled.
    pub fn open(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid interface name {name:?}"),
            ));
        }
        let mut ifr = IfReq {
            name: [0; IFNAMSIZ],
            flags: c_short::try_from(IFF_TAP | IFF_NO_PI)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            _pad: [0; 22],
        };
        ifr.name[..bytes.len()].copy_from_slice(bytes);
        let fd = OwnedFd::from(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")?,
        );
        #[allow(unsafe_code, reason = "TUNSETIFF ioctl")]
        // SAFETY: TUNSETIFF reads and writes the `ifreq` that lives for the duration of the
        // call; `IfReq` matches the kernel's 40-byte layout.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut ifr) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Self::from_fd(fd)
    }

    /// Adopts `fd`, an open TAP device (or any file descriptor that reads and writes one
    /// frame per call), switching it to non-blocking mode.
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime with I/O enabled.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        #[allow(unsafe_code, reason = "fcntl on an owned fd")]
        // SAFETY: F_GETFL and F_SETFL on an fd we own; no pointer arguments.
        let ret = unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), F_GETFL);
            if flags == -1 {
                flags
            } else {
                libc::fcntl(fd.as_raw_fd(), F_SETFL, flags | O_NONBLOCK)
            }
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        #[allow(unsafe_code, reason = "registering a raw fd with the reactor")]
        // SAFETY: `fd` is an open descriptor owned by the `OwnedFd`, which the `AsyncFd`
        // owns until it is dropped; `as_raw_fd` keeps returning that same descriptor.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Splits the device into a frame reader and writer.
    pub fn split(self) -> (TapReader, TapWriter) {
        (
            TapReader {
                fd: Arc::clone(&self.fd),
            },
            TapWriter { fd: self.fd },
        )
    }
}

/// Reads frames from a [`TapDevice`].
#[derive(Debug)]
pub struct TapReader {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl FrameRead for TapReader {
    /// Reads one frame per `read(2)`; a read of zero bytes is the end of the transport.
    async fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        loop {
            let mut guard = self.fd.readable().await?;
            if let Ok(result) = guard.try_io(|fd| read(fd.get_ref(), buf)) {
                return result.map(|len| (len > 0).then_some(len));
            }
        }
    }
}

/// Writes frames to a [`TapDevice`].
#[derive(Debug)]
pub struct TapWriter {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl FrameWrite for TapWriter {
    /// Writes one frame per `write(2)`. While the interface is down the kernel refuses
    /// frames with `EIO`; such a frame is dropped and the transport stays open.
    async fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|fd| write(fd.get_ref(), frame)) {
                Ok(Err(e)) if e.raw_os_error() == Some(EIO) => return Ok(()),
                Ok(result) => return result.map(drop),
                Err(_would_block) => {}
            }
        }
    }
}

/// One `read(2)` into `buf`.
fn read(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    #[allow(unsafe_code, reason = "read(2) on an owned fd")]
    // SAFETY: `buf` is valid for writes of `buf.len()` bytes.
    let ret = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

/// One `write(2)` of `frame`.
fn write(fd: &OwnedFd, frame: &[u8]) -> io::Result<usize> {
    #[allow(unsafe_code, reason = "write(2) on an owned fd")]
    // SAFETY: `frame` is valid for reads of `frame.len()` bytes.
    let ret = unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram;

    use super::*;
    use crate::transport::MAX_FRAME_LEN;

    /// A datagram socket pair reads and writes one message per call, like a TAP device.
    #[tokio::test]
    async fn frames_over_a_datagram_fd() {
        let (ours, theirs) = UnixDatagram::pair().unwrap();
        let (mut reader, mut writer) = TapDevice::from_fd(OwnedFd::from(ours)).unwrap().split();
        theirs.send(b"first frame").unwrap();
        theirs.send(b"second").unwrap();
        let mut buf = vec![0; MAX_FRAME_LEN];
        let len = reader.read_frame(&mut buf).await.unwrap().unwrap();
        assert_eq!(&buf[..len], b"first frame");
        let len = reader.read_frame(&mut buf).await.unwrap().unwrap();
        assert_eq!(&buf[..len], b"second");

        writer.write_frame(b"to the guest").await.unwrap();
        let mut got = [0; 64];
        let len = theirs.recv(&mut got).unwrap();
        assert_eq!(&got[..len], b"to the guest");
    }

    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN"]
    async fn open_tap() {
        let tap = TapDevice::open("nsether%d").unwrap();
        drop(tap.split());
    }

    #[test]
    fn rejects_bad_names() {
        let err = TapDevice::open("an-interface-name-too-long").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
