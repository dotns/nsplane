//! Linux TAP devices: a transport and persistent interfaces.
//!
//! [`TapDevice`] is the TAP transport, `/dev/net/tun` with `IFF_TAP | IFF_NO_PI`, so every
//! read and write is one raw ethernet frame. [`ensure_tap`] makes a persistent TAP
//! interface that another process attaches to.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use libc::{
    AF_INET, AF_NETLINK, EBUSY, EIO, F_GETFL, F_SETFL, IFF_NO_PI, IFF_NOARP, IFF_TAP, IFF_UP,
    IFF_VNET_HDR, IFNAMSIZ, NETLINK_ROUTE, O_NONBLOCK, RTM_DELLINK, SIOCGIFFLAGS, SIOCSIFFLAGS,
    SOCK_CLOEXEC, SOCK_DGRAM, SOCK_RAW, TUNSETGROUP, TUNSETIFF, TUNSETOWNER, TUNSETPERSIST, c_int,
    c_short, c_ulong,
};
use tokio::io::unix::AsyncFd;

use crate::transport::{FrameRead, FrameWrite};

/// `struct ifreq` with the flags member of its union, padded to the kernel's 40 bytes.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: c_short,
    _pad: [u8; 22],
}

impl IfReq {
    /// An `ifreq` for the interface `name` (already validated) with the 16 flag bits
    /// `flags`.
    fn new(name: &str, flags: c_int) -> io::Result<Self> {
        let bits =
            u16::try_from(flags).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut ifr = Self {
            name: [0; IFNAMSIZ],
            flags: c_short::from_ne_bytes(bits.to_ne_bytes()),
            _pad: [0; 22],
        };
        ifr.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(ifr)
    }
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
            return Err(invalid_name(name));
        }
        Self::from_fd(tun_attach(name, IFF_TAP | IFF_NO_PI)?)
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

/// `IFF_TUN_EXCL` from `<linux/if_tun.h>`: `TUNSETIFF` fails with `EBUSY` instead of
/// attaching when the interface already exists.
const IFF_TUN_EXCL: c_int = 0x8000;

/// A persistent TAP interface for [`ensure_tap`]: its name and the user and group allowed
/// to attach to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapConfig {
    name: String,
    owner: Option<u32>,
    group: Option<u32>,
}

impl TapConfig {
    /// A TAP interface named `name`, attachable only with `CAP_NET_ADMIN`.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: None,
            group: None,
        }
    }

    /// Lets the user `uid` attach to the interface (`TUNSETOWNER`).
    #[must_use]
    pub const fn owner(mut self, uid: u32) -> Self {
        self.owner = Some(uid);
        self
    }

    /// Lets members of the group `gid` attach to the interface (`TUNSETGROUP`).
    #[must_use]
    pub const fn group(mut self, gid: u32) -> Self {
        self.group = Some(gid);
        self
    }

    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Makes sure the interface of `config` exists, creating it as a persistent TAP device if
/// it does not.
///
/// An existing interface is used as it is: nothing about it changes and it stays in place
/// when the returned [`TapInterface`] is dropped. A missing one is created with
/// `IFF_TAP | IFF_NO_PI | IFF_VNET_HDR`, the configured owner and group, and the persist
/// flag, so that another process (a virtual machine monitor) can attach to it while no
/// file descriptor of ours stays open. Before it is brought up, IPv6 address
/// autoconfiguration and IPv6 are turned off on it (`net.ipv6.conf.<name>.autoconf` and
/// `disable_ipv6`) and ARP with `IFF_NOARP`, so the host kernel neither answers the guest
/// nor sends frames of its own to it. Dropping the [`TapInterface`] deletes a created
/// interface.
///
/// Needs `CAP_NET_ADMIN` to create the interface; using an existing one needs nothing. A
/// read-only `/proc/sys` is accepted when the IPv6 settings already have the wanted values
/// (for example inherited from `net.ipv6.conf.default`); a kernel without IPv6 skips them.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for a name that is empty, longer than 15 bytes, or
/// contains NUL, `/`, `%`, `:` or whitespace; otherwise the error of the failing system
/// call, after a partly set up interface has been deleted again.
pub fn ensure_tap(config: &TapConfig) -> io::Result<TapInterface> {
    let name = config.name.as_str();
    match if_index(name) {
        Ok(index) => {
            return Ok(TapInterface {
                name: name.to_owned(),
                index,
                created: false,
            });
        }
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Err(e),
        Err(_) => {}
    }
    let fd = match tun_attach(name, IFF_TAP | IFF_NO_PI | IFF_VNET_HDR | IFF_TUN_EXCL) {
        Ok(fd) => fd,
        // Created by someone else since the lookup above.
        Err(e) if e.raw_os_error() == Some(EBUSY) => {
            return Ok(TapInterface {
                name: name.to_owned(),
                index: if_index(name)?,
                created: false,
            });
        }
        Err(e) => return Err(e),
    };
    let tap = TapInterface {
        name: name.to_owned(),
        index: if_index(name)?,
        created: true,
    };
    if let Some(uid) = config.owner {
        tun_ioctl(&fd, TUNSETOWNER, uid.into())?;
    }
    if let Some(gid) = config.group {
        tun_ioctl(&fd, TUNSETGROUP, gid.into())?;
    }
    tun_ioctl(&fd, TUNSETPERSIST, 1)?;
    drop(fd);
    ipv6_conf(name, "autoconf", "0")?;
    ipv6_conf(name, "disable_ipv6", "1")?;
    set_up_noarp(name)?;
    Ok(tap)
}

/// An interface from [`ensure_tap`]; deletes it on drop if [`ensure_tap`] created it.
#[derive(Debug)]
pub struct TapInterface {
    name: String,
    index: u32,
    created: bool,
}

impl TapInterface {
    /// The interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The interface index.
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Whether [`ensure_tap`] created the interface, and so deletes it on drop.
    pub const fn created(&self) -> bool {
        self.created
    }
}

impl Drop for TapInterface {
    /// Deletes a created interface over rtnetlink (`RTM_DELLINK` by index), which works
    /// while another process is still attached; a failure is logged.
    fn drop(&mut self) {
        if self.created
            && let Err(err) = delete_link(self.index)
        {
            tracing::warn!("deleting TAP interface {} failed: {err}", self.name);
        }
    }
}

/// The index of the interface `name`; [`io::ErrorKind::InvalidInput`] for a name the kernel
/// would not accept (see [`ensure_tap`]).
pub(crate) fn if_index(name: &str) -> io::Result<u32> {
    let valid = !name.is_empty()
        && name.len() < IFNAMSIZ
        && name != "."
        && name != ".."
        && !name
            .bytes()
            .any(|b| b == 0 || b == b'/' || b == b'%' || b == b':' || b.is_ascii_whitespace());
    if !valid {
        return Err(invalid_name(name));
    }
    let cname = CString::new(name).map_err(|_| invalid_name(name))?;
    #[allow(unsafe_code, reason = "if_nametoindex")]
    // SAFETY: `cname` is a NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

fn invalid_name(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid interface name {name:?}"),
    )
}

/// Opens `/dev/net/tun` and attaches it to the interface `name` with `flags`
/// (`TUNSETIFF`).
fn tun_attach(name: &str, flags: c_int) -> io::Result<OwnedFd> {
    let mut ifr = IfReq::new(name, flags)?;
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
    Ok(fd)
}

/// A TUN `ioctl` that takes its argument by value.
fn tun_ioctl(fd: &OwnedFd, request: libc::Ioctl, arg: c_ulong) -> io::Result<()> {
    #[allow(unsafe_code, reason = "TUN ioctl with an integer argument")]
    // SAFETY: TUNSETOWNER, TUNSETGROUP and TUNSETPERSIST read their argument as an integer
    // value, not as a pointer.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Writes `value` to `net.ipv6.conf.<name>.<key>`; succeeds without writing when IPv6 is
/// not built into the kernel or the setting already has the value.
fn ipv6_conf(name: &str, key: &str, value: &str) -> io::Result<()> {
    let path = format!("/proc/sys/net/ipv6/conf/{name}/{key}");
    match fs::write(&path, value) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) if fs::read_to_string(&path).is_ok_and(|v| v.trim() == value) => Ok(()),
        Err(e) => Err(io::Error::new(e.kind(), format!("writing {path}: {e}"))),
    }
}

/// `request` as the `ioctl` request type of the C library (`c_ulong` on glibc, `c_int` on
/// musl). Socket ioctl numbers fit in 16 bits, so the conversion is lossless.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::unnecessary_cast,
    reason = "the request type depends on the C library; the value fits either"
)]
const fn request(request: c_ulong) -> libc::Ioctl {
    request as libc::Ioctl
}

/// Sets `IFF_UP` and `IFF_NOARP` on the interface `name`.
fn set_up_noarp(name: &str) -> io::Result<()> {
    let sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)?;
    let mut ifr = IfReq::new(name, 0)?;
    #[allow(unsafe_code, reason = "SIOCGIFFLAGS ioctl")]
    // SAFETY: SIOCGIFFLAGS writes the flags into the `ifreq` that lives for the duration of
    // the call; `IfReq` matches the kernel's 40-byte layout.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), request(SIOCGIFFLAGS), &raw mut ifr) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    ifr.flags |= c_short::try_from(IFF_UP | IFF_NOARP).unwrap_or_default();
    #[allow(unsafe_code, reason = "SIOCSIFFLAGS ioctl")]
    // SAFETY: SIOCSIFFLAGS reads the `ifreq` that lives for the duration of the call.
    let ret = unsafe { libc::ioctl(sock.as_raw_fd(), request(SIOCSIFFLAGS), &raw mut ifr) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Deletes the interface with index `index` (`RTM_DELLINK`) and waits for the kernel's
/// acknowledgement.
fn delete_link(index: u32) -> io::Result<()> {
    let sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)?;
    // struct nlmsghdr (16 bytes) followed by struct ifinfomsg (16 bytes), host byte order.
    let mut msg = [0u8; 32];
    msg[0..4].copy_from_slice(&32u32.to_ne_bytes());
    msg[4..6].copy_from_slice(&RTM_DELLINK.to_ne_bytes());
    // NLM_F_REQUEST | NLM_F_ACK
    msg[6..8].copy_from_slice(&5u16.to_ne_bytes());
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes());
    msg[20..24].copy_from_slice(&index.to_ne_bytes());
    #[allow(unsafe_code, reason = "send(2) on an owned socket")]
    // SAFETY: `msg` is valid for reads of its length; an unconnected netlink socket sends
    // to the kernel.
    let ret = unsafe { libc::send(sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut reply = [0u8; 256];
    #[allow(unsafe_code, reason = "recv(2) on an owned socket")]
    // SAFETY: `reply` is valid for writes of its length.
    let ret = unsafe { libc::recv(sock.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
    let len = usize::try_from(ret).map_err(|_| io::Error::last_os_error())?;
    // An NLMSG_ERROR message: the header, then the negated errno (0 acknowledges).
    let kind = reply.get(4..6).map(|b| u16::from_ne_bytes([b[0], b[1]]));
    let errno = reply
        .get(16..20.min(len))
        .and_then(|b| b.try_into().ok())
        .map(i32::from_ne_bytes);
    match (kind, errno) {
        (Some(2), Some(0)) => Ok(()),
        (Some(2), Some(errno)) => Err(io::Error::from_raw_os_error(-errno)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected rtnetlink reply",
        )),
    }
}

/// `socket(2)` as an owned descriptor.
pub(crate) fn socket(domain: c_int, kind: c_int, protocol: c_int) -> io::Result<OwnedFd> {
    #[allow(unsafe_code, reason = "socket(2)")]
    // SAFETY: no pointer arguments.
    let fd = unsafe { libc::socket(domain, kind, protocol) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    #[allow(unsafe_code, reason = "taking ownership of a new descriptor")]
    // SAFETY: `fd` is a descriptor just returned by socket(2) and owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
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
pub(crate) mod tests {
    use std::os::unix::net::UnixDatagram;
    use std::path::Path;

    use super::*;
    use crate::transport::MAX_FRAME_LEN;

    /// Whether the test may create interfaces and open packet sockets: `CAP_NET_ADMIN` and
    /// `CAP_NET_RAW` in the effective set and `/dev/net/tun` present. Tests that need them
    /// return early otherwise.
    pub(crate) fn net_caps() -> bool {
        const CAP_NET_ADMIN: u32 = 12;
        const CAP_NET_RAW: u32 = 13;
        let caps = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                let hex = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
                u64::from_str_radix(hex.trim(), 16).ok()
            })
            .unwrap_or(0);
        let needed = (1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW);
        let ok = caps & needed == needed && Path::new("/dev/net/tun").exists();
        if !ok {
            eprintln!("skipped: needs CAP_NET_ADMIN, CAP_NET_RAW and /dev/net/tun");
        }
        ok
    }

    /// Opens the existing TAP `name` the way a virtual machine monitor does, with a
    /// virtio-net header in front of every frame.
    pub(crate) fn attach_vnet(name: &str) -> OwnedFd {
        tun_attach(name, IFF_TAP | IFF_NO_PI | IFF_VNET_HDR).unwrap()
    }

    fn sys(name: &str, file: &str) -> String {
        fs::read_to_string(format!("/sys/class/net/{name}/{file}"))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn exists(name: &str) -> bool {
        Path::new("/sys/class/net").join(name).exists()
    }

    #[test]
    fn ensure_tap_creates_and_deletes() {
        if !net_caps() {
            return;
        }
        let name = "nsafp-create";
        let tap = ensure_tap(&TapConfig::new(name).owner(1234).group(4321)).unwrap();
        assert!(tap.created());
        assert_eq!(tap.name(), name);
        assert_eq!(tap.index(), if_index(name).unwrap());
        assert_eq!(sys(name, "owner"), "1234");
        assert_eq!(sys(name, "group"), "4321");
        let tun_flags =
            u32::from_str_radix(sys(name, "tun_flags").trim_start_matches("0x"), 16).unwrap();
        let wanted = u32::try_from(IFF_TAP | IFF_NO_PI | IFF_VNET_HDR).unwrap();
        assert_eq!(tun_flags & wanted, wanted);
        let flags = u32::from_str_radix(sys(name, "flags").trim_start_matches("0x"), 16).unwrap();
        let wanted = u32::try_from(IFF_UP | IFF_NOARP).unwrap();
        assert_eq!(flags & wanted, wanted);
        let conf = format!("/proc/sys/net/ipv6/conf/{name}");
        if Path::new(&conf).exists() {
            assert_eq!(
                fs::read_to_string(format!("{conf}/disable_ipv6"))
                    .unwrap()
                    .trim(),
                "1"
            );
            assert_eq!(
                fs::read_to_string(format!("{conf}/autoconf"))
                    .unwrap()
                    .trim(),
                "0"
            );
        }
        drop(tap);
        assert!(!exists(name));
    }

    /// The interface is deleted on drop even while another process still holds it open.
    #[test]
    fn ensure_tap_deletes_while_attached() {
        if !net_caps() {
            return;
        }
        let name = "nsafp-held";
        let tap = ensure_tap(&TapConfig::new(name)).unwrap();
        let held = attach_vnet(name);
        drop(tap);
        assert!(!exists(name));
        drop(held);
    }

    #[test]
    fn ensure_tap_leaves_an_existing_interface() {
        if !net_caps() {
            return;
        }
        let name = "nsafp-exists";
        let first = ensure_tap(&TapConfig::new(name)).unwrap();
        let second = ensure_tap(&TapConfig::new(name).owner(1)).unwrap();
        assert!(!second.created());
        assert_eq!(second.index(), first.index());
        drop(second);
        assert!(exists(name));
        assert_eq!(sys(name, "owner"), "-1");
        drop(first);
        assert!(!exists(name));
    }

    /// The loopback interface exists everywhere: it is used as it is, no capability needed.
    #[test]
    fn ensure_tap_uses_loopback_as_is() {
        let lo = ensure_tap(&TapConfig::new("lo")).unwrap();
        assert!(!lo.created());
        assert_eq!(lo.name(), "lo");
        drop(lo);
        assert!(exists("lo"));
    }

    #[test]
    fn ensure_tap_rejects_bad_names() {
        for name in ["", "an-interface-name", "a/b", "..", "tap%d", "a b", "a:1"] {
            let err = ensure_tap(&TapConfig::new(name)).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
    }

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
