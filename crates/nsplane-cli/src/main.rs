// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Development and test daemon for Linux and macOS. Products embed the nsplane library.

#![deny(unsafe_code)]

#[cfg(not(unix))]
compile_error!("nsplane-cli is a Linux/macOS development tool; embed the library instead");

use anyhow::{Context as _, bail};
use clap::Parser;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
#[cfg(not(target_vendor = "apple"))]
use nix::unistd::setgroups;
use nix::unistd::{Gid, Uid, geteuid, getgid, getuid, setgid, setuid};
use nsplane::{EngineBuilder, UdpTransport};
use nsplane_tun::{Tun, TunOptions};
use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};
use std::net::Ipv6Addr;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use tokio::signal::unix::{SignalKind, signal};
use tracing::Level;

/// Userspace WireGuard daemon for development and testing. Runs in the foreground and logs
/// to stderr; SIGINT (Ctrl-C) or SIGTERM stops it.
#[derive(Debug, Parser)]
#[command(name = "nsplane-cli", version, about)]
struct Args {
    /// The name of the created interface. With --tun-fd it names the UAPI socket when the
    /// adopted device's name cannot be queried
    #[arg(value_parser = check_tun_name)]
    interface_name: String,

    /// Adopt this already-open TUN device fd (3 or higher) instead of creating the
    /// interface. The daemon takes ownership of the fd and closes it on exit
    #[arg(long, env = "WG_TUN_FD")]
    tun_fd: Option<i32>,

    /// Also serve the UAPI on this already-connected Unix stream socket fd (3 or higher,
    /// not the --tun-fd one), next to the standard socket; the daemon keeps running when
    /// that connection ends. The daemon takes ownership of the fd and closes it on exit
    #[arg(long, env = "WG_UAPI_FD")]
    uapi_fd: Option<i32>,

    /// Number of runtime worker threads
    #[arg(short, long, env = "WG_THREADS", default_value = "4")]
    threads: NonZeroUsize,

    /// Log verbosity
    #[arg(
        short,
        long,
        env = "WG_LOG_LEVEL",
        default_value = "error",
        value_parser = ["error", "info", "debug", "trace"],
    )]
    verbosity: String,

    /// Do not drop sudo privileges
    #[arg(long, env = "WG_SUDO", value_parser = clap::builder::BoolishValueParser::new())]
    disable_drop_privileges: bool,

    /// Number of crypto worker tasks; 0 or 1 encrypts and decrypts on the engine task
    #[arg(long, env = "WG_CRYPTO_WORKERS", default_value_t = 0)]
    crypto_workers: usize,

    /// Disable segmentation offload on the created TUN device and the UDP socket. With
    /// --tun-fd only the UDP socket is affected; a `listen-port` or `fwmark` set over the
    /// UAPI binds its new socket without offload too
    #[arg(long, env = "WG_NO_OFFLOAD", value_parser = clap::builder::BoolishValueParser::new())]
    no_offload: bool,
}

#[cfg_attr(
    not(target_os = "macos"),
    allow(clippy::unnecessary_wraps, reason = "clap value parser signature")
)]
fn check_tun_name(v: &str) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        if is_utun_name(v) {
            Ok(v.to_owned())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(v.to_owned())
    }
}

/// Whether `name` is `utun` (kernel-assigned unit) or `utunN` with a unit the kernel can
/// address (`N + 1` fits in a `u32`).
#[cfg(target_os = "macos")]
fn is_utun_name(name: &str) -> bool {
    match name.strip_prefix("utun") {
        Some("") => true,
        Some(idx) => idx
            .parse::<u32>()
            .ok()
            .and_then(|x| x.checked_add(1))
            .is_some(),
        None => false,
    }
}

/// Key material lives in this process: never write it to a core file, and log panics.
fn harden_process() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    std::panic::set_hook(Box::new(|info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(panic = %info, %backtrace, "panic");
    }));
}

/// The descriptors the invoker handed over by number (`--tun-fd`, `--uapi-fd`).
#[derive(Debug)]
struct Inherited {
    tun: Option<OwnedFd>,
    uapi: Option<OwnedFd>,
}

impl Inherited {
    /// Takes ownership of the descriptors numbered `tun_fd` and `uapi_fd`.
    ///
    /// `main` calls this once, before the logger, the runtime or anything else opens a
    /// descriptor: a number the invoker passed can then only name a descriptor the process
    /// inherited, never one it opened itself. Nothing is adopted when the two numbers are
    /// the same.
    fn adopt(tun_fd: Option<i32>, uapi_fd: Option<i32>) -> anyhow::Result<Self> {
        if let (Some(tun), Some(uapi)) = (tun_fd, uapi_fd)
            && tun == uapi
        {
            bail!("--tun-fd and --uapi-fd are the same descriptor {tun}");
        }
        let take = |flag: &str, fd: Option<i32>| {
            fd.map(|fd| adopt_fd(fd).with_context(|| format!("Invalid {flag} {fd}")))
                .transpose()
        };
        Ok(Self {
            tun: take("--tun-fd", tun_fd)?,
            uapi: take("--uapi-fd", uapi_fd)?,
        })
    }
}

/// Takes ownership of the inherited descriptor numbered `fd` and marks it close-on-exec.
///
/// Only [`Inherited::adopt`] calls this, once per number. The standard streams (and
/// negative numbers) are refused; a number that is not an open descriptor fails without
/// closing anything.
fn adopt_fd(fd: i32) -> anyhow::Result<OwnedFd> {
    if fd < 3 {
        bail!("not an inheritable descriptor: standard streams and negative numbers are refused");
    }
    // SAFETY: the invoker hands the open descriptor `fd` to this process by passing its
    // number, and nothing in the process has used it: the standard library only touches
    // 0, 1 and 2 before `main`, `fd` is none of those, and `Inherited::adopt` runs before
    // the process opens any descriptor and never takes the same number twice. The
    // `OwnedFd` is therefore the sole owner. A number the invoker left closed is caught
    // below and released without `close`.
    #[allow(unsafe_code, reason = "adopting a descriptor passed by number")]
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let flags = match fcntl(&owned, FcntlArg::F_GETFD) {
        Ok(flags) => FdFlag::from_bits_retain(flags),
        Err(e) => {
            // Not ours to close: give the number back.
            let _ = owned.into_raw_fd();
            return Err(e).context("not an open descriptor");
        }
    };
    fcntl(&owned, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))
        .context("cannot set FD_CLOEXEC")?;
    Ok(owned)
}

#[allow(clippy::print_stderr, reason = "CLI output boundary")]
fn main() -> ExitCode {
    harden_process();
    let args = Args::parse();
    // First thing after parsing, see `Inherited::adopt`.
    let result =
        Inherited::adopt(args.tun_fd, args.uapi_fd).and_then(|inherited| run(&args, inherited));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = ?e, "nsplane-cli failed");
            eprintln!("nsplane-cli failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args, inherited: Inherited) -> anyhow::Result<()> {
    let log_level: Level = args.verbosity.parse().context("Invalid verbosity value")?;
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads.get())
        .enable_all()
        .build()
        .context("Failed to start the runtime")?;
    runtime.block_on(serve(args, inherited))
}

/// The MTU an adopted TUN fd starts with; a real TUN device's MTU replaces it at once.
const ADOPTED_TUN_MTU: u16 = 1420;

/// Registers the connected Unix stream socket `fd` (`--uapi-fd`) with the tokio reactor.
fn adopt_uapi_stream(fd: OwnedFd) -> anyhow::Result<tokio::net::UnixStream> {
    let stream = UnixStream::from(fd);
    // Fails for anything that is not a Unix socket.
    stream.local_addr()?;
    stream.set_nonblocking(true)?;
    Ok(tokio::net::UnixStream::from_std(stream)?)
}

/// Creates or adopts the TUN device and serves packets and UAPI until SIGINT or SIGTERM.
/// Interface addresses, routes and administrative up state are configured externally.
async fn serve(args: &Args, inherited: Inherited) -> anyhow::Result<()> {
    let uapi_stream = inherited
        .uapi
        .map(|fd| {
            let number = fd.as_raw_fd();
            adopt_uapi_stream(fd).with_context(|| format!("Invalid --uapi-fd {number}"))
        })
        .transpose()?;
    let tun = match inherited.tun {
        Some(fd) => {
            let number = fd.as_raw_fd();
            Tun::from_fd(fd, ADOPTED_TUN_MTU)
                .with_context(|| format!("Invalid --tun-fd {number}"))?
        }
        None => Tun::create_with(
            &args.interface_name,
            TunOptions::new().offload(!args.no_offload),
        )
        .context("Failed to initialize tunnel")?,
    };
    let name = tun.name().unwrap_or_else(|e| {
        tracing::debug!(error = ?e, "Cannot read the tunnel name, using the given one");
        args.interface_name.clone()
    });
    let tun_offload = tun.offload();
    let (source, sink) = tun.split().context("Failed to initialize tunnel")?;

    let transport = UdpTransport::bind_with_offload(
        TRANSPORT_ID,
        (Ipv6Addr::UNSPECIFIED, 0).into(),
        !args.no_offload,
    )
    .context("Failed to bind the UDP socket")?;
    let port = transport.local_addr().port();
    tracing::info!(
        tun_offload = ?tun_offload,
        udp_offload = transport.offload(),
        crypto_workers = args.crypto_workers,
        "Data path configured"
    );
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .crypto_workers(args.crypto_workers)
        .build()
        .context("Failed to start the engine")?;
    let handle = engine.handle();
    let uapi = Uapi::with_listen_port(engine.handle(), port).offload(!args.no_offload);
    let listener = UapiListener::bind(&name).context("Failed to bind the UAPI socket")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("Failed to watch SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("Failed to watch SIGTERM")?;
    if let Some(stream) = uapi_stream {
        let uapi = uapi.clone();
        tokio::spawn(async move {
            uapi.serve_stream(stream).await;
            tracing::info!("UAPI connection of --uapi-fd closed");
        });
    }
    let mut uapi_task = tokio::spawn(async move { uapi.serve(listener).await });

    if !args.disable_drop_privileges {
        drop_privileges().context("Failed to drop privileges")?;
    }

    tracing::info!(interface = %name, "nsplane-cli started successfully");
    let wait = engine.wait();
    tokio::pin!(wait);
    let served = tokio::select! {
        _ = interrupt.recv() => { tracing::info!("SIGINT received, shutting down"); false }
        _ = terminate.recv() => { tracing::info!("SIGTERM received, shutting down"); false }
        served = &mut uapi_task => {
            served.context("UAPI server failed")?.context("UAPI server failed")?;
            true
        }
        stopped = &mut wait => return stopped.context("Engine failed"),
    };
    // Already stopped if the UAPI server returned on its own.
    let _ = handle.shutdown().await;
    wait.await.context("Engine failed")?;
    // The server returns once the engine stops, removing the socket file.
    if !served {
        uapi_task.await.context("UAPI server failed")??;
    }
    Ok(())
}

/// Permanently switches to the user that invoked `sudo`, read from `SUDO_UID` / `SUDO_GID`.
///
/// Without `sudo` (either variable unset or invalid) the process switches to its real user
/// and group IDs. For a plain root process those are 0, so regaining root still succeeds and
/// this fails, as it did when the login name resolved to root: run as root without `sudo`,
/// pass `--disable-drop-privileges`.
///
/// A root process also replaces its supplementary GIDs with the target GID, so those of root
/// do not outlive the switch.
fn drop_privileges() -> anyhow::Result<()> {
    let id = |name| std::env::var(name).ok()?.parse::<u32>().ok();
    let (uid, gid) = match (id("SUDO_UID"), id("SUDO_GID")) {
        (Some(uid), Some(gid)) => (Uid::from_raw(uid), Gid::from_raw(gid)),
        _ => (getuid(), getgid()),
    };

    // Supplementary groups before the IDs: only root may change them, and neither setgid
    // nor setuid drops them.
    if geteuid().is_root() {
        #[cfg(not(target_vendor = "apple"))]
        setgroups(&[gid]).context("setgroups")?;
        // `nix` has no `setgroups` on Apple targets.
        #[cfg(target_vendor = "apple")]
        nsplane_sys::set_supplementary_groups(&[gid.as_raw()]).context("setgroups")?;
    }
    // Group first: once the user ID is dropped, changing the group is no longer allowed.
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;

    // Validate that root cannot be regained.
    if setgid(Gid::from_raw(0)).is_ok() || setuid(Uid::from_raw(0)).is_ok() {
        anyhow::bail!("Failed to permanently drop privileges");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn zero_threads_is_rejected() {
        let parse = |threads| Args::try_parse_from(["nsplane-cli", "utun7", "--threads", threads]);
        // The runtime cannot be built without a worker thread.
        assert!(parse("0").is_err());
        assert!(parse("1").is_ok());
        // Zero crypto workers is valid: the engine task does the work itself.
        assert!(Args::try_parse_from(["nsplane-cli", "utun7", "--crypto-workers", "0"]).is_ok());
    }

    /// The close-on-exec flag of `fd`.
    fn cloexec(fd: &OwnedFd) -> bool {
        FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD).unwrap()).contains(FdFlag::FD_CLOEXEC)
    }

    #[test]
    fn adopts_an_open_descriptor_and_sets_cloexec() {
        let (a, mut b) = UnixStream::pair().unwrap();
        // As an invoker hands it over: inheritable.
        fcntl(&a, FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
        let number = a.into_raw_fd();

        let inherited = Inherited::adopt(None, Some(number)).unwrap();
        assert!(inherited.tun.is_none());
        let fd = inherited.uapi.unwrap();
        assert_eq!(fd.as_raw_fd(), number);
        assert!(cloexec(&fd));

        // Still the same open socket.
        UnixStream::from(fd).write_all(b"adopted").unwrap();
        let mut buf = [0u8; 7];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"adopted");
    }

    #[test]
    fn adopts_both_descriptors() {
        let (a, b) = UnixStream::pair().unwrap();
        let (tun, uapi) = (a.into_raw_fd(), b.into_raw_fd());
        let inherited = Inherited::adopt(Some(tun), Some(uapi)).unwrap();
        assert_eq!(inherited.tun.unwrap().as_raw_fd(), tun);
        assert_eq!(inherited.uapi.unwrap().as_raw_fd(), uapi);
    }

    #[test]
    fn refuses_standard_streams_and_negative_numbers() {
        for fd in [i32::MIN, -1, 0, 1, 2] {
            let err = adopt_fd(fd).unwrap_err();
            assert!(
                format!("{err:#}").contains("standard streams"),
                "{fd}: {err:#}"
            );
            let err = Inherited::adopt(Some(fd), None).unwrap_err();
            assert!(format!("{err:#}").contains(&format!("Invalid --tun-fd {fd}")));
            let err = Inherited::adopt(None, Some(fd)).unwrap_err();
            assert!(format!("{err:#}").contains(&format!("Invalid --uapi-fd {fd}")));
        }
        // Refused, not closed.
        assert!(fcntl(std::io::stderr(), FcntlArg::F_GETFD).is_ok());
    }

    #[test]
    fn refuses_a_closed_number() {
        // Far above any descriptor limit, so never open.
        let err = adopt_fd(i32::MAX).unwrap_err();
        assert!(
            format!("{err:#}").contains("not an open descriptor"),
            "{err:#}"
        );
    }

    #[test]
    fn refuses_the_same_number_twice() {
        let (a, _b) = UnixStream::pair().unwrap();
        let number = a.as_raw_fd();
        let err = Inherited::adopt(Some(number), Some(number)).unwrap_err();
        assert!(format!("{err:#}").contains("same descriptor"), "{err:#}");
        // Nothing was adopted: `a` still owns its open descriptor.
        assert!(a.local_addr().is_ok());
    }

    #[test]
    fn fd_options_parse_from_flags() {
        let args = Args::try_parse_from(["nsplane-cli", "--tun-fd", "5", "--uapi-fd", "6", "utun"])
            .unwrap();
        assert_eq!((args.tun_fd, args.uapi_fd), (Some(5), Some(6)));
        assert!(Args::try_parse_from(["nsplane-cli", "--tun-fd", "x", "utun"]).is_err());
    }
}
