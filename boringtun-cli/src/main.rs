// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![forbid(unsafe_code)]

use anyhow::Context as _;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::Parser;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
use tracing::Level;

/// Userspace WireGuard daemon.
#[derive(Debug, Parser)]
#[command(name = "boringtun", version, about)]
#[allow(clippy::struct_excessive_bools, reason = "CLI flags")]
struct Args {
    /// The name of the created interface
    #[arg(value_parser = check_tun_name)]
    interface_name: String,

    /// Run and log in the foreground
    #[cfg(unix)]
    #[arg(short, long)]
    foreground: bool,

    /// Number of OS threads to use
    #[arg(short, long, env = "WG_THREADS", default_value_t = 4)]
    threads: usize,

    /// Log verbosity
    #[arg(
        short,
        long,
        env = "WG_LOG_LEVEL",
        default_value = "error",
        value_parser = ["error", "info", "debug", "trace"],
    )]
    verbosity: String,

    /// File descriptor for the user API
    #[cfg(target_os = "linux")]
    #[arg(long, env = "WG_UAPI_FD", default_value_t = -1, allow_negative_numbers = true)]
    uapi_fd: i32,

    /// File descriptor for an already-existing TUN device
    #[cfg(unix)]
    #[arg(long, env = "WG_TUN_FD", default_value_t = -1, allow_negative_numbers = true)]
    tun_fd: i32,

    /// Log file
    #[cfg(unix)]
    #[arg(short, long, env = "WG_LOG_FILE", default_value = "/tmp/boringtun.out")]
    log: PathBuf,

    /// Do not drop sudo privileges
    #[cfg(unix)]
    #[arg(long, env = "WG_SUDO", value_parser = clap::builder::BoolishValueParser::new())]
    disable_drop_privileges: bool,

    /// Disable connected UDP sockets to each peer
    #[arg(long)]
    disable_connected_udp: bool,

    /// Disable using multiple queues for the tunnel interface
    #[cfg(target_os = "linux")]
    #[arg(long)]
    disable_multi_queue: bool,
}

#[cfg_attr(
    not(target_os = "macos"),
    allow(clippy::unnecessary_wraps, reason = "clap value parser signature")
)]
fn check_tun_name(v: &str) -> Result<String, String> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
    {
        if boringtun::device::tun::parse_utun_name(v).is_ok() {
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

/// Terminal output of the CLI; everything else goes through `tracing`.
#[allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "CLI output boundary"
)]
mod output {
    #[cfg(unix)]
    pub(crate) fn info(msg: &str) {
        println!("{msg}");
    }

    pub(crate) fn error(msg: &str) {
        eprintln!("{msg}");
    }
}

/// Key material lives in this process: never write it to a core file, and log panics.
fn harden_process() {
    #[cfg(unix)]
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    std::panic::set_hook(Box::new(|info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(panic = %info, %backtrace, "panic");
    }));
}

fn main() -> ExitCode {
    harden_process();
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = ?e, "BoringTun failed");
            output::error(&format!("BoringTun failed: {e:#}"));
            ExitCode::FAILURE
        }
    }
}

const fn device_config(args: &Args) -> DeviceConfig {
    DeviceConfig {
        n_threads: args.threads,
        #[cfg(target_os = "linux")]
        uapi_fd: args.uapi_fd,
        use_connected_socket: !args.disable_connected_udp,
        #[cfg(target_os = "linux")]
        use_multi_queue: !args.disable_multi_queue,
    }
}

/// Runs the device in the foreground, logging to the terminal; Ctrl-C stops it.
#[cfg(windows)]
fn run(args: &Args) -> anyhow::Result<()> {
    let log_level: Level = args.verbosity.parse().context("Invalid verbosity value")?;
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(log_level)
        .init();

    let mut device_handle = DeviceHandle::new(&args.interface_name, device_config(args))
        .context("Failed to initialize tunnel")?;
    tracing::info!("BoringTun started successfully");
    device_handle.wait();
    Ok(())
}

#[cfg(unix)]
fn run(args: &Args) -> anyhow::Result<()> {
    use anyhow::bail;
    use boringtun::device::drop_privileges::drop_privileges;
    use daemonize::{Daemonize, Outcome};
    use std::fs::File;
    use std::os::unix::net::UnixDatagram;

    let tun_fd = args.tun_fd.to_string();
    let tun_name = if args.tun_fd >= 0 {
        tun_fd.as_str()
    } else {
        args.interface_name.as_str()
    };
    let log_level: Level = args.verbosity.parse().context("Invalid verbosity value")?;

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().context("socketpair")?;
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if args.foreground {
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    } else {
        let log_file = File::create(&args.log)
            .with_context(|| format!("Could not create log file {}", args.log.display()))?;

        let daemonize = Daemonize::new().working_directory("/tmp");

        match daemonize.execute() {
            Outcome::Parent(Ok(_)) => {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    output::info("BoringTun started successfully");
                    return Ok(());
                }
                bail!("BoringTun failed to start");
            }
            Outcome::Parent(Err(e)) => bail!("BoringTun failed to fork: {e}"),
            Outcome::Child(Ok(_)) => {
                // The log writer thread must be started after the fork: threads do not survive it.
                let (non_blocking, guard) = tracing_appender::non_blocking(log_file);
                _guard = guard;
                tracing_subscriber::fmt()
                    .with_max_level(log_level)
                    .with_writer(non_blocking)
                    .with_ansi(false)
                    .init();
            }
            Outcome::Child(Err(e)) => bail!("BoringTun failed to daemonize: {e}"),
        }
    }

    let mut device_handle = match DeviceHandle::new(tun_name, device_config(args)) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            let _ = sock1.send(&[0]);
            return Err(e).context("Failed to initialize tunnel");
        }
    };

    if !args.disable_drop_privileges
        && let Err(e) = drop_privileges()
    {
        let _ = sock1.send(&[0]);
        return Err(e).context("Failed to drop privileges");
    }

    // Notify parent that tunnel initialization succeeded
    let _ = sock1.send(&[1]);
    drop(sock1);

    tracing::info!("BoringTun started successfully");

    device_handle.wait();
    Ok(())
}
