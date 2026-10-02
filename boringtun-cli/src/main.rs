// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Development and test daemon for Linux and macOS. Products embed the `boringtun` library.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("boringtun-cli is a Linux/macOS development tool; embed the library instead");

use anyhow::Context as _;
use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::Parser;
use std::process::ExitCode;
use tracing::Level;

/// Userspace WireGuard daemon for development and testing. Runs in the foreground and logs
/// to stderr; Ctrl-C stops it.
#[derive(Debug, Parser)]
#[command(name = "boringtun", version, about)]
struct Args {
    /// The name of the created interface
    #[arg(value_parser = check_tun_name)]
    interface_name: String,

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
    #[arg(long, env = "WG_TUN_FD", default_value_t = -1, allow_negative_numbers = true)]
    tun_fd: i32,

    /// Do not drop sudo privileges
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

/// Key material lives in this process: never write it to a core file, and log panics.
fn harden_process() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    std::panic::set_hook(Box::new(|info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(panic = %info, %backtrace, "panic");
    }));
}

#[allow(clippy::print_stderr, reason = "CLI output boundary")]
fn main() -> ExitCode {
    harden_process();
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = ?e, "BoringTun failed");
            eprintln!("BoringTun failed: {e:#}");
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

fn run(args: &Args) -> anyhow::Result<()> {
    let log_level: Level = args.verbosity.parse().context("Invalid verbosity value")?;
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .init();

    let tun_fd = args.tun_fd.to_string();
    let tun_name = if args.tun_fd >= 0 {
        tun_fd.as_str()
    } else {
        args.interface_name.as_str()
    };

    let mut device_handle =
        DeviceHandle::new(tun_name, device_config(args)).context("Failed to initialize tunnel")?;

    if !args.disable_drop_privileges {
        drop_privileges().context("Failed to drop privileges")?;
    }

    tracing::info!("BoringTun started successfully");
    device_handle.wait();
    Ok(())
}
