// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Development and test daemon for Linux and macOS. Products embed the nsplane library.

#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("nsplane-cli is a Linux/macOS development tool; embed the library instead");

use anyhow::Context as _;
use clap::Parser;
use nix::unistd::{Gid, Uid, getgid, getuid, setgid, setuid};
use nsplane::EngineBuilder;
use nsplane_tun::Tun;
use nsplane_uapi::{Uapi, UapiListener};
use std::process::ExitCode;
use tokio::signal::unix::{SignalKind, signal};
use tracing::Level;

/// Userspace WireGuard daemon for development and testing. Runs in the foreground and logs
/// to stderr; SIGINT (Ctrl-C) or SIGTERM stops it.
#[derive(Debug, Parser)]
#[command(name = "nsplane-cli", version, about)]
struct Args {
    /// The name of the created interface
    #[arg(value_parser = check_tun_name)]
    interface_name: String,

    /// Number of runtime worker threads
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

    /// Do not drop sudo privileges
    #[arg(long, env = "WG_SUDO", value_parser = clap::builder::BoolishValueParser::new())]
    disable_drop_privileges: bool,
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

#[allow(clippy::print_stderr, reason = "CLI output boundary")]
fn main() -> ExitCode {
    harden_process();
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = ?e, "nsplane-cli failed");
            eprintln!("nsplane-cli failed: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> anyhow::Result<()> {
    let log_level: Level = args.verbosity.parse().context("Invalid verbosity value")?;
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(std::io::stderr)
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.threads)
        .enable_all()
        .build()
        .context("Failed to start the runtime")?;
    runtime.block_on(serve(args))
}

/// Brings the interface up and runs it until SIGINT or SIGTERM.
async fn serve(args: &Args) -> anyhow::Result<()> {
    let tun = Tun::create(&args.interface_name).context("Failed to initialize tunnel")?;
    let name = tun.name().context("Failed to read the tunnel name")?;
    let (source, sink) = tun.split().context("Failed to initialize tunnel")?;

    let engine = EngineBuilder::new(source, sink).build();
    let handle = engine.handle();
    let uapi = Uapi::new(engine.handle());
    uapi.bind_transport(0)
        .await
        .context("Failed to bind the UDP socket")?;
    let listener = UapiListener::bind(&name).context("Failed to bind the UAPI socket")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("Failed to watch SIGINT")?;
    let mut terminate = signal(SignalKind::terminate()).context("Failed to watch SIGTERM")?;
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
fn drop_privileges() -> anyhow::Result<()> {
    let id = |name| std::env::var(name).ok()?.parse::<u32>().ok();
    let (uid, gid) = match (id("SUDO_UID"), id("SUDO_GID")) {
        (Some(uid), Some(gid)) => (Uid::from_raw(uid), Gid::from_raw(gid)),
        _ => (getuid(), getgid()),
    };

    // Group first: once the user ID is dropped, changing the group is no longer allowed.
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;

    // Validate that root cannot be regained.
    if setgid(Gid::from_raw(0)).is_ok() || setuid(Uid::from_raw(0)).is_ok() {
        anyhow::bail!("Failed to permanently drop privileges");
    }
    Ok(())
}
