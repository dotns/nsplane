//! A host bridge: the engine gets its TUN the way mobile platforms hand it over.
//!
//! The "host" creates and configures the TUN device (like `tun_node`: `ip` on Linux) and
//! the engine runs on it in one of two modes:
//!
//! - `--mode fd` (default): the host clears `FD_CLOEXEC` on the TUN fd and re-executes this
//!   binary with `--child-fd <N>` and the same flags; the child adopts the inherited fd
//!   (`nsplane_tun::Tun::from_raw_fd`) and runs the engine and the UAPI. The parent only
//!   waits for the child, forwards Ctrl-C to it and exits with its status. This models
//!   Android `VpnService.establish()` / an iOS packet tunnel handing an fd to the extension.
//! - `--mode channel`: the host keeps the TUN and pumps packets between it and an engine
//!   built on [`ChannelSource`] / [`ChannelSink`] (TUN reads -> the source's `mpsc`
//!   sender; the sink's receiver -> TUN writes), and forwards the TUN's MTU changes through
//!   the source's `watch::Sender`. This models iOS `packetFlow` / Android byte pumps.
//!
//! Echo (`--echo-port`) and `--check`s run on the host's kernel stack, through the tunnel.
//! Linux (and macOS) only; needs root (or `CAP_NET_ADMIN`).
//!
//! APIs shown: `nix::fcntl` (`F_SETFD`, no `unsafe`), `nsplane_tun::Tun::from_raw_fd`,
//! [`ChannelSource::new`], [`ChannelSink::new`], `PacketSource` / `PacketSink` of
//! `nsplane_tun`, and the shared node assembly.
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin fd_bridge -- --mode fd --private-key
//! <KEY> --address 10.0.0.1/24 --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32
//! --echo-port 7`
//!
//! [`ChannelSource`]: nsplane::ChannelSource
//! [`ChannelSource::new`]: nsplane::ChannelSource::new
//! [`ChannelSink`]: nsplane::ChannelSink
//! [`ChannelSink::new`]: nsplane::ChannelSink::new

#[cfg(unix)]
mod unix {
    use std::process::ExitCode;

    use anyhow::{Context as _, bail};
    use clap::{Parser, ValueEnum};
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use nsplane::{ChannelSink, ChannelSource, PacketSink as _, PacketSource as _};
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, TunArgs, build_engine, configure_peers, configure_tun, init_logging,
        serve_uapi,
    };
    use nsplane_examples::status::Status;
    use nsplane_tun::{Tun, TunSink, TunSource};
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use tokio::process::Command;

    /// Packets queued between the host pumps and the engine, per direction.
    const CHANNEL_CAPACITY: usize = 1024;

    /// How the engine gets the TUN.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    pub(crate) enum Mode {
        /// Hand the TUN fd to a child process that adopts it.
        Fd,
        /// Pump packets between the TUN and channel source / sink.
        Channel,
    }

    /// The engine on a TUN handed over by a host: by fd or by packet channels (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "fd_bridge", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        #[command(flatten)]
        tun: TunArgs,

        /// How the engine gets the TUN
        #[arg(long, value_enum, default_value_t = Mode::Fd)]
        mode: Mode,

        /// Internal (fd mode): the inherited TUN fd; set by the parent when it re-executes
        /// itself
        #[arg(long, value_name = "N")]
        child_fd: Option<i32>,
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        if let Some(fd) = args.child_fd {
            return child(&args, fd).await;
        }
        let tun = Tun::create(&args.tun.tun_name)
            .with_context(|| format!("cannot create TUN {}", args.tun.tun_name))?;
        let name = tun.name().unwrap_or_else(|_| args.tun.tun_name.clone());
        configure_tun(&name, &args.tun.address, args.tun.mtu, &args.node.peer)?;
        match args.mode {
            Mode::Fd => parent(tun).await,
            Mode::Channel => channel(&args, tun, &name).await,
        }
    }

    /// Fd mode, host side: hands the TUN fd to a re-executed child and waits for it.
    async fn parent(tun: Tun) -> anyhow::Result<ExitCode> {
        let fd = tun.as_fd();
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).context("cannot clear FD_CLOEXEC")?;
        let exe = std::env::current_exe().context("cannot find the own executable")?;
        let mut child = Command::new(exe)
            .args(std::env::args_os().skip(1))
            .arg("--child-fd")
            .arg(fd.as_raw_fd().to_string())
            .spawn()
            .context("cannot start the child")?;
        let pid = child.id().context("the child has no pid")?;
        tracing::info!(pid, fd = fd.as_raw_fd(), "TUN fd handed to the child");
        let status = tokio::select! {
            status = child.wait() => status?,
            signal = tokio::signal::ctrl_c() => {
                signal.context("cannot watch Ctrl-C")?;
                let pid = Pid::from_raw(i32::try_from(pid)?);
                // The child may have got the terminal's Ctrl-C already and be gone.
                if let Err(e) = kill(pid, Signal::SIGINT) {
                    tracing::debug!(error = %e, "cannot signal the child");
                }
                child.wait().await?
            }
        };
        // The host keeps its copy of the fd until the child is done with the device.
        drop(tun);
        tracing::info!(%status, "child exited");
        Ok(status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(ExitCode::FAILURE, ExitCode::from))
    }

    /// Fd mode, extension side: adopts the inherited fd and runs the engine on it.
    async fn child(args: &Args, fd: i32) -> anyhow::Result<ExitCode> {
        if args.mode != Mode::Fd {
            bail!("--child-fd is only used in fd mode");
        }
        let tun = Tun::from_raw_fd(fd, args.tun.mtu)
            .with_context(|| format!("cannot adopt TUN fd {fd}"))?;
        let name = tun.name().context("the inherited fd is no TUN device")?;
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        let node = build_engine(source, sink, &args.node)?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        let socket = serve_uapi(handle.clone(), &name, node.transports.listen.port())?;
        tracing::info!(interface = %name, fd, listen = %node.transports.listen, uapi = %socket, "engine started on the inherited TUN fd");
        let status = args
            .node
            .status_file
            .clone()
            .map(|path| Status::new(path, handle, node.transports.listen));
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    /// Channel mode: the host pumps packets between the TUN and the engine's channels.
    async fn channel(args: &Args, tun: Tun, name: &str) -> anyhow::Result<ExitCode> {
        let (tun_source, tun_sink) = tun.split().context("cannot open the TUN device")?;
        let mtu = *tun_source.mtu().borrow();
        let (source, to_engine, mtu_sender) = ChannelSource::new(CHANNEL_CAPACITY, mtu);
        let (sink, from_engine) = ChannelSink::new(CHANNEL_CAPACITY);
        tokio::spawn(pump_in(tun_source, to_engine, mtu_sender));
        tokio::spawn(pump_out(from_engine, tun_sink));

        let node = build_engine(source, sink, &args.node)?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;
        let socket = serve_uapi(handle.clone(), name, node.transports.listen.port())?;
        tracing::info!(interface = %name, listen = %node.transports.listen, uapi = %socket, "engine started on packet channels");
        let status = args
            .node
            .status_file
            .clone()
            .map(|path| Status::new(path, handle, node.transports.listen));
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    /// Host -> engine: TUN reads into the source's channel; TUN MTU changes into its watch.
    async fn pump_in(
        mut tun: TunSource,
        to_engine: tokio::sync::mpsc::Sender<nsplane::PacketBuf>,
        mtu_sender: tokio::sync::watch::Sender<u16>,
    ) {
        let mut mtu = tun.mtu();
        // The TUN's MTU watcher ends with the device; then only packets are pumped.
        let mut watching = true;
        loop {
            tokio::select! {
                packet = tun.recv() => match packet {
                    Ok(packet) => {
                        if to_engine.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "TUN read failed, host pump stops");
                        return;
                    }
                },
                changed = mtu.changed(), if watching => {
                    if changed.is_err() {
                        watching = false;
                        continue;
                    }
                    let value = *mtu.borrow_and_update();
                    tracing::info!(mtu = value, "TUN MTU changed, forwarding it to the engine");
                    if mtu_sender.send(value).is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Engine -> host: the sink's channel into TUN writes.
    async fn pump_out(
        mut from_engine: tokio::sync::mpsc::Receiver<(nsplane::PeerId, nsplane::PacketBuf)>,
        tun: TunSink,
    ) {
        while let Some((peer, packet)) = from_engine.recv().await {
            if let Err(e) = tun.send(packet, peer).await {
                tracing::debug!(error = %e, "TUN write failed");
            }
        }
    }
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    use clap::Parser as _;
    unix::main(unix::Args::parse()).await
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<std::process::ExitCode> {
    anyhow::bail!("fd_bridge runs on Linux and macOS only")
}
