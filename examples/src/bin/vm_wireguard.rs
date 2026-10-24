//! A virtual machine reaching WireGuard peers: the engine's local side is the guest's
//! virtio-net link instead of a TUN device.
//!
//! Listens on `--socket` and serves the first connection, a guest runtime speaking the
//! length-prefixed frame protocol (QEMU `-netdev stream`, passt, libkrun); or, with
//! `--packet <IFNAME>` (Linux), serves the guest behind the host TAP `IFNAME` that a monitor
//! such as Firecracker holds, through an `AF_PACKET` socket, creating that TAP first with
//! `--create-tap`. An `nsplane-ether` adapter answers the guest's DHCP, ARP and neighbor discovery and hands
//! its IP packets to the engine, which carries them over UDP to the `--peer`s. The guest
//! leases its tunnel address (`--address`) with the gateway, the `--dns` servers and the
//! tunnel MTU (`--mtu`); `--ipv6-prefix` adds a router advertisement, `--masquerade`
//! rewrites the guest's IPv6 flows to a single tunnel address, and `--policy` installs a
//! reloadable ACL on the engine. Exits when the guest disconnects (Unix socket only) or on
//! Ctrl-C, logging the adapter and ACL counters; a TAP created with `--create-tap` is deleted
//! on exit. The status file's `extra` holds `ether`, `acl` and
//! `masquerade`. See [`nsplane_examples::vm`] for the address plan.
//!
//! APIs shown: [`spawn_port`] and the frame transports ([`stream::unix`], `PacketSocket` and
//! `ensure_tap` on Linux) as the engine's packet source and sink, [`EtherConfig`] with a [`DhcpConfig`] lease, the fragmentation
//! stage ([`FragmentConfig`]), [`MapSink`] and a wrapping source around a [`Masquerade`],
//! and [`AclFilter`] with a namespace policy that restricts both directions.
//!
//! Usage: `cargo run -p nsplane-examples --bin vm_wireguard -- --socket /tmp/guest.sock
//! --private-key-file vm.key --listen 0.0.0.0:51820 --address 10.66.0.2/24
//! --peer <PUBKEY>,endpoint=192.0.2.1:51820,allowed-ips=0.0.0.0/0,keepalive=25`; for
//! Firecracker, `--packet fctap0 --create-tap` instead of `--socket` and `fctap0` as the
//! microVM's `host_dev_name`.
//!
//! [`spawn_port`]: nsplane_ether::spawn_port
//! [`stream::unix`]: nsplane_ether::stream::unix
//! [`EtherConfig`]: nsplane_ether::EtherConfig
//! [`DhcpConfig`]: nsplane_ether::DhcpConfig
//! [`FragmentConfig`]: nsplane::FragmentConfig
//! [`MapSink`]: nsplane::MapSink
//! [`Masquerade`]: nsplane_nat::Masquerade
//! [`AclFilter`]: nsplane_acl::AclFilter

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use anyhow::Context as _;
    use clap::Parser;
    use nsplane_ether::stream;
    use nsplane_examples::node::{self, NodeArgs, init_logging};
    use nsplane_examples::status::Status;
    use nsplane_examples::vm::{self, VmArgs};
    use tokio::net::UnixListener;

    /// A virtual machine's link as the local side of a WireGuard engine.
    #[derive(Debug, Parser)]
    #[command(name = "vm_wireguard", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        vm: VmArgs,

        /// Unix socket the guest runtime connects to
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "packet",
            conflicts_with = "packet"
        )]
        socket: Option<PathBuf>,

        /// Serve the guest behind the existing interface IFNAME, the host side of a TAP held
        /// by a monitor such as Firecracker, through a raw packet socket (Linux; needs the
        /// raw socket capability)
        #[arg(long, value_name = "IFNAME")]
        packet: Option<String>,

        /// With --packet: create IFNAME as a persistent TAP unless it exists (needs the
        /// network admin capability) and delete it on exit
        #[arg(long, requires = "packet")]
        create_tap: bool,

        /// With --create-tap: the user allowed to attach to the TAP
        #[arg(long, value_name = "UID", requires = "create_tap")]
        tap_owner: Option<u32>,

        /// With --create-tap: the group allowed to attach to the TAP
        #[arg(long, value_name = "GID", requires = "create_tap")]
        tap_group: Option<u32>,
    }

    /// Keeps a TAP created with `--create-tap` until the node exits.
    #[cfg(target_os = "linux")]
    type Tap = Option<nsplane_ether::TapInterface>;
    #[cfg(not(target_os = "linux"))]
    type Tap = ();

    /// Connects the guest on `--socket` or `--packet` and starts the node on its link.
    async fn connect(args: &Args) -> anyhow::Result<(vm::Vm, Tap)> {
        if let Some(socket) = &args.socket {
            let listener = UnixListener::bind(socket)
                .with_context(|| format!("cannot listen on {}", socket.display()))?;
            tracing::info!(socket = %socket.display(), "waiting for the guest");
            let (conn, _) = listener.accept().await?;
            let (reader, writer) = stream::unix(conn);
            let vm = vm::start(reader, writer, &args.node, &args.vm).await?;
            return Ok((vm, Tap::default()));
        }
        let ifname = args.packet.as_deref().unwrap_or_default();
        #[cfg(target_os = "linux")]
        {
            use nsplane_ether::{PacketSocket, TapConfig, ensure_tap};

            let tap = if args.create_tap {
                let mut config = TapConfig::new(ifname);
                if let Some(uid) = args.tap_owner {
                    config = config.owner(uid);
                }
                if let Some(gid) = args.tap_group {
                    config = config.group(gid);
                }
                let tap = ensure_tap(&config)
                    .with_context(|| format!("cannot create the TAP interface {ifname}"))?;
                tracing::info!(
                    interface = ifname,
                    created = tap.created(),
                    "TAP interface ready"
                );
                Some(tap)
            } else {
                None
            };
            let (reader, writer) = PacketSocket::bind(ifname)
                .with_context(|| format!("cannot open a packet socket on {ifname}"))?
                .split();
            tracing::info!(interface = ifname, "serving the guest on the interface");
            let vm = vm::start(reader, writer, &args.node, &args.vm).await?;
            Ok((vm, tap))
        }
        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("--packet {ifname} needs Linux")
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        // A TAP created with --create-tap lives until the node returns.
        let (vm, _tap) = connect(&args).await?;
        tracing::info!(listen = %vm.listen, lease = %node::cidr(&args.vm.address), gateway = %args.vm.gateway_ipv4()?, mtu = args.vm.mtu, "guest connected");
        if let Some(acl) = &vm.acl {
            tokio::spawn(acl.clone().watch());
        }

        let handle = vm.engine.handle();
        let status = args.node.status_file.clone().map(|path| {
            let (ether, acl, masquerade) =
                (vm.ether.clone(), vm.acl.clone(), vm.masquerade.clone());
            Status::new(path, handle.clone(), vm.listen).extra(move |extra| {
                extra.insert("ether".to_owned(), vm::ether_json(&ether));
                if let Some(acl) = &acl {
                    extra.insert("acl".to_owned(), acl.status_json());
                }
                if let Some(masquerade) = &masquerade {
                    extra.insert("masquerade".to_owned(), vm::masquerade_json(masquerade));
                }
            })
        });
        let writer = status.as_ref().map(Status::spawn);

        let wait = vm.engine.wait();
        tokio::pin!(wait);
        let stopped = tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("cannot watch Ctrl-C")?;
                tracing::info!("Ctrl-C received, shutting down");
                false
            }
            _ = vm.guest_gone => {
                tracing::info!("guest disconnected, shutting down");
                false
            }
            stopped = &mut wait => {
                stopped.context("the engine failed")?;
                true
            }
        };
        if let Some(writer) = writer {
            writer.abort();
            let _ = writer.await;
        }
        if let Some(status) = &status {
            status.write().await?;
        }
        tracing::info!(ether = %vm::ether_json(&vm.ether), "adapter counters");
        if let Some(acl) = &vm.acl {
            tracing::info!(acl = %acl.status_json(), "ACL counters");
        }
        if stopped {
            anyhow::bail!("the engine stopped");
        }
        let _ = handle.shutdown().await;
        wait.await.context("the engine failed")?;
        Ok(ExitCode::SUCCESS)
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
    anyhow::bail!("vm_wireguard needs a Unix platform (the guest connects over a Unix socket)")
}
