//! A TUN node that the `wg` tool can manage, like `nsplane-cli`.
//!
//! Creates a TUN device, configures its `--address`es, MTU and routes (Linux: through `ip`;
//! macOS: prints the `ifconfig` / `route` commands to run; Windows: through `netsh`), runs
//! the engine on it with a UDP transport on `--listen`, and on Unix serves the UAPI on the
//! standard socket, so `wg show <name>` and `wg set <name> ...` work. Echo (`--echo-port`)
//! and `--check`s run on the host's kernel stack, through the tunnel. Runs until Ctrl-C, or
//! until the checks finish with `--exit-after-checks`. Needs root (or `CAP_NET_ADMIN`); on
//! Windows an administrator and `wintun.dll` beside the executable or in the system
//! directory. There the adapter is a Wintun adapter: `--exclusive` refuses a live adapter
//! of the same name, and the peers come from `--peer` only.
//!
//! APIs shown: `nsplane_tun::Tun::create_with` (offloads off with `--no-offload`),
//! `Tun::offload` and `Tun::split` as the engine's packet source
//! and sink, `nsplane_uapi::Uapi::with_listen_port` (`--transport udp`) and
//! `Uapi::with_external_transport` (`--transport relay|wss`), `UapiListener::bind` and
//! `Uapi::serve`,
//! and the shared node assembly (`build_engine`, `configure_peers`).
//!
//! Usage: `sudo cargo run -p nsplane-examples --bin tun_node -- --private-key <KEY>
//! --address 10.0.0.1/24 --peer <PUBKEY>,endpoint=192.0.2.2:51820,allowed-ips=10.0.0.2/32
//! --echo-port 7`

#[cfg(any(unix, windows))]
mod imp {
    use std::net::IpAddr;
    #[cfg(any(target_os = "linux", windows))]
    use std::process::Command;
    use std::process::ExitCode;

    use anyhow::Context as _;
    #[cfg(any(target_os = "linux", windows))]
    use anyhow::bail;
    use clap::Parser;
    use nsplane::AllowedIp;
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, build_engine, configure_peers, init_logging, parse_cidr,
    };
    #[cfg(unix)]
    use nsplane_examples::node::{TransportKind, UDP_TRANSPORT};
    use nsplane_examples::status::Status;
    #[cfg(unix)]
    use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};

    // `wg set listen-port` rebinds the UAPI's transport, so the node's UDP transport is it;
    // a relay or WSS transport under that id is left alone.
    #[cfg(unix)]
    const _: () = assert!(UDP_TRANSPORT.get() == TRANSPORT_ID.get());

    /// The default interface name: Linux names it freely, macOS needs `utun[N]`.
    const DEFAULT_TUN_NAME: &str = if cfg!(target_os = "macos") {
        "utun"
    } else {
        "nsp0"
    };

    /// An nsplane node on a TUN device, managed with `wg` (needs root).
    #[derive(Debug, Parser)]
    #[command(name = "tun_node", version)]
    pub(crate) struct Args {
        #[command(flatten)]
        node: NodeArgs,

        #[command(flatten)]
        echo: EchoArgs,

        /// Name of the TUN interface (macOS: `utun` or `utunN`)
        #[arg(long, value_name = "NAME", default_value = DEFAULT_TUN_NAME)]
        tun_name: String,

        /// Address of the interface with its prefix, repeatable
        #[arg(long, value_name = "CIDR", value_parser = parse_cidr)]
        address: Vec<AllowedIp>,

        /// MTU of the interface
        #[arg(long, value_name = "N", default_value_t = 1420)]
        mtu: u16,

        /// Refuse a live adapter of the same name instead of opening it
        #[cfg(windows)]
        #[arg(long)]
        exclusive: bool,
    }

    /// `addr/cidr`.
    fn cidr(ip: &AllowedIp) -> String {
        format!("{}/{}", ip.addr, ip.cidr)
    }

    /// The first `bits` bits of `addr`, as a number of its family's width.
    fn masked(addr: IpAddr, bits: u8) -> u128 {
        let (value, width) = match addr {
            IpAddr::V4(v4) => (u128::from(v4.to_bits()), 32),
            IpAddr::V6(v6) => (v6.to_bits(), 128),
        };
        let bits = u32::from(bits.min(width));
        if bits == 0 {
            0
        } else {
            value >> (u32::from(width) - bits)
        }
    }

    /// Whether `net` contains all of `ip`.
    fn covers(net: &AllowedIp, ip: &AllowedIp) -> bool {
        net.addr.is_ipv4() == ip.addr.is_ipv4()
            && net.cidr <= ip.cidr
            && masked(net.addr, net.cidr) == masked(ip.addr, net.cidr)
    }

    /// The peers' allowed IPs that no interface address's connected prefix covers.
    fn routes(args: &Args) -> Vec<AllowedIp> {
        let mut routes: Vec<AllowedIp> = Vec::new();
        for ip in args.node.peer.iter().flat_map(|peer| &peer.allowed_ips) {
            if !args.address.iter().any(|net| covers(net, ip)) && !routes.contains(ip) {
                routes.push(*ip);
            }
        }
        routes
    }

    /// Runs `ip <args>`; a "File exists" error (already configured) is fine.
    #[cfg(target_os = "linux")]
    fn ip(args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .context("cannot run `ip`")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() || stderr.contains("File exists") {
            tracing::info!(command = format!("ip {}", args.join(" ")), "configured");
            Ok(())
        } else {
            bail!("`ip {}` failed: {}", args.join(" "), stderr.trim())
        }
    }

    /// Configures addresses, MTU, link state and routes of `name` through `ip`.
    #[cfg(target_os = "linux")]
    fn configure_interface(name: &str, args: &Args) -> anyhow::Result<()> {
        for address in &args.address {
            ip(&["address", "add", &cidr(address), "dev", name])?;
        }
        ip(&[
            "link",
            "set",
            "dev",
            name,
            "mtu",
            &args.mtu.to_string(),
            "up",
        ])?;
        for route in routes(args) {
            ip(&["route", "add", &cidr(&route), "dev", name])?;
        }
        Ok(())
    }

    /// Runs `netsh interface <args>`; an "already exists" error is fine.
    #[cfg(windows)]
    fn netsh(args: &[&str]) -> anyhow::Result<()> {
        let output = Command::new("netsh")
            .arg("interface")
            .args(args)
            .output()
            .context("cannot run `netsh`")?;
        // netsh reports its errors on stdout.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if output.status.success() || stdout.contains("already exists") {
            tracing::info!(
                command = format!("netsh interface {}", args.join(" ")),
                "configured"
            );
            Ok(())
        } else {
            bail!(
                "`netsh interface {}` failed: {}",
                args.join(" "),
                stdout.trim()
            )
        }
    }

    /// Configures addresses and routes of `name` through `netsh`; the MTU is set when the
    /// adapter is created.
    #[cfg(windows)]
    fn configure_interface(name: &str, args: &Args) -> anyhow::Result<()> {
        let family = |ip: &AllowedIp| if ip.addr.is_ipv4() { "ipv4" } else { "ipv6" };
        for address in &args.address {
            netsh(&[family(address), "add", "address", name, &cidr(address)])?;
        }
        for route in routes(args) {
            netsh(&[family(&route), "add", "route", &cidr(&route), name])?;
        }
        Ok(())
    }

    /// Prints the `ifconfig` / `route` commands that configure `name`.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn configure_interface(name: &str, args: &Args) {
        let mut commands = Vec::new();
        for address in &args.address {
            if address.addr.is_ipv4() {
                commands.push(format!(
                    "ifconfig {name} inet {} {} alias",
                    cidr(address),
                    address.addr
                ));
            } else {
                commands.push(format!("ifconfig {name} inet6 {} alias", cidr(address)));
            }
        }
        commands.push(format!("ifconfig {name} mtu {} up", args.mtu));
        for net in args.address.iter().chain(routes(args).iter()) {
            let family = if net.addr.is_ipv4() {
                "-inet"
            } else {
                "-inet6"
            };
            commands.push(format!(
                "route -q -n add {family} {} -interface {name}",
                cidr(net)
            ));
        }
        nsplane_examples::out::line(format_args!("Configure the interface with:"));
        for command in commands {
            nsplane_examples::out::line(format_args!("  sudo {command}"));
        }
    }

    pub(crate) async fn main(args: Args) -> anyhow::Result<ExitCode> {
        init_logging(&args.node.log)?;
        #[cfg(unix)]
        let tun = node::create_tun(&args.tun_name, &args.node)?;
        #[cfg(unix)]
        let offload = node::offload_mode(tun.offload());
        #[cfg(windows)]
        let tun = {
            let options = nsplane_tun::TunOptions::new()
                .exclusive(args.exclusive)
                .mtu(args.mtu);
            // The error's source names the Wintun failure, e.g. `AdapterExists`.
            nsplane_tun::Tun::create_with(&args.tun_name, options)
                .map_err(|e| anyhow::anyhow!("cannot create TUN {}: {e:?}", args.tun_name))?
        };
        let name = tun.name().unwrap_or_else(|_| args.tun_name.clone());
        #[cfg(any(target_os = "linux", windows))]
        configure_interface(&name, &args)?;
        #[cfg(all(unix, not(target_os = "linux")))]
        configure_interface(&name, &args);
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        let node = build_engine(source, sink, &args.node)?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;

        #[cfg(windows)]
        tracing::info!(interface = %name, listen = %node.transports.listen, "TUN node started");
        #[cfg(unix)]
        {
            let port = node.transports.listen.port();
            let uapi = match args.node.transport.transport {
                TransportKind::Udp => Uapi::with_listen_port(handle.clone(), port),
                TransportKind::Relay | TransportKind::Wss => {
                    Uapi::with_external_transport(handle.clone(), port)
                }
            };
            let listener = UapiListener::bind(&name).context("cannot bind the UAPI socket")?;
            let socket = listener.path().display().to_string();
            tokio::spawn(async move {
                if let Err(e) = uapi.serve(listener).await {
                    tracing::warn!(error = %e, "UAPI server failed");
                }
            });
            tracing::info!(interface = %name, %offload, listen = %node.transports.listen, uapi = %socket, "TUN node started");
        }

        let status = args
            .node
            .status_file
            .clone()
            .map(|path| Status::new(path, handle, node.transports.listen));
        node::run(node.engine, &args.echo, Backend::Kernel, status).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn prefix_cover() {
            let net = parse_cidr("10.0.0.1/24").unwrap();
            assert!(covers(&net, &parse_cidr("10.0.0.2/32").unwrap()));
            assert!(!covers(&net, &parse_cidr("10.0.1.2/32").unwrap()));
            assert!(!covers(&net, &parse_cidr("10.0.0.0/16").unwrap()));
            assert!(!covers(&net, &parse_cidr("fd00::1/128").unwrap()));
            let v6 = parse_cidr("fd00::1/64").unwrap();
            assert!(covers(&v6, &parse_cidr("fd00::2/128").unwrap()));
            assert!(covers(&parse_cidr("0.0.0.0/0").unwrap(), &net));
        }
    }
}

#[cfg(any(unix, windows))]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    use clap::Parser as _;
    imp::main(imp::Args::parse()).await
}

#[cfg(not(any(unix, windows)))]
fn main() -> anyhow::Result<std::process::ExitCode> {
    anyhow::bail!("tun_node runs on Linux, macOS and Windows only")
}
