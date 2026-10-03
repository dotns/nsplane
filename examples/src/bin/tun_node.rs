//! A TUN node that the `wg` tool can manage, like `nsplane-cli`.
//!
//! Creates a TUN device, configures its `--address`es, MTU and routes (Linux: through `ip`;
//! macOS: prints the `ifconfig` / `route` commands to run), runs the engine on it with a
//! UDP transport on `--listen`, and serves the UAPI on the standard socket, so
//! `wg show <name>` and `wg set <name> ...` work. Echo (`--echo-port`) and `--check`s run
//! on the host's kernel stack, through the tunnel. Runs until Ctrl-C, or until the checks
//! finish with `--exit-after-checks`. Needs root (or `CAP_NET_ADMIN`).
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

#[cfg(unix)]
mod unix {
    use std::net::IpAddr;
    #[cfg(target_os = "linux")]
    use std::process::Command;
    use std::process::ExitCode;

    use anyhow::Context as _;
    #[cfg(target_os = "linux")]
    use anyhow::bail;
    use clap::Parser;
    use nsplane::AllowedIp;
    use nsplane_examples::echo::{Backend, EchoArgs};
    use nsplane_examples::node::{
        self, NodeArgs, TransportKind, UDP_TRANSPORT, build_engine, configure_peers, init_logging,
        parse_cidr,
    };
    use nsplane_examples::status::Status;
    use nsplane_uapi::{TRANSPORT_ID, Uapi, UapiListener};

    // `wg set listen-port` rebinds the UAPI's transport, so the node's UDP transport is it;
    // a relay or WSS transport under that id is left alone.
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

    /// Prints the `ifconfig` / `route` commands that configure `name`.
    #[cfg(not(target_os = "linux"))]
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
        let tun = node::create_tun(&args.tun_name, &args.node)?;
        let offload = node::offload_mode(tun.offload());
        let name = tun.name().unwrap_or_else(|_| args.tun_name.clone());
        #[cfg(target_os = "linux")]
        configure_interface(&name, &args)?;
        #[cfg(not(target_os = "linux"))]
        configure_interface(&name, &args);
        let (source, sink) = tun.split().context("cannot open the TUN device")?;
        let node = build_engine(source, sink, &args.node)?;
        let handle = node.engine.handle();
        configure_peers(&handle, &args.node.peer).await?;

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

#[cfg(unix)]
#[tokio::main]
async fn main() -> anyhow::Result<std::process::ExitCode> {
    use clap::Parser as _;
    unix::main(unix::Args::parse()).await
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<std::process::ExitCode> {
    anyhow::bail!("tun_node runs on Linux and macOS only")
}
