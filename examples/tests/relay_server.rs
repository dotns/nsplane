//! The relay's wrapping transport on a real UDP socket (what reaches the own engine, what
//! is relayed, what is answered, and that nothing else is ever sent), and `relay_server`
//! with two `netstack_node --transport relay` processes.

use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nsplane::{PacketBuf, Transport, UdpTransport};
use nsplane_examples::node::{UDP_TRANSPORT, encode_key, encode_public_key, generate_key};
use nsplane_examples::relay::envelope::MachineKey;
use nsplane_examples::relay::messages::{
    PendingNonces, build_reflexive_request, build_register_source,
};
use nsplane_examples::relay::router::{
    Counters, MachinePin, Router, Source, TargetConfig, machine_id,
};
use nsplane_examples::relay::server::RelayServerTransport;
use nsplane_examples::relay::wire::{self, ControlType, Frame, WgKind};
use nsplane_noise::noise::{Tunn, TunnResult};
use nsplane_noise::x25519::{PublicKey, StaticSecret};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const OWN: u8 = 1;
const A: u8 = 2;
const B: u8 = 3;
const QUIET: Duration = Duration::from_millis(300);

fn secret(byte: u8) -> StaticSecret {
    StaticSecret::from([byte; 32])
}

fn public(byte: u8) -> [u8; 32] {
    PublicKey::from(&secret(byte)).to_bytes()
}

/// A handshake initiation from key `from` to key `to`, and the response.
fn handshake(from: u8, to: u8) -> TestResult<(Vec<u8>, Vec<u8>)> {
    let mut initiator = Tunn::new(
        secret(from),
        PublicKey::from(public(to)),
        None,
        None,
        1,
        None,
    );
    let mut responder = Tunn::new(
        secret(to),
        PublicKey::from(public(from)),
        None,
        None,
        2,
        None,
    );
    let mut buf = vec![0u8; 2048];
    let TunnResult::WriteToNetwork(init) = initiator.format_handshake_initiation(&mut buf, false)
    else {
        return Err("no initiation".into());
    };
    let init = init.to_vec();
    let mut out = vec![0u8; 2048];
    let TunnResult::WriteToNetwork(response) = responder.decapsulate(None, &init, &mut out) else {
        return Err("no response".into());
    };
    Ok((init, response.to_vec()))
}

/// A relay on loopback whose own engine is a channel of the datagrams handed to it.
struct Relay {
    addr: SocketAddr,
    router: Arc<Mutex<Router>>,
    engine: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
}

impl Relay {
    fn start(targets: Vec<TargetConfig>) -> TestResult<Self> {
        let udp = UdpTransport::bind(UDP_TRANSPORT, "127.0.0.1:0".parse()?)?;
        let addr = udp.local_addr();
        let mut router = Router::new(public(OWN), "relay".into(), addr);
        router.set_targets(targets);
        let router = Arc::new(Mutex::new(router));
        let transport = RelayServerTransport::new(udp, Arc::clone(&router));
        let (tx, engine) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = PacketBuf::with_capacity(2048);
            while let Ok((_, path)) = transport.recv(&mut buf).await {
                if tx.send((buf.as_packet().to_vec(), path.addr)).is_err() {
                    return;
                }
            }
        });
        Ok(Self {
            addr,
            router,
            engine,
        })
    }

    fn counters(&self) -> Counters {
        self.router
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counters()
    }

    fn target_source(&self, index: usize) -> Option<Source> {
        let router = self.router.lock().unwrap_or_else(PoisonError::into_inner);
        router.targets(Instant::now()).get(index)?.source
    }

    /// Waits until the router counted `n` in `counter`.
    async fn settle(&self, counter: impl Fn(&Counters) -> u64, n: u64) -> TestResult {
        for _ in 0..50 {
            if counter(&self.counters()) >= n {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(format!("counter never reached {n}: {:?}", self.counters()).into())
    }
}

async fn socket() -> TestResult<UdpSocket> {
    Ok(UdpSocket::bind("127.0.0.1:0").await?)
}

/// The next datagram on `socket`, or `None` after [`QUIET`].
async fn next(socket: &UdpSocket) -> TestResult<Option<Vec<u8>>> {
    let mut buf = vec![0u8; 2048];
    let Ok(received) = timeout(QUIET, socket.recv_from(&mut buf)).await else {
        return Ok(None);
    };
    buf.truncate(received?.0);
    Ok(Some(buf))
}

fn pinned(key: u8, machine: &MachineKey) -> TargetConfig {
    TargetConfig {
        wg_public_key: public(key),
        pin: Some(MachinePin {
            machine_id: machine_id(&machine.public()),
            machine_key: machine.public(),
        }),
        static_source: None,
    }
}

fn register_frame(key: u8, machine: &MachineKey) -> TestResult<Vec<u8>> {
    Ok(build_register_source(
        &machine_id(&machine.public()),
        machine,
        public(key),
    )?)
}

#[tokio::test]
async fn own_engine_and_relayed_traffic_are_told_apart() -> TestResult {
    let machine = MachineKey::generate();
    let mut relay = Relay::start(vec![pinned(B, &machine)])?;
    let (a, b) = (socket().await?, socket().await?);
    b.send_to(&register_frame(B, &machine)?, relay.addr).await?;
    relay.settle(|c| c.registrations, 1).await?;

    // To the relay's own key: the engine gets it, nobody else.
    let (own_init, _) = handshake(A, OWN)?;
    a.send_to(&own_init, relay.addr).await?;
    let received = timeout(QUIET, relay.engine.recv()).await?;
    assert_eq!(received, Some((own_init, a.local_addr()?)));
    assert_eq!(next(&b).await?, None);

    // To B: relayed to B's registered source, both ways; the engine sees none of it.
    let (init, response) = handshake(A, B)?;
    a.send_to(&init, relay.addr).await?;
    assert_eq!(next(&b).await?, Some(init));
    b.send_to(&response, relay.addr).await?;
    assert_eq!(next(&a).await?, Some(response));
    assert!(relay.engine.try_recv().is_err());
    let counters = relay.counters();
    assert_eq!((counters.own_engine, counters.forwarded), (1, 2));
    Ok(())
}

#[tokio::test]
async fn ambiguous_handshakes_are_dropped() -> TestResult {
    // A target with the relay's own key: an initiation matches both.
    let mut relay = Relay::start(vec![TargetConfig {
        wg_public_key: public(OWN),
        pin: None,
        static_source: Some(Source::Udp("127.0.0.1:9".parse()?)),
    }])?;
    let a = socket().await?;
    let (init, _) = handshake(A, OWN)?;
    a.send_to(&init, relay.addr).await?;
    relay.settle(|c| c.dropped_ambiguous, 1).await?;
    assert!(relay.engine.try_recv().is_err());
    assert_eq!(relay.counters().forwarded, 0);
    Ok(())
}

#[tokio::test]
async fn unauthenticated_registration_is_rejected() -> TestResult {
    let machine = MachineKey::generate();
    let intruder = MachineKey::generate();
    let relay = Relay::start(vec![pinned(B, &machine)])?;
    let attacker = socket().await?;
    // Signed by another machine, claiming the pinned machine id.
    let forged = build_register_source(&machine_id(&machine.public()), &intruder, public(B))?;
    attacker.send_to(&forged, relay.addr).await?;
    relay.settle(|c| c.dropped_bad_signature, 1).await?;
    assert_eq!(relay.target_source(0), None);
    assert_eq!(next(&attacker).await?, None);

    // The genuine one, then its replay from the attacker.
    let b = socket().await?;
    let genuine = register_frame(B, &machine)?;
    b.send_to(&genuine, relay.addr).await?;
    relay.settle(|c| c.registrations, 1).await?;
    attacker.send_to(&genuine, relay.addr).await?;
    relay.settle(|c| c.dropped_replay, 1).await?;
    assert_eq!(relay.target_source(0), Some(Source::Udp(b.local_addr()?)));
    Ok(())
}

#[tokio::test]
async fn reflexive_replies_are_bound_to_the_request_nonce() -> TestResult {
    let machine = MachineKey::generate();
    let relay = Relay::start(vec![pinned(A, &machine)])?;
    let a = socket().await?;
    let mut pending = PendingNonces::new();
    let nonce = pending.issue(Instant::now());
    let request =
        build_reflexive_request(&machine_id(&machine.public()), &machine, public(A), nonce)?;
    a.send_to(&request, relay.addr).await?;
    let reply = next(&a).await?.ok_or("no reflexive reply")?;
    let (msg_type, payload) = wire::decode_control(&reply)?;
    assert_eq!(msg_type, ControlType::ReflexiveResponse);
    let response = pending.accept(payload, Instant::now())?;
    assert_eq!(response.nonce, nonce);
    assert_eq!(response.observed_addr, a.local_addr()?);
    assert_eq!(response.relay_socket_addr, relay.addr);
    // The same reply cannot be accepted twice, and a replayed request gets none.
    assert!(pending.accept(payload, Instant::now()).is_err());
    a.send_to(&request, relay.addr).await?;
    assert_eq!(next(&a).await?, None);
    assert_eq!(relay.counters().control_tx, 1);
    Ok(())
}

#[tokio::test]
async fn the_relay_sends_no_unsolicited_control() -> TestResult {
    let machine = MachineKey::generate();
    let mut relay = Relay::start(vec![pinned(B, &machine)])?;
    let (a, b) = (socket().await?, socket().await?);
    b.send_to(&register_frame(B, &machine)?, relay.addr).await?;
    relay.settle(|c| c.registrations, 1).await?;
    let (init, _) = handshake(A, B)?;
    a.send_to(&init, relay.addr).await?;
    // B gets the relayed initiation and nothing else: registration is never acknowledged.
    let relayed = next(&b).await?.ok_or("nothing relayed")?;
    assert_eq!(
        wire::classify(&relayed),
        Frame::WireGuard(WgKind::HandshakeInit)
    );
    assert_eq!(next(&b).await?, None);

    // Junk, reserved and response-typed control frames, and plain WireGuard: no answer.
    let c = socket().await?;
    let (own_init, _) = handshake(A, OWN)?;
    for datagram in [
        b"junk".to_vec(),
        vec![0xF1, 0, 0, 0, 1],
        wire::encode_control(ControlType::ReflexiveResponse, b"\xA0"),
        wire::encode_control(ControlType::ReflexiveRequest, b"\xA0"),
        own_init,
    ] {
        c.send_to(&datagram, relay.addr).await?;
    }
    assert_eq!(next(&c).await?, None);
    assert!(relay.engine.recv().await.is_some());
    assert_eq!(relay.counters().control_tx, 0);
    Ok(())
}

/// A loopback UDP port that was free a moment ago.
fn free_port() -> TestResult<u16> {
    Ok(std::net::UdpSocket::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// One `netstack_node --transport relay` of the process test.
struct NodeProc {
    _child: Child,
    status: PathBuf,
    reflexive: PathBuf,
}

/// The process test's files and addresses.
struct Setup {
    dir: PathBuf,
    relay_addr: String,
    relay_pub: String,
}

impl Setup {
    /// Creates a machine key with `relay_server gen-machine-key`; returns its path and
    /// public key.
    fn machine_key(&self, name: &str) -> TestResult<(PathBuf, String)> {
        let path = self.dir.join(name);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_relay_server"))
            .arg("gen-machine-key")
            .arg(&path)
            .output()?;
        assert!(output.status.success(), "{output:?}");
        Ok((path, String::from_utf8(output.stdout)?.trim().to_owned()))
    }

    /// Starts a node `name` on `port` with stack address `ip` and peer `other` (public
    /// key, stack address, port), reached through the relay with a direct candidate.
    fn node(
        &self,
        name: &str,
        key: &StaticSecret,
        (port, ip): (u16, &str),
        machine: &Path,
        (other_pub, other_ip, other_port): (&str, &str, u16),
    ) -> TestResult<NodeProc> {
        let candidates = self.dir.join(format!("{name}.candidates.json"));
        let candidate = format!("127.0.0.1:{other_port}");
        std::fs::write(&candidates, json!({ other_pub: [candidate] }).to_string())?;
        let status = self.dir.join(format!("{name}.status.json"));
        let reflexive = self.dir.join(format!("{name}.reflexive.json"));
        let relay = &self.relay_addr;
        let child = Command::new(env!("CARGO_BIN_EXE_netstack_node"))
            .args(["--private-key", &encode_key(&key.to_bytes())])
            .args(["--listen", &format!("127.0.0.1:{port}"), "--address", ip])
            .args(["--transport", "relay", "--relay", relay])
            .arg("--machine-key-file")
            .arg(machine)
            .arg("--peer-candidates")
            .arg(&candidates)
            .arg("--reflexive-out")
            .arg(&reflexive)
            .arg("--status-file")
            .arg(&status)
            .args(["--direct-timeout-ms", "2000", "--echo-port", "7"])
            .args([
                "--peer",
                &format!(
                    "{},endpoint={relay},allowed-ips=10.78.0.1/32",
                    self.relay_pub
                ),
            ])
            .args([
                "--peer",
                &format!("{other_pub},endpoint={relay},allowed-ips={other_ip}/32,keepalive=1"),
            ])
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        Ok(NodeProc {
            _child: child,
            status,
            reflexive,
        })
    }
}

/// `relay_server` and two `netstack_node --transport relay` processes: discovery,
/// registration, the reflexive file and the direct path, as the status files report them.
#[tokio::test]
async fn relay_server_and_relay_transport_nodes() -> TestResult {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("nsplane-relay-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (relay_key, a_key, b_key) = (generate_key(), generate_key(), generate_key());
    let [relay_pub, a_pub, b_pub] =
        [&relay_key, &a_key, &b_key].map(|key| encode_public_key(&PublicKey::from(key)));
    let (a_port, b_port) = (free_port()?, free_port()?);
    let setup = Setup {
        dir,
        relay_addr: format!("127.0.0.1:{}", free_port()?),
        relay_pub,
    };
    let (a_machine, a_machine_pub) = setup.machine_key("a.machine")?;
    let (b_machine, b_machine_pub) = setup.machine_key("b.machine")?;

    let config = setup.dir.join("relay.json");
    let machine_keys = json!({"machine_keys": [
        {"machine_key": a_machine_pub, "wg_public_key": a_pub},
        {"machine_key": b_machine_pub, "wg_public_key": b_pub},
    ]});
    std::fs::write(&config, machine_keys.to_string())?;
    let relay_status = setup.dir.join("relay.status.json");
    let _relay = Command::new(env!("CARGO_BIN_EXE_relay_server"))
        .args(["--private-key", &encode_key(&relay_key.to_bytes())])
        .args(["--listen", &setup.relay_addr, "--address", "10.78.0.1/24"])
        .args(["--peer", &format!("{a_pub},allowed-ips=10.78.0.2/32")])
        .args(["--peer", &format!("{b_pub},allowed-ips=10.78.0.3/32")])
        .args(["--echo-port", "7"])
        .arg("--config")
        .arg(&config)
        .arg("--status-file")
        .arg(&relay_status)
        .kill_on_drop(true)
        .spawn()?;
    let a = setup.node(
        "a",
        &a_key,
        (a_port, "10.78.0.2/24"),
        &a_machine,
        (&b_pub, "10.78.0.3", b_port),
    )?;
    let _b = setup.node(
        "b",
        &b_key,
        (b_port, "10.78.0.3/24"),
        &b_machine,
        (&a_pub, "10.78.0.2", a_port),
    )?;

    // The JSON paths the e2e harness reads.
    let relay_addr = setup.relay_addr.as_str();
    let ready = |status: &Value, relay: &Value| {
        status["extra"]["relay"]["endpoints"][relay_addr]["state"] == "capable"
            && status["extra"]["paths"][&b_pub]["active"] == "direct"
            && status["extra"]["paths"][&b_pub]["confirmed"] == true
            && relay["extra"]["relay"]["counters"]["registrations"].as_u64() >= Some(2)
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let (status, relay) = loop {
        let (status, relay) = (read_json(&a.status), read_json(&relay_status));
        if let (Some(status), Some(relay)) = (&status, &relay)
            && ready(status, relay)
        {
            break (status.clone(), relay.clone());
        }
        assert!(
            Instant::now() < deadline,
            "not ready: {status:?}\n{relay:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let endpoint = &status["extra"]["relay"]["endpoints"][relay_addr];
    assert!(endpoint["control_answered"].as_u64() >= Some(1), "{status}");
    let a_addr = format!("127.0.0.1:{a_port}");
    assert_eq!(status["extra"]["relay"]["reflexive"], a_addr.as_str());
    let direct = &status["extra"]["paths"][&b_pub]["direct"];
    assert_eq!(*direct, format!("127.0.0.1:{b_port}").as_str());
    let reflexive = read_json(&a.reflexive).ok_or("no reflexive file")?;
    assert_eq!(reflexive["reflexive"], a_addr.as_str());
    assert_eq!(reflexive["relay"], relay_addr);
    let targets = relay["extra"]["relay"]["targets"]
        .as_array()
        .ok_or("no targets")?;
    assert_eq!(targets.len(), 2, "{relay}");
    assert!(targets.iter().all(|t| t["source"].is_string()), "{relay}");
    let _ = std::fs::remove_dir_all(&setup.dir);
    Ok(())
}
