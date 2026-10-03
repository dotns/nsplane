use std::error::Error;
use std::task::Waker;

use smoltcp::socket::tcp as client_tcp;
use smoltcp::wire::IpListenEndpoint;
use tokio::io::ReadBuf;
use tokio::time::{sleep, timeout};

use super::*;
use crate::udp::build_udp;

mod basic_udp;
mod buffers;
mod half_close;
mod listener_integration;
mod listener_pool;
mod ownership;
mod progress;
mod reassembly;

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(1);

/// A stack at `ip`/32 with the ns tunnel MTU.
fn config(ip: Ipv4Addr) -> NetStackConfig {
    NetStackConfig::new(vec![(IpAddr::V4(ip), 32)], 1360)
}

/// The next item of `stream`, waiting for it.
async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// The next item of `stream` if one is ready now.
fn try_next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    match Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(item) => item,
        Poll::Pending => None,
    }
}

/// The bytes `conn` can read now.
fn try_read(conn: &mut TcpConnection) -> Vec<u8> {
    let mut storage = vec![0; 64 * 1024];
    let mut buf = ReadBuf::new(&mut storage);
    let ready = tokio::io::AsyncRead::poll_read(
        Pin::new(conn),
        &mut Context::from_waker(Waker::noop()),
        &mut buf,
    );
    match ready {
        Poll::Ready(Ok(())) => buf.filled().to_vec(),
        _ => Vec::new(),
    }
}

/// A client-side smoltcp peer driven against a [`NetStack`] through its source and sink.
struct RawPeer {
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    epoch: Instant,
    source: NetStackSource,
    sink: NetStackSink,
}

impl RawPeer {
    /// Starts a stack with `config` and a client at `client_ip` wired to it.
    fn start(config: NetStackConfig, client_ip: Ipv4Addr, seed: u64) -> (NetStackHandle, Self) {
        let (stack, handle) = NetStack::new(config);
        let (source, sink) = stack.split();
        let mut device = VirtualDevice::new(1360, usize::MAX, Arc::default());
        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = seed;
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 32));
        });
        let peer = Self {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            epoch: Instant::now(),
            source,
            sink,
        };
        (handle, peer)
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(i64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(0))
    }

    /// Opens a client socket to `server:port` from `local_port`.
    fn connect(
        &mut self,
        server: Ipv4Addr,
        port: u16,
        local_port: u16,
    ) -> Result<SocketHandle, Box<dyn Error>> {
        let rx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
        let mut socket = client_tcp::Socket::new(rx_buf, tx_buf);
        socket.connect(
            self.iface.context(),
            (IpAddress::Ipv4(server), port),
            IpListenEndpoint {
                addr: None,
                port: local_port,
            },
        )?;
        Ok(self.sockets.add(socket))
    }

    fn socket(&mut self, handle: SocketHandle) -> &mut client_tcp::Socket<'static> {
        self.sockets.get_mut::<client_tcp::Socket<'static>>(handle)
    }

    fn state(&self, handle: SocketHandle) -> tcp::State {
        self.sockets.get::<client_tcp::Socket<'_>>(handle).state()
    }

    /// Shuttles packets both ways once: stack egress into the client, client egress into
    /// the stack.
    async fn pump_once(&mut self) {
        while let Ok(packet) = self.source.rx.try_recv() {
            self.device.inject(packet);
        }
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        let packets: Vec<PacketBuf> = self.device.drain_tx().collect();
        for packet in packets {
            let _ = self.sink.send(packet, PeerId::new(0)).await;
        }
    }

    /// Shuttles packets for `ticks` short ticks.
    async fn pump(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.pump_once().await;
            sleep(Duration::from_millis(5)).await;
        }
    }

    /// Pumps until `ready` holds, for at most five seconds.
    async fn pump_until(&mut self, ready: impl Fn(&Self) -> bool + Sync) -> TestResult {
        timeout(Duration::from_secs(5), async {
            while !ready(self) {
                self.pump(1).await;
            }
        })
        .await
        .map_err(|_| "TCP state should converge")?;
        Ok(())
    }
}

#[tokio::test]
async fn stopped_stack_releases_its_queues_and_handles() -> TestResult {
    let server: SocketAddr = "169.254.53.53:53".parse()?;
    let (stack, handle) = NetStack::new(config(Ipv4Addr::new(169, 254, 53, 53)));
    let (mut source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let packet = build_udp("100.64.0.2:12345".parse()?, server, &[1]).ok_or("build")?;
    sink.send(packet, PeerId::new(0)).await?;
    // Prove the UDP path is running before stopping the stack.
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;

    drop(sink);
    for _ in 0..2 {
        let error = timeout(WAIT, source.recv())
            .await?
            .err()
            .ok_or("source must end")?;
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }
    assert_eq!(
        timeout(WAIT, flow.recv()).await?.as_deref(),
        Some(&[1u8][..])
    );
    assert!(timeout(WAIT, flow.recv()).await?.is_none());
    assert!(timeout(WAIT, next(&mut incoming)).await?.is_none());
    let error = flow.send(b"late").await.err().ok_or("send must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    let error = handle
        .connect_tcp("169.254.53.1:80".parse()?)
        .await
        .err()
        .ok_or("connect must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

#[tokio::test]
async fn dropped_source_stops_the_stack() -> TestResult {
    let (stack, _handle) = NetStack::new(config(Ipv4Addr::new(10, 0, 0, 1)));
    let (source, sink) = stack.split();
    drop(source);
    let result = timeout(WAIT, async {
        loop {
            let packet = PacketBuf::from_packet(&[0x45]);
            if let Err(error) = sink.send(packet, PeerId::new(0)).await {
                return error;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert_eq!(result.kind(), io::ErrorKind::BrokenPipe);
    Ok(())
}

#[tokio::test]
async fn second_incoming_call_ends_immediately() -> TestResult {
    let (_stack, handle) = NetStack::new(config(Ipv4Addr::new(10, 0, 0, 1)));
    let _first = handle.incoming_tcp();
    assert!(
        timeout(WAIT, next(&mut handle.clone().incoming_tcp()))
            .await?
            .is_none()
    );
    let _first = handle.incoming_udp();
    assert!(
        timeout(WAIT, next(&mut handle.incoming_udp()))
            .await?
            .is_none()
    );
    Ok(())
}

#[test]
fn classify_counts_every_reject() -> TestResult {
    let settings = Settings::new(config(Ipv4Addr::new(10, 0, 0, 1)));
    let ours: SocketAddr = "10.0.0.1:53".parse()?;
    let theirs: SocketAddr = "10.0.0.2:5353".parse()?;
    let udp = build_udp(theirs, ours, b"x").ok_or("build")?;
    assert_eq!(classify(udp.as_packet(), &settings), Ok(Class::Udp));
    let elsewhere = build_udp(theirs, "10.0.0.9:53".parse()?, b"x").ok_or("build")?;
    assert_eq!(
        classify(elsewhere.as_packet(), &settings),
        Err(Reject::NoAddress)
    );
    assert_eq!(classify(&[0x45, 0], &settings), Err(Reject::Malformed));
    let mut icmp = udp.as_packet().to_vec();
    icmp[9] = protocol::ICMP;
    assert_eq!(classify(&icmp, &settings), Err(Reject::Unsupported));
    let mut fragment = udp.as_packet().to_vec();
    fragment[6] = 0x20; // More fragments.
    assert_eq!(classify(&fragment, &settings), Err(Reject::Unsupported));
    let mut truncated_tcp = udp.as_packet()[..22].to_vec();
    truncated_tcp[2..4].copy_from_slice(&22u16.to_be_bytes());
    truncated_tcp[9] = protocol::TCP;
    assert_eq!(classify(&truncated_tcp, &settings), Err(Reject::Malformed));
    Ok(())
}
