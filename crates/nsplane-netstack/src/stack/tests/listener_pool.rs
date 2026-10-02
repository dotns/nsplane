use super::*;

/// The ns per-port and global listener ceilings; both are the configured pool size.
const MAX_LISTENERS_PER_PORT: usize = 32;
const MAX_LISTENERS_TOTAL: usize = 32;
const POOL: Pool = Pool {
    limit: MAX_LISTENERS_TOTAL,
    buffer: 4096,
};

type Listeners = HashMap<u16, Vec<SocketHandle>>;

fn pool(listeners: &Listeners, port: u16) -> Vec<SocketHandle> {
    listeners.get(&port).cloned().unwrap_or_default()
}

fn state(sockets: &SocketSet<'_>, handle: SocketHandle) -> tcp::State {
    sockets.get::<tcp::Socket<'_>>(handle).state()
}

/// Records a packet's listener demand, then hands it to the device (the driver's ingest
/// step for TCP).
fn account_and_inject(
    packet: PacketBuf,
    demand: &mut HashMap<u16, usize>,
    device: &mut VirtualDevice,
) {
    if let Some(dst_port) = tcp_dst_port(packet.as_packet())
        && tcp_is_syn(packet.as_packet())
    {
        *demand.entry(dst_port).or_insert(0) += 1;
    }
    device.inject(packet);
}

#[test]
fn terminal_receive_refreshes_idle_only_for_new_socket_bytes() {
    let mut activity = SmolInstant::from_secs(0);
    record_receive_activity(1024, &mut activity, SmolInstant::from_secs(299));
    assert_eq!(activity, SmolInstant::from_secs(299));
    for state in [tcp::State::Closed, tcp::State::TimeWait] {
        assert!(!tcp_terminal_ready(
            state,
            true,
            activity,
            SmolInstant::from_secs(300)
        ));
        assert!(!tcp_terminal_ready(
            state,
            true,
            activity,
            SmolInstant::from_secs(598)
        ));
        record_receive_activity(0, &mut activity, SmolInstant::from_secs(598));
        assert_eq!(activity, SmolInstant::from_secs(299));
        assert!(tcp_terminal_ready(
            state,
            true,
            activity,
            SmolInstant::from_secs(599)
        ));
    }
}

#[test]
fn ipv6_tcp_listener_demand_checks_direct_and_hop_by_hop_headers() {
    let mut packet = vec![0_u8; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
    packet[6] = 6;
    packet[42..44].copy_from_slice(&51900_u16.to_be_bytes());
    packet[53] = 2;
    assert_eq!(tcp_dst_port(&packet), Some(51900));
    assert!(tcp_is_syn(&packet));
    let mut with_extension = packet[..40].to_vec();
    with_extension[6] = 0;
    with_extension[4..6].copy_from_slice(&28_u16.to_be_bytes());
    with_extension.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
    with_extension.extend_from_slice(&packet[40..]);
    assert_eq!(tcp_dst_port(&with_extension), Some(51900));
    assert!(tcp_is_syn(&with_extension));
    with_extension[41] = 255;
    assert_eq!(tcp_dst_port(&with_extension), None);
    for end in 0..packet.len() {
        assert_eq!(tcp_dst_port(&packet[..end]), None);
        assert!(!tcp_is_syn(&packet[..end]));
    }
    packet[53] |= 16;
    assert!(!tcp_is_syn(&packet));
    for next_header in [17, 44, 59] {
        packet[6] = next_header;
        assert_eq!(tcp_dst_port(&packet), None);
        assert!(!tcp_is_syn(&packet));
    }
}

#[test]
fn terminal_tcp_waits_for_receive_drain_without_losing_idle_limit() {
    let at = SmolInstant::from_secs(1000);
    let before = SmolInstant::from_secs(1299);
    let deadline = SmolInstant::from_secs(1300);
    for state in [tcp::State::Closed, tcp::State::TimeWait] {
        assert!(tcp_terminal_ready(state, false, at, at));
        assert!(!tcp_terminal_ready(state, true, at, before));
        assert!(tcp_terminal_ready(state, true, at, deadline));
        assert!(!tcp_terminal_ready(state, true, before, deadline));
    }
    assert!(!tcp_terminal_ready(
        tcp::State::Established,
        false,
        at,
        deadline
    ));
}

#[test]
fn ensure_tcp_listeners_drops_a_stale_socket() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let port: u16 = 5201;

    ensure_tcp_listeners(port, 1, &mut listeners, &mut sockets, POOL);
    let first = pool(&listeners, port);
    assert_eq!(first.len(), 1);
    assert_eq!(state(&sockets, first[0]), tcp::State::Listen);

    sockets.get_mut::<tcp::Socket<'_>>(first[0]).abort();

    ensure_tcp_listeners(port, 1, &mut listeners, &mut sockets, POOL);
    let second = pool(&listeners, port);
    assert_eq!(
        second.len(),
        1,
        "the dead socket must not linger in the pool"
    );
    // The handle value carries no identity here (`SocketSet` reuses the slot it just
    // freed), so the invariant is the state: the port is listening again.
    assert_eq!(state(&sockets, second[0]), tcp::State::Listen);
}

#[test]
fn ensure_tcp_listeners_adds_nothing_when_demand_is_already_free() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let port: u16 = 5201;

    ensure_tcp_listeners(port, 1, &mut listeners, &mut sockets, POOL);
    let first = pool(&listeners, port);

    ensure_tcp_listeners(port, 1, &mut listeners, &mut sockets, POOL);

    assert_eq!(
        pool(&listeners, port),
        first,
        "a free Listen socket already covers a demand of one"
    );
}

/// The pool is sized to the batch's SYN count: N simultaneous SYNs need N sockets in
/// `Listen` *before* the poll runs, or the surplus is RST.
#[test]
fn ensure_tcp_listeners_grows_to_the_syn_count() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let port: u16 = 8080;

    ensure_tcp_listeners(port, 12, &mut listeners, &mut sockets, POOL);

    let handles = pool(&listeners, port);
    assert_eq!(handles.len(), 12);
    assert!(
        handles
            .iter()
            .all(|&h| state(&sockets, h) == tcp::State::Listen),
        "every socket in the pool must be free to accept a SYN"
    );
}

/// Memory stays bounded: a SYN flood cannot grow the pool past its cap, and the excess
/// is refused.
#[test]
fn ensure_tcp_listeners_is_capped_per_port() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let port: u16 = 8080;

    ensure_tcp_listeners(
        port,
        MAX_LISTENERS_PER_PORT * 4,
        &mut listeners,
        &mut sockets,
        POOL,
    );

    assert_eq!(pool(&listeners, port).len(), MAX_LISTENERS_PER_PORT);
}

#[test]
fn ensure_tcp_listeners_is_capped_across_ports() -> TestResult {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);

    // Enough ports, each demanding its per-port cap, to blow the global one.
    let ports = (MAX_LISTENERS_TOTAL / MAX_LISTENERS_PER_PORT) + 4;
    for i in 0..ports {
        let port = 9000 + u16::try_from(i)?;
        ensure_tcp_listeners(
            port,
            MAX_LISTENERS_PER_PORT,
            &mut listeners,
            &mut sockets,
            POOL,
        );
    }

    let total: usize = listeners.values().map(Vec::len).sum();
    assert_eq!(total, MAX_LISTENERS_TOTAL);
    Ok(())
}

#[test]
fn prepare_tcp_listeners_reclaims_surplus_before_fair_allocation() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let burst_port = 8000;
    let single_port = 9000;
    let mut allocation_cursor = 0;

    ensure_tcp_listeners(
        burst_port,
        MAX_LISTENERS_PER_PORT,
        &mut listeners,
        &mut sockets,
        POOL,
    );

    let demand = HashMap::from([(burst_port, MAX_LISTENERS_PER_PORT), (single_port, 1)]);
    let refused = prepare_tcp_listeners(
        &demand,
        &mut allocation_cursor,
        &mut listeners,
        &mut sockets,
        POOL,
    );

    assert_eq!(pool(&listeners, single_port).len(), 1);
    assert_eq!(pool(&listeners, burst_port).len(), MAX_LISTENERS_TOTAL - 1);
    assert_eq!(
        listeners.values().map(Vec::len).sum::<usize>(),
        MAX_LISTENERS_TOTAL
    );
    assert_eq!(refused, 1, "one SYN of the burst finds no socket");
}

#[test]
fn prepare_tcp_listeners_prunes_terminal_socket_on_untouched_port() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let terminal_port = 7000;
    let demanded_port = 8000;
    let mut allocation_cursor = 0;

    ensure_tcp_listeners(terminal_port, 1, &mut listeners, &mut sockets, POOL);
    let terminal_handle = pool(&listeners, terminal_port)[0];
    sockets.get_mut::<tcp::Socket<'_>>(terminal_handle).abort();

    prepare_tcp_listeners(
        &HashMap::from([(demanded_port, 1)]),
        &mut allocation_cursor,
        &mut listeners,
        &mut sockets,
        POOL,
    );

    assert!(!listeners.contains_key(&terminal_port));
    assert_eq!(pool(&listeners, demanded_port).len(), 1);
}

#[test]
fn prepare_tcp_listeners_rotates_an_overfull_batch_across_calls() -> TestResult {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let mut allocation_cursor = 0;
    let mut demand: HashMap<u16, usize> = HashMap::new();
    for i in 0..(MAX_LISTENERS_TOTAL + 8) {
        demand.insert(10_000 + u16::try_from(i)?, 1);
    }

    let refused = prepare_tcp_listeners(
        &demand,
        &mut allocation_cursor,
        &mut listeners,
        &mut sockets,
        POOL,
    );
    assert_eq!(refused, 8);
    let first: Vec<u16> = listeners.keys().copied().collect();
    assert_eq!(first.len(), MAX_LISTENERS_TOTAL);

    prepare_tcp_listeners(
        &demand,
        &mut allocation_cursor,
        &mut listeners,
        &mut sockets,
        POOL,
    );
    let second: Vec<u16> = listeners.keys().copied().collect();
    assert_eq!(second.len(), MAX_LISTENERS_TOTAL);

    let mut served = first;
    served.extend(second);
    served.sort_unstable();
    served.dedup();
    assert_eq!(
        served.len(),
        demand.len(),
        "a repeated over-cap batch must eventually reserve every destination port"
    );
    Ok(())
}

#[test]
fn prepare_preserves_syn_received_and_accepts_an_immediate_fin() -> TestResult {
    let server_ip = Ipv4Addr::new(10, 11, 0, 1);
    let client_ip = Ipv4Addr::new(10, 11, 0, 2);
    let server_port = 8080;
    let now = SmolInstant::ZERO;

    let mut server_device = VirtualDevice::new(1360, usize::MAX, Arc::default());
    let mut server_config = Config::new(HardwareAddress::Ip);
    server_config.random_seed = 0x5151_5151;
    let mut server_iface = Interface::new(server_config, &mut server_device, now);
    server_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(server_ip), 32));
    });
    let mut server_sockets = SocketSet::new(vec![]);
    let mut listeners = Listeners::new();
    let mut allocation_cursor = 0;

    let mut client_device = VirtualDevice::new(1360, usize::MAX, Arc::default());
    let mut client_config = Config::new(HardwareAddress::Ip);
    client_config.random_seed = 0x6161_6161;
    let mut client_iface = Interface::new(client_config, &mut client_device, now);
    client_iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(client_ip), 32));
    });
    let mut client_sockets = SocketSet::new(vec![]);
    let rx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
    let tx_buf = client_tcp::SocketBuffer::new(vec![0u8; 4096]);
    let mut client_socket = client_tcp::Socket::new(rx_buf, tx_buf);
    client_socket.connect(
        client_iface.context(),
        (IpAddress::Ipv4(server_ip), server_port),
        IpListenEndpoint {
            addr: None,
            port: 49_152,
        },
    )?;
    let client_handle = client_sockets.add(client_socket);

    client_iface.poll(now, &mut client_device, &mut client_sockets);
    let mut syn_demand = HashMap::new();
    let packets: Vec<PacketBuf> = client_device.drain_tx().collect();
    for packet in packets {
        account_and_inject(packet, &mut syn_demand, &mut server_device);
    }
    prepare_tcp_listeners(
        &syn_demand,
        &mut allocation_cursor,
        &mut listeners,
        &mut server_sockets,
        POOL,
    );
    server_iface.poll(now, &mut server_device, &mut server_sockets);

    let listener_handle = pool(&listeners, server_port)[0];
    assert_eq!(
        state(&server_sockets, listener_handle),
        tcp::State::SynReceived
    );

    let mut pressure: HashMap<u16, usize> = HashMap::new();
    for i in 0..(MAX_LISTENERS_TOTAL + 8) {
        pressure.insert(20_000 + u16::try_from(i)?, 1);
    }
    prepare_tcp_listeners(
        &pressure,
        &mut allocation_cursor,
        &mut listeners,
        &mut server_sockets,
        POOL,
    );
    assert!(pool(&listeners, server_port).contains(&listener_handle));
    assert_eq!(
        state(&server_sockets, listener_handle),
        tcp::State::SynReceived
    );

    let packets: Vec<PacketBuf> = server_device.drain_tx().collect();
    for packet in packets {
        client_device.inject(packet);
    }
    client_iface.poll(now, &mut client_device, &mut client_sockets);
    client_sockets
        .get_mut::<client_tcp::Socket<'_>>(client_handle)
        .close();
    client_iface.poll(now, &mut client_device, &mut client_sockets);

    let mut final_demand = HashMap::new();
    let packets: Vec<PacketBuf> = client_device.drain_tx().collect();
    for packet in packets {
        account_and_inject(packet, &mut final_demand, &mut server_device);
    }
    prepare_tcp_listeners(
        &final_demand,
        &mut allocation_cursor,
        &mut listeners,
        &mut server_sockets,
        POOL,
    );
    server_iface.poll(now, &mut server_device, &mut server_sockets);

    let state = state(&server_sockets, listener_handle);
    assert_eq!(state, tcp::State::CloseWait);
    assert!(tcp_listener_ready_for_promotion(state));
    Ok(())
}

#[test]
fn tcp_idle_timeout_reaps_idle_connections_but_preserves_active_ones() {
    let opened_at = SmolInstant::from_secs(1_000);
    let before_deadline = SmolInstant::from_secs(1_299);
    let deadline = SmolInstant::from_secs(1_300);

    assert!(!tcp_idle_timeout_expired(
        tcp::State::Established,
        opened_at,
        before_deadline
    ));
    assert!(tcp_idle_timeout_expired(
        tcp::State::Established,
        opened_at,
        deadline
    ));
    assert!(
        !tcp_idle_timeout_expired(tcp::State::Established, before_deadline, deadline),
        "application activity must extend the socket lifetime"
    );
    assert!(
        tcp_idle_timeout_expired(tcp::State::CloseWait, opened_at, deadline),
        "a peer that half-closed must not bypass the idle lifetime"
    );
    assert!(
        tcp_idle_timeout_expired(tcp::State::FinWait2, opened_at, deadline),
        "a locally half-closed connection must not bypass the idle lifetime"
    );
    assert!(
        !tcp_idle_timeout_expired(tcp::State::TimeWait, opened_at, deadline),
        "smoltcp owns the terminal TIME-WAIT timer"
    );
}

#[test]
fn listener_socket_keeps_tcp_keep_alive_disabled() {
    let mut listeners = Listeners::new();
    let mut sockets: SocketSet<'_> = SocketSet::new(vec![]);
    let port: u16 = 5201;

    ensure_tcp_listeners(port, 1, &mut listeners, &mut sockets, POOL);
    let handle = pool(&listeners, port)[0];

    assert_eq!(sockets.get::<tcp::Socket<'_>>(handle).keep_alive(), None);
}

#[test]
fn tcp_is_syn_matches_only_a_bare_syn() {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[9] = 6;
    pkt[33] = 0x02; // SYN
    assert!(tcp_is_syn(&pkt));
    pkt[33] = 0x12; // SYN-ACK: the reply to a connection the stack opened
    assert!(!tcp_is_syn(&pkt));
    pkt[33] = 0x10; // ACK
    assert!(!tcp_is_syn(&pkt));
}
