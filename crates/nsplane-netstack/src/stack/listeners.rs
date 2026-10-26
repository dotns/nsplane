//! The pool of listening sockets for inbound connections.

use std::collections::HashMap;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;

use crate::config::TcpRto;

/// Socket pool limits: sockets per port and in total, and each socket's buffer sizes and
/// RTO bounds.
#[derive(Debug, Clone, Copy)]
pub(super) struct Pool {
    pub(super) limit: usize,
    pub(super) rx_buffer: usize,
    pub(super) tx_buffer: usize,
    pub(super) rto: TcpRto,
}

pub(super) const fn tcp_listener_ready_for_promotion(state: tcp::State) -> bool {
    matches!(state, tcp::State::Established | tcp::State::CloseWait)
}

/// A TCP socket tuned for relaying, with buffers of `rx_buffer` and `tx_buffer` bytes and
/// the RTO bounds `rto`.
///
/// smoltcp derives the window-scale shift from the receive buffer's capacity here.
pub(super) fn new_tcp_socket(
    rx_buffer: usize,
    tx_buffer: usize,
    rto: TcpRto,
) -> tcp::Socket<'static> {
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; rx_buffer]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; tx_buffer]);
    let mut socket = tcp::Socket::new(rx_buf, tx_buf);
    // smoltcp's default 10 ms delayed ACK withholds window updates until expiry, stalling
    // a far sender that filled the receive window (one ack delay per window over a
    // high-RTT overlay); Nagle adds an RTT of coalescing latency. A relay wants neither.
    socket.set_ack_delay(None);
    socket.set_nagle_enabled(false);
    socket.set_keep_alive(None);
    // Without congestion control smoltcp sends the whole peer window at once and, after a
    // timeout, all of it again; a path that drops part of such a burst (a full socket
    // buffer) loses the retransmission too and the timeouts double past 30 s. CUBIC
    // restarts from one segment after a timeout and backs off on loss.
    socket.set_congestion_control(tcp::CongestionControl::Cubic);
    socket.set_min_rto(rto.min);
    socket.set_initial_rto(rto.initial);
    socket
}

/// Computes fair free-listener targets for the complete current SYN batch, trims idle
/// sockets above those targets, then fills each target. Every port receives one socket
/// before any port receives a second one. `SynReceived` sockets are never reclaimed
/// because they own in-flight handshakes. Returns how many SYNs find no socket.
pub(super) fn prepare_tcp_listeners(
    demand: &HashMap<u16, usize>,
    allocation_cursor: &mut u16,
    listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    sockets: &mut SocketSet<'_>,
    pool: Pool,
) -> usize {
    let mut held_per_port: HashMap<u16, usize> = HashMap::new();
    let mut held_total = 0usize;
    for (&port, handles) in listeners.iter() {
        for &handle in handles {
            let state = sockets.get::<tcp::Socket<'_>>(handle).state();
            if !matches!(
                state,
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait
            ) {
                *held_per_port.entry(port).or_insert(0) += 1;
                held_total += 1;
            }
        }
    }

    let mut requests: Vec<(u16, usize)> = demand
        .iter()
        .map(|(&port, &want)| {
            let held = held_per_port.get(&port).copied().unwrap_or(0);
            (port, want.min(pool.limit.saturating_sub(held)))
        })
        .collect();
    requests.sort_unstable_by_key(|&(port, _)| port);
    if !requests.is_empty() {
        let start = requests.partition_point(|&(port, _)| port < *allocation_cursor);
        let request_count = requests.len();
        requests.rotate_left(start % request_count);
    }

    let mut targets: HashMap<u16, usize> = HashMap::new();
    let mut available = pool.limit.saturating_sub(held_total);
    let mut last_allocated_port = None;
    for target_free in 1..=pool.limit {
        let mut needed_this_round = false;
        for &(port, want) in &requests {
            if target_free > want {
                continue;
            }
            needed_this_round = true;
            if available == 0 {
                break;
            }
            targets.insert(port, target_free);
            available -= 1;
            last_allocated_port = Some(port);
        }
        if !needed_this_round || available == 0 {
            break;
        }
    }
    if let Some(port) = last_allocated_port {
        *allocation_cursor = port.wrapping_add(1);
    }
    let planned_total = held_total + targets.values().sum::<usize>();
    let mut refused = 0;
    for (&port, &want) in demand {
        let free = targets.get(&port).copied().unwrap_or(0);
        if free < want {
            refused += want - free;
            tracing::warn!(
                target: "netstack",
                port,
                demand = want,
                free,
                held = held_per_port.get(&port).copied().unwrap_or(0),
                total = planned_total,
                "TCP listener pool at its cap; excess SYNs will be refused"
            );
        }
    }

    let mut reclaimed = Vec::new();
    for (&port, handles) in listeners.iter_mut() {
        let keep_free = targets.get(&port).copied().unwrap_or(0);
        let mut free_kept = 0usize;
        handles.retain(|&handle| {
            match sockets.get::<tcp::Socket<'_>>(handle).state() {
                tcp::State::Listen if free_kept < keep_free => {
                    free_kept += 1;
                    true
                }
                tcp::State::Listen | tcp::State::Closed | tcp::State::TimeWait => {
                    reclaimed.push(handle);
                    false
                }
                // In-flight handshakes and sockets awaiting the two-phase promotion pass
                // own their handles and are never reclaimed.
                _ => true,
            }
        });
    }
    listeners.retain(|_, handles| !handles.is_empty());
    for handle in reclaimed {
        sockets.remove(handle);
    }

    for (port, target_free) in targets {
        ensure_tcp_listeners(port, target_free, listeners, sockets, pool);
    }
    refused
}

/// Holds at least `demand` sockets in `Listen` on `port`, so that many SYNs can be
/// accepted by the next poll.
///
/// Sockets already in `SynReceived` stay tracked (they are mid-handshake and will be
/// promoted) but do not count as free capacity: a SYN cannot land on them.
pub(super) fn ensure_tcp_listeners(
    port: u16,
    demand: usize,
    listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    sockets: &mut SocketSet<'_>,
    pool: Pool,
) {
    let handles = listeners.entry(port).or_default();
    let mut terminal_handles = Vec::new();
    handles.retain(|&handle| {
        let terminal = matches!(
            sockets.get::<tcp::Socket<'_>>(handle).state(),
            tcp::State::Closed | tcp::State::TimeWait
        );
        if terminal {
            terminal_handles.push(handle);
        }
        !terminal
    });
    for handle in terminal_handles {
        sockets.remove(handle);
    }
    let free = handles
        .iter()
        .filter(|&&handle| sockets.get::<tcp::Socket<'_>>(handle).state() == tcp::State::Listen)
        .count();
    let held = handles.len();

    let total: usize = listeners.values().map(Vec::len).sum();
    let headroom = pool
        .limit
        .saturating_sub(held)
        .min(pool.limit.saturating_sub(total));
    let add = demand.saturating_sub(free).min(headroom);
    if add < demand.saturating_sub(free) {
        tracing::warn!(
            target: "netstack",
            port,
            demand,
            free,
            held,
            total,
            "TCP listener pool at its cap; excess SYNs will be refused"
        );
    }

    let handles = listeners.entry(port).or_default();
    for _ in 0..add {
        let mut socket = new_tcp_socket(pool.rx_buffer, pool.tx_buffer, pool.rto);
        let _ = socket.listen(port);
        handles.push(sockets.add(socket));
    }
}
