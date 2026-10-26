//! Shared setup of the `Redirect` tests: a client and a service netstack joined by a redirect.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use nsplane::{PacketBuf, PacketSink, PacketSource};
use nsplane_nat::{Redirect, RedirectVerdict};
use nsplane_netstack::{DEFAULT_MTU, NetStack, NetStackConfig, NetStackHandle};
use nsplane_packet::PeerId;

use crate::TestResult;

/// The client's address.
pub const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// The address of the stack the flows are redirected to.
pub const STACK: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);

/// The client, the service stack and the redirect between them.
#[derive(Debug)]
pub struct Rig {
    /// The client's stack.
    pub client: NetStackHandle,
    /// The stack the flows are redirected to.
    pub stack: NetStackHandle,
    /// The redirect between them.
    pub redirect: Arc<Redirect>,
    /// Calls of the decision closure.
    pub decisions: Arc<AtomicUsize>,
}

/// Starts the client at [`CLIENT`] and the stack at [`STACK`] with `redirect` between them.
///
/// Client packets go through `Redirect::forward`, the stack's through `Redirect::reverse`.
/// `decisions` counts the calls of `redirect`'s decision closure.
pub fn start_rig(redirect: Arc<Redirect>, decisions: Arc<AtomicUsize>) -> Rig {
    let (client_stack, client) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(CLIENT), 32)],
        DEFAULT_MTU,
    ));
    let (stack_stack, stack) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(STACK), 32)],
        DEFAULT_MTU,
    ));
    let (client_out, client_in) = client_stack.split();
    let (stack_out, stack_in) = stack_stack.split();
    pump(
        client_out,
        stack_in,
        Arc::clone(&redirect),
        Redirect::forward,
    );
    pump(
        stack_out,
        client_in,
        Arc::clone(&redirect),
        Redirect::reverse,
    );
    Rig {
        client,
        stack,
        redirect,
        decisions,
    }
}

/// Moves packets from `from` to `to` through `step` until either side stops, as the local
/// path would: rewritten and passed packets go on, dropped ones do not.
fn pump<S, K>(
    mut from: S,
    to: K,
    redirect: Arc<Redirect>,
    step: fn(&Redirect, &mut PacketBuf) -> RedirectVerdict,
) where
    S: PacketSource + Send + 'static,
    K: PacketSink + Send + Sync + 'static,
{
    tokio::spawn(async move {
        while let Ok(mut packet) = from.recv().await {
            if matches!(step(&redirect, &mut packet), RedirectVerdict::Drop(_)) {
                continue;
            }
            if to.send(packet, PeerId::new(0)).await.is_err() {
                break;
            }
        }
    });
}

/// `addr` as an IPv4 socket address.
pub fn v4(addr: SocketAddr) -> TestResult<SocketAddrV4> {
    match addr {
        SocketAddr::V4(addr) => Ok(addr),
        SocketAddr::V6(addr) => Err(format!("IPv6 address {addr}").into()),
    }
}
