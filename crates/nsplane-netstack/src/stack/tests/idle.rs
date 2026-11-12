//! The driver's periodic turn: kept while a TCP socket exists, absent on a stack without
//! one.

use std::sync::atomic::Ordering;

use super::abort::pump_while;
use super::*;

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 9, 31, 1);
const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 31, 2);
/// Several periods of the driver's periodic turn.
const QUIET: Duration = Duration::from_millis(400);

/// The driver turns of the stack behind `handle` so far.
fn turns(handle: &NetStackHandle) -> u64 {
    handle.stats.turns.load(Ordering::Relaxed)
}

#[tokio::test]
async fn a_stack_without_tcp_sockets_takes_no_turn_until_woken() -> TestResult {
    let (stack, handle) = NetStack::new(config(SERVER));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    sleep(Duration::from_millis(100)).await;
    let before = turns(&handle);
    sleep(QUIET).await;
    assert_eq!(turns(&handle), before, "an empty stack should sleep");

    // Ingress still wakes it at once.
    let server = SocketAddr::new(SERVER.into(), 53);
    let packet = build_udp("10.9.31.2:40000".parse()?, server, &[1]).ok_or("build")?;
    sink.send(packet, PeerId::new(0)).await?;
    let flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert!(turns(&handle) > before);

    // A UDP flow needs no timer either.
    sleep(Duration::from_millis(100)).await;
    let before = turns(&handle);
    sleep(QUIET).await;
    assert_eq!(
        turns(&handle),
        before,
        "a stack with UDP flows should sleep"
    );
    drop(flow);
    Ok(())
}

#[tokio::test]
async fn the_periodic_turn_runs_while_a_connection_exists_and_stops_after_it() -> TestResult {
    let (handle, mut peer) = RawPeer::start(config(SERVER), CLIENT, 0x1d1e);
    let mut incoming = handle.incoming_tcp();
    peer.connect(SERVER, 80, 49_152)?;
    let conn = pump_while(&mut peer, &mut Box::pin(next(&mut incoming)))
        .await?
        .ok_or("the stack stopped")?;
    peer.pump(4).await;

    // Nothing arrives and nothing is written: only the periodic turn is left, the guard
    // that bridges a connection at least every 50 ms.
    let before = turns(&handle);
    sleep(QUIET).await;
    let periodic = turns(&handle) - before;
    assert!(
        (4..=20).contains(&periodic),
        "{periodic} turns in {QUIET:?} with an idle connection"
    );

    // Released: no socket is left, and neither is the periodic turn.
    let mut terminal = conn.terminal();
    conn.abort();
    pump_while(
        &mut peer,
        &mut Box::pin(terminal.wait_for(|terminal| *terminal)),
    )
    .await??;
    peer.pump(20).await;
    let before = turns(&handle);
    sleep(QUIET).await;
    assert_eq!(turns(&handle), before, "the stack should sleep again");
    Ok(())
}

#[tokio::test]
async fn a_stack_with_reassembly_keeps_its_periodic_turn() -> TestResult {
    let config = NetStackConfig {
        reassembly: Some(ReassemblyConfig::default()),
        ..config(SERVER)
    };
    let (_stack, handle) = NetStack::new(config);
    sleep(Duration::from_millis(100)).await;
    let before = turns(&handle);
    sleep(QUIET).await;
    assert!(
        turns(&handle) - before >= 4,
        "fragments expire on the periodic turn"
    );
    Ok(())
}
