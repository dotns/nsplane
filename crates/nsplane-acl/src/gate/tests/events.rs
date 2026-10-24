//! Decision events: what emits, the token bucket, a full channel and
//! replacement.

use std::net::SocketAddr;
use std::time::Instant;

use super::*;

/// A gate with `policy` whose clock is the returned manual time.
fn manual_gate(policy: GatePolicy) -> (Arc<FlowGate>, Arc<Mutex<Instant>>) {
    let clock = Arc::new(Mutex::new(Instant::now()));
    let read = Arc::clone(&clock);
    let gate = FlowGate::with_clock(GateConfig::default(), move || *read.lock().unwrap());
    gate.replace(policy).expect("the policy is valid");
    (gate, clock)
}

/// An enforcing scope granting `remote` inbound TCP to port 22 only.
fn ssh_only(mode: GateMode) -> GatePolicy {
    policy(vec![scope(
        "scope-1",
        mode,
        vec![grant(
            "ssh",
            Direction::Inbound,
            &["remote"],
            vec![host(LOCAL)],
            vec![tcp_port(22)],
        )],
    )])
}

fn socket(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

/// Deny `count` new inbound flows (TCP SYNs to port 23 from distinct ports).
fn deny_flows(gate: &FlowGate, count: u16) {
    for port in 0..count {
        assert_eq!(
            gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 50_000 + port, 23, 0x02)),
            denied(GateReason::NoGrant)
        );
    }
}

#[test]
fn events_off_emit_nothing_and_count_nothing() {
    let (gate, _clock) = manual_gate(ssh_only(GateMode::Enforce));
    deny_flows(&gate, 3);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (0, 0));

    let events = gate.enable_events(GateEventsConfig::default());
    gate.disable_events();
    deny_flows(&gate, 3);
    assert_eq!(events.recv(), None, "disabling disconnects the receiver");
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (0, 0));
    assert_eq!(counters.enforced_denied, 6);
}

#[test]
fn new_flow_decisions_emit_one_event_each() {
    let (gate, clock) = manual_gate(ssh_only(GateMode::Enforce));
    let events = gate.enable_events(GateEventsConfig::default());
    let start = *clock.lock().unwrap();

    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x02)),
        granted("ssh")
    );
    assert_eq!(
        events.try_recv(),
        Some(GateEvent {
            at: start,
            peer: PEER,
            protocol: 6,
            src: socket(REMOTE, 40_000),
            dst: socket(LOCAL, 22),
            allow: true,
            enforced: true,
            reason: GateReason::Granted,
            rule: Some(RuleId::from("ssh")),
        })
    );

    // Packets of the existing flow, either way, do not emit.
    assert_eq!(
        gate.evaluate_outbound(PEER, &tcp(LOCAL, REMOTE, 22, 40_000, 0x12)),
        valid()
    );
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 22, 0x10)),
        valid()
    );
    assert_eq!(events.try_recv(), None);

    *clock.lock().unwrap() += Duration::from_secs(1);
    assert_eq!(
        gate.evaluate_inbound(PEER, &udp(REMOTE, LOCAL, 5353, 53)),
        denied(GateReason::NoGrant)
    );
    assert_eq!(
        events.try_recv(),
        Some(GateEvent {
            at: start + Duration::from_secs(1),
            peer: PEER,
            protocol: 17,
            src: socket(REMOTE, 5353),
            dst: socket(LOCAL, 53),
            allow: false,
            enforced: true,
            reason: GateReason::NoGrant,
            rule: None,
        })
    );
    // A reply-only packet without state is a denial too.
    assert_eq!(
        gate.evaluate_inbound(PEER, &icmp(REMOTE, LOCAL, 0, 9)),
        denied(GateReason::ReverseNewFlow)
    );
    let event = events.try_recv().expect("a denial emits");
    assert_eq!(
        (event.protocol, event.src, event.dst, event.reason),
        (
            1,
            socket(REMOTE, 0),
            socket(LOCAL, 0),
            GateReason::ReverseNewFlow
        )
    );
    assert_eq!(events.try_recv(), None);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (3, 0));
}

#[test]
fn observed_denials_emit_unenforced_events() {
    let (gate, _clock) = manual_gate(ssh_only(GateMode::Observe));
    let events = gate.enable_events(GateEventsConfig::default());
    assert_eq!(
        gate.evaluate_inbound(PEER, &tcp(REMOTE, LOCAL, 40_000, 23, 0x02)),
        observe(false, GateReason::NoGrant, None)
    );
    let event = events.try_recv().expect("an observed denial emits");
    assert_eq!(
        (event.allow, event.enforced, event.reason),
        (false, false, GateReason::NoGrant)
    );
}

#[test]
fn the_token_bucket_limits_emission_and_refills_with_the_clock() {
    let (gate, clock) = manual_gate(ssh_only(GateMode::Enforce));
    let events = gate.enable_events(GateEventsConfig {
        rate: 10,
        burst: 3,
        ..GateEventsConfig::default()
    });
    deny_flows(&gate, 5);
    assert_eq!(events.drain().count(), 3);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (3, 2));

    // 100 ms at 10 per second refill one token.
    *clock.lock().unwrap() += Duration::from_millis(100);
    deny_flows(&gate, 2);
    assert_eq!(events.drain().count(), 1);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (4, 3));

    // The bucket refills up to its burst only.
    *clock.lock().unwrap() += Duration::from_secs(60);
    deny_flows(&gate, 5);
    assert_eq!(events.drain().count(), 3);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (7, 5));
}

#[test]
fn a_full_channel_drops_events() {
    let (gate, _clock) = manual_gate(ssh_only(GateMode::Enforce));
    let events = gate.enable_events(GateEventsConfig {
        capacity: 2,
        ..GateEventsConfig::default()
    });
    deny_flows(&gate, 5);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (2, 3));
    assert_eq!(events.drain().count(), 2);
    deny_flows(&gate, 1);
    assert_eq!(events.drain().count(), 1);
}

#[test]
fn enabling_again_replaces_the_receiver() {
    let (gate, _clock) = manual_gate(ssh_only(GateMode::Enforce));
    let first = gate.enable_events(GateEventsConfig::default());
    deny_flows(&gate, 1);
    let second = gate.enable_events(GateEventsConfig::default());
    deny_flows(&gate, 1);
    assert!(first.recv().is_some(), "buffered events are still received");
    assert_eq!(first.recv(), None);
    assert!(second.try_recv().is_some());

    // A gone receiver counts every event as dropped.
    drop(second);
    deny_flows(&gate, 1);
    let counters = gate.counters();
    assert_eq!((counters.events_emitted, counters.events_dropped), (2, 1));
}
