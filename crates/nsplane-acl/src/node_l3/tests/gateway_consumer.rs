use super::*;

fn runtime() -> Arc<NodeL3Gate> {
    let runtime = NodeL3Gate::new("machine-1");
    runtime
        .apply_from_source("source-a", config(NodeL3Mode::Enforce, false))
        .unwrap();
    runtime
        .replace_transport_projection(&gateway_projection(Some("gateway-public")))
        .unwrap();
    runtime
}

#[test]
fn gateway_consumer_is_only_a_candidate_and_never_an_l3_allow() {
    let runtime = runtime();
    for packet in [
        tcp(SERVICE_VIP, LOCAL, 18890, 49152, 0x12),
        udp(SERVICE_VIP, LOCAL, 19999, 49152),
    ] {
        assert_eq!(
            runtime.evaluate_inbound([9; 32], &packet),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::SourceBinding,
            }
        );
        let candidate = runtime.gateway_consumer_packet([9; 32], &packet).unwrap();
        assert_eq!(candidate.packet(), &packet);
        assert_eq!(candidate.authority().gateway_id(), "gateway-public");
        assert_eq!(candidate.authority().source_id(), "source-a");
        assert!(runtime.gateway_consumer_authority_current(candidate.authority()));
        assert_eq!(
            runtime.evaluate_inbound([9; 32], &packet),
            NodeL3Decision::Enforce {
                allow: false,
                reason: NodeL3Reason::SourceBinding,
            }
        );
    }
}

#[test]
fn candidate_rejects_unknown_peer_node_sources_wrong_destination_and_malformed_packets() {
    let runtime = runtime();
    let packet = tcp(SERVICE_VIP, LOCAL, 18890, 49152, 0x12);
    assert!(runtime.gateway_consumer_packet([8; 32], &packet).is_none());
    for source in [LOCAL, REMOTE] {
        assert!(
            runtime
                .gateway_consumer_packet([9; 32], &tcp(source, LOCAL, 18890, 49152, 0x12))
                .is_none()
        );
    }
    assert!(
        runtime
            .gateway_consumer_packet([9; 32], &tcp(SERVICE_VIP, REMOTE, 18890, 49152, 0x12))
            .is_none()
    );
    assert!(
        runtime
            .gateway_consumer_packet([9; 32], &packet[..24])
            .is_none()
    );
    assert!(
        runtime
            .gateway_consumer_packet([9; 32], &icmp_error(SERVICE_VIP, LOCAL, &packet))
            .is_none()
    );
}

#[test]
fn candidate_expires_on_policy_or_transport_replacement_and_withdrawal() {
    let runtime = runtime();
    let packet = tcp(SERVICE_VIP, LOCAL, 18890, 49152, 0x12);
    let old = runtime.gateway_consumer_packet([9; 32], &packet).unwrap();
    let mut policy = config(NodeL3Mode::Enforce, false);
    policy.generation = 2;
    runtime.apply_from_source("source-a", policy).unwrap();
    assert!(!runtime.gateway_consumer_authority_current(old.authority()));
    let old = runtime.gateway_consumer_packet([9; 32], &packet).unwrap();
    runtime
        .stage_transport_projection(&gateway_projection(Some("gateway-public")))
        .unwrap();
    assert!(!runtime.gateway_consumer_authority_current(old.authority()));
    assert!(runtime.gateway_consumer_packet([9; 32], &packet).is_none());
    runtime
        .replace_transport_projection(&gateway_projection(Some("gateway-public")))
        .unwrap();
    let new = runtime.gateway_consumer_packet([9; 32], &packet).unwrap();
    assert!(!new.authority().same_snapshot(old.authority()));
    runtime.withdraw_transport_projection();
    assert!(!runtime.gateway_consumer_authority_current(new.authority()));
}

#[test]
fn candidate_requires_explicit_gateway_identity_and_enforce_policy() {
    let runtime = runtime();
    let packet = udp(SERVICE_VIP, LOCAL, 19999, 49152);
    runtime
        .replace_transport_projection(&gateway_projection(None))
        .unwrap();
    assert!(runtime.gateway_consumer_packet([9; 32], &packet).is_none());
    let runtime = NodeL3Gate::new("machine-1");
    runtime.apply(config(NodeL3Mode::Observe, false)).unwrap();
    runtime
        .replace_transport_projection(&gateway_projection(Some("gateway-public")))
        .unwrap();
    assert!(runtime.gateway_consumer_packet([9; 32], &packet).is_none());
}

#[test]
fn fragments_capture_peer_identity_but_do_not_grant_orphan_l3_access() {
    let runtime = runtime();
    let mut projection = gateway_projection(Some("gateway-public"));
    let mut other = projection.peers[0].clone();
    other.public_key = [8; 32];
    projection.peers.push(other);
    runtime.replace_transport_projection(&projection).unwrap();
    let packet = later_fragment(SERVICE_VIP, LOCAL, 42);
    let first = runtime.gateway_consumer_packet([9; 32], &packet).unwrap();
    let other = runtime.gateway_consumer_packet([8; 32], &packet).unwrap();
    assert!(!first.authority().same_snapshot(other.authority()));
    assert_eq!(
        runtime.evaluate_inbound([9; 32], &packet),
        NodeL3Decision::Enforce {
            allow: false,
            reason: NodeL3Reason::OrphanFragment,
        }
    );
}
