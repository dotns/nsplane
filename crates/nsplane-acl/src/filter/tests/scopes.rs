//! Outbound source scopes and per-identity scopes.

use super::*;

/// A filter whose outbound sources are `LOCAL4/32` and `LOCAL/128`.
fn scoped(engine: &Arc<AclEngine>, config: AclFilterConfig) -> AclFilter {
    let scope = AclFilterScope::new().with_outbound_sources([
        format!("{LOCAL4}/32").parse().unwrap(),
        format!("{LOCAL}/128").parse().unwrap(),
    ]);
    AclFilter::with_scope(Arc::clone(engine), ns_identity(), config, scope)
}

#[test]
fn default_scope_accepts_a_foreign_outbound_source() {
    assert_eq!(AclFilterScope::new(), AclFilterScope::default());
    assert_eq!(AclFilterScope::default().outbound_sources, None);
    let f = filter();
    let foreign = tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 80);
    assert_eq!(outbound(&f, PEER, foreign), Verdict::Accept);
    let foreign = tcp_packet(addr("fd00::99"), 5000, addr("fd00::9"), 80);
    assert_eq!(outbound(&f, PEER, foreign), Verdict::Accept);
    assert_eq!(f.stats().outbound_source, 0);
}

#[test]
fn outbound_source_scope_passes_own_addresses_to_the_destination_rules() {
    let engine = scope_engine();
    let f = scoped(&engine, AclFilterConfig::default());
    let (a, local, local4) = (peer_addr(A), addr(LOCAL), addr(LOCAL4));
    let foreign = addr("fd00::99");

    // An unrestricted peer: own sources pass, foreign ones are dropped.
    assert_eq!(
        outbound(&f, PEER, tcp_packet(local4, 5000, addr("10.0.0.1"), 9)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, PEER, udp_packet(local, 5000, addr("fd00::9"), 9)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(
            &f,
            PEER,
            tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 9)
        ),
        drop(reasons::OUTBOUND_SOURCE)
    );
    // The ns evidence: an IPv6 SYN from fd00::99 into the tunnel.
    assert_eq!(
        outbound(&f, A, tcp_packet(foreign, 40000, a, 22)),
        drop(reasons::OUTBOUND_SOURCE)
    );

    // A restricted peer: own sources are still judged by its outbound rules.
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 80)),
        Verdict::Accept
    );
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 22)),
        drop(reasons::OUTBOUND)
    );
    // Every protocol is checked.
    let ping = ip(foreign, a, protocol::ICMPV6, &icmp_echo(128, 1));
    assert_eq!(outbound(&f, A, ping), drop(reasons::OUTBOUND_SOURCE));

    let stats = f.stats();
    assert_eq!((stats.outbound_source, stats.outbound_denied), (3, 1));
    // Inbound handling is unchanged.
    assert_eq!(
        inbound(&f, A, tcp_packet(a, 4000, local, 22)),
        Verdict::Accept
    );
}

#[test]
fn outbound_source_is_checked_before_rules_pinholes_and_replies() {
    let engine = scope_engine();
    let (a, c, foreign) = (peer_addr(A), peer_addr(C), addr("fd00::99"));
    let unscoped = ns_filter(&engine, AclFilterConfig::default());
    let f = scoped(&engine, AclFilterConfig::default());

    // A matching outbound rule.
    let to_rule = || tcp_packet(foreign, 5000, a, 80);
    assert_eq!(outbound(&unscoped, A, to_rule()), Verdict::Accept);
    assert_eq!(outbound(&f, A, to_rule()), drop(reasons::OUTBOUND_SOURCE));

    // A reply allowance: `A` reaches `C` on TCP 22 and `C` answers from its own address.
    let reply = || tcp_packet(c, 22, a, 4000);
    for filter in [&unscoped, &f] {
        assert_eq!(
            inbound(filter, A, tcp_packet(a, 4000, c, 22)),
            Verdict::Accept
        );
    }
    assert_eq!(outbound(&unscoped, A, reply()), Verdict::Accept);
    assert_eq!(outbound(&f, A, reply()), drop(reasons::OUTBOUND_SOURCE));
    assert_eq!(unscoped.stats().outbound_replies, 1);
    assert_eq!(f.stats().outbound_replies, 0);

    // An open outbound pinhole.
    let (engine, clock) = pinhole_engine(Some(Vec::new()));
    let unscoped = ns_filter(&engine, AclFilterConfig::default());
    let f = scoped(&engine, AclFilterConfig::default());
    let _guard = open(&engine, &clock, E, Direction::Outbound, 7000);
    let to_pinhole = || tcp_packet(foreign, 5000, peer_addr(E), 7000);
    assert_eq!(outbound(&unscoped, E, to_pinhole()), Verdict::Accept);
    assert_eq!(
        outbound(&f, E, to_pinhole()),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(f.stats().outbound_source, 1);

    // A dropped packet to an unrestricted peer records no reply allowance.
    let f = scoped(&engine, AclFilterConfig::default());
    assert_eq!(
        outbound(&f, PEER, udp_packet(foreign, 5000, addr("fd00::9"), 53)),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(f.inner.table().entries.len(), 0);
}

#[test]
fn outbound_source_scope_drops_truncated_and_foreign_fragments() {
    let engine = scope_engine();
    let f = scoped(&engine, AclFilterConfig::default());
    // Too short to hold the source address, or no IP version at all.
    let mut v4 = vec![0x45; 15];
    let mut v6 = vec![0x60; 23];
    assert_eq!(
        outbound(&f, PEER, PacketBuf::from_packet(&v4)),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(
        outbound(&f, PEER, PacketBuf::from_packet(&v6)),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(
        outbound(&f, PEER, PacketBuf::from_packet(&[])),
        drop(reasons::OUTBOUND_SOURCE)
    );
    // Long enough for the source, but not a valid packet: judged like the empty one.
    v4.push(0x45);
    v4[12..16].copy_from_slice(&[10, 0, 0, 2]);
    assert_eq!(
        outbound(&f, PEER, PacketBuf::from_packet(&v4)),
        Verdict::Accept
    );
    v6.push(0x60);
    v6[8..24].copy_from_slice(&"fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    assert_eq!(
        outbound(&f, PEER, PacketBuf::from_packet(&v6)),
        Verdict::Accept
    );

    // Each fragment carries the source: a non-first one from a foreign address is dropped.
    let (local4, remote) = (addr(LOCAL4), addr("10.0.0.1"));
    let frag = |src, offset_units| {
        ip_frag(
            src,
            remote,
            protocol::UDP,
            &[0; 8],
            Some(Frag {
                id: 9,
                offset_units,
                more: true,
            }),
        )
    };
    assert_eq!(outbound(&f, PEER, frag(local4, 0)), Verdict::Accept);
    assert_eq!(outbound(&f, PEER, frag(local4, 1)), Verdict::Accept);
    assert_eq!(
        outbound(&f, PEER, frag(addr("10.0.0.99"), 1)),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(f.stats().outbound_source, 4);
}

#[test]
fn empty_outbound_sources_drop_every_outbound_packet() {
    let engine = scope_engine();
    let scope = AclFilterScope::new().with_outbound_sources(Vec::new());
    assert_eq!(scope.outbound_sources, Some(Vec::new()));
    let f = AclFilter::with_scope(engine, ns_identity(), AclFilterConfig::default(), scope);
    let (local, a) = (addr(LOCAL), peer_addr(A));
    assert_eq!(
        outbound(&f, A, tcp_packet(local, 5000, a, 80)),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(
        outbound(
            &f,
            PEER,
            tcp_packet(addr(LOCAL4), 5000, addr("10.0.0.1"), 80)
        ),
        drop(reasons::OUTBOUND_SOURCE)
    );
    assert_eq!(f.stats().outbound_source, 2);
}

#[test]
fn ipv6_accept_passes_outbound_ipv6_before_the_source_scope() {
    let engine = scope_engine();
    let f = scoped(&engine, ipv6_accept());
    let foreign = addr("fd00::99");
    assert_eq!(
        outbound(&f, A, tcp_packet(foreign, 5000, peer_addr(A), 22)),
        Verdict::Accept
    );
    // IPv4 is still checked.
    assert_eq!(
        outbound(
            &f,
            PEER,
            tcp_packet(addr("10.0.0.99"), 5000, addr("10.0.0.1"), 80)
        ),
        drop(reasons::OUTBOUND_SOURCE)
    );
    let stats = f.stats();
    assert_eq!((stats.ipv6_accepted, stats.outbound_source), (1, 1));
}

/// Two local identities other than the default one.
fn local_identities() -> [LocalIdentityId; 2] {
    let mut core = nsplane_core::Core::new(nsplane_core::CoreConfig::default());
    [1, 2].map(|seed| {
        core.add_local_identity(nsplane_core::x25519::StaticSecret::from([seed; 32]))
            .unwrap()
    })
}

/// Outbound sources in `10.0.0.0/24`, no other-protocol rule.
fn scope_a() -> AclFilterScope {
    AclFilterScope::new().with_outbound_sources([net("10.0.0.0/24")])
}

/// Outbound sources in `10.1.0.0/24`, GRE to `10.0.0.2` accepted.
fn scope_b() -> AclFilterScope {
    AclFilterScope::new()
        .with_outbound_sources([net("10.1.0.0/24")])
        .with_other_protocol(OtherProtocolRule::new(
            OtherProtocol::Ip(47),
            [net("10.0.0.2/32")],
        ))
}

/// Which scope `peer`'s packets are judged under: `Some(true)` for
/// [`scope_a`], `Some(false)` for [`scope_b`], `None` for no constraint.
fn judged_scope(f: &AclFilter, peer: PeerId) -> Option<bool> {
    let remote = addr("10.0.0.1");
    let from = |src: &str| outbound(f, peer, tcp_packet(addr(src), 5000, remote, 80));
    let gre = inbound(f, peer, ip(remote, addr("10.0.0.2"), 47, &[0; 4]));
    match (from("10.0.0.2"), from("10.1.0.2"), gre) {
        (Verdict::Accept, Verdict::Accept, Verdict::Drop { .. }) => None,
        (Verdict::Accept, Verdict::Drop { .. }, Verdict::Drop { .. }) => Some(true),
        (Verdict::Drop { .. }, Verdict::Accept, Verdict::Accept) => Some(false),
        verdicts => panic!("no single scope gives {verdicts:?}"),
    }
}

#[test]
fn scopes_are_selected_by_local_identity() {
    let [x, y] = local_identities();
    let map = identity();
    map.set_local_identity(OTHER_PEER, x);
    // An identity without a scope of its own.
    map.set_local_identity(KEY_PEER, y);
    map.insert(KEY_PEER, label_set(&[ADDR]));
    let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
    assert_eq!(AclFilterScopes::new(), AclFilterScopes::default());
    for peer in [PEER, OTHER_PEER, KEY_PEER] {
        assert_eq!(judged_scope(&f, peer), None);
    }
    let scopes = AclFilterScopes::new()
        .with_default(scope_a())
        .with_identity(x, scope_b());
    assert_eq!(f.replace_scopes(scopes), Ok(1));
    assert_eq!(judged_scope(&f, PEER), Some(true));
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));
    // No entry for its identity: the default scope.
    assert_eq!(judged_scope(&f, KEY_PEER), Some(true));
    let stats = f.stats();
    assert_eq!((stats.outbound_source, stats.protocol), (3, 5));
    assert_eq!(stats.accepted, 1);

    // A scope for the default identity replaces the default scope for its peers only.
    let scopes = AclFilterScopes::new()
        .with_default(scope_b())
        .with_identity(LocalIdentityId::DEFAULT, scope_a());
    assert_eq!(f.replace_scopes(scopes), Ok(2));
    assert_eq!(judged_scope(&f, PEER), Some(true));
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));
    assert_eq!(judged_scope(&f, KEY_PEER), Some(false));
}

#[test]
fn replace_scopes_bumps_the_generation_and_rejects_duplicates() {
    let [x, _] = local_identities();
    let map = identity();
    map.set_local_identity(OTHER_PEER, x);
    let config = AclFilterConfig::default();
    let f = AclFilter::with_scope(rules_engine(test_policy()), map, config, scope_a());
    // The build scope is the default one, generation 0.
    assert_eq!(f.scope_generation(), 0);
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(true));

    // Any clone replaces the scopes of all of them.
    let handle = f.clone();
    let scopes = AclFilterScopes::new().with_default(scope_b());
    assert_eq!(handle.replace_scopes(scopes), Ok(1));
    assert_eq!(f.scope_generation(), 1);
    assert_eq!(judged_scope(&f, PEER), Some(false));

    // A duplicate identity publishes nothing.
    let duplicate = AclFilterScopes::new()
        .with_identity(x, scope_a())
        .with_identity(x, scope_a());
    assert_eq!(
        f.replace_scopes(duplicate),
        Err(AclFilterScopeError::DuplicateIdentity(x))
    );
    assert_eq!(f.scope_generation(), 1);
    assert_eq!(judged_scope(&f, PEER), Some(false));
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));

    // Back to no constraint: the fast path again.
    assert!(!f.inner.unscoped.load(Ordering::Relaxed));
    assert_eq!(f.replace_scopes(AclFilterScopes::new()), Ok(2));
    assert!(f.inner.unscoped.load(Ordering::Relaxed));
    assert_eq!(judged_scope(&f, OTHER_PEER), None);
    // Entries that constrain nothing keep the fast path.
    let empty = AclFilterScopes::new().with_identity(x, AclFilterScope::new());
    assert_eq!(f.replace_scopes(empty), Ok(3));
    assert!(f.inner.unscoped.load(Ordering::Relaxed));
}

#[test]
fn set_local_identity_changes_the_scope() {
    let [x, _] = local_identities();
    let map = identity();
    let f = AclFilter::new(rules_engine(test_policy()), Arc::clone(&map));
    let scopes = AclFilterScopes::new()
        .with_default(scope_a())
        .with_identity(x, scope_b());
    f.replace_scopes(scopes).unwrap();
    // The peer's identity is cached with its labels.
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(true));
    map.set_local_identity(OTHER_PEER, x);
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));
    // Inserting labels keeps the identity; removing the peer clears it.
    map.insert(OTHER_PEER, label_set(&[ADDR, "peer-2"]));
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));
    map.remove(OTHER_PEER);
    map.insert(OTHER_PEER, label_set(&[ADDR, "peer-2"]));
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(true));
}

/// The labels of a [`PeerLabelMap`], versioned or not, counting the
/// local identity lookups.
struct CountingIdentity {
    map: PeerLabelMap,
    versioned: bool,
    lookups: AtomicU64,
}

impl PeerIdentity for CountingIdentity {
    fn labels(&self, peer: PeerId) -> Option<LabelSet> {
        self.map.labels(peer)
    }

    fn generation(&self) -> u64 {
        if self.versioned {
            self.map.generation()
        } else {
            0
        }
    }

    fn local_identity(&self, peer: PeerId) -> LocalIdentityId {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.map.local_identity(peer)
    }
}

#[test]
fn local_identity_is_cached_when_versioned_and_asked_only_when_needed() {
    let [x, _] = local_identities();
    for versioned in [true, false] {
        let map = PeerLabelMap::new();
        map.insert(PEER, label_set(&[ADDR]));
        map.insert(OTHER_PEER, label_set(&[ADDR]));
        map.set_local_identity(OTHER_PEER, x);
        let identity = Arc::new(CountingIdentity {
            map,
            versioned,
            lookups: AtomicU64::new(0),
        });
        let config = AclFilterConfig::default();
        let engine = rules_engine(test_policy());
        let f = AclFilter::with_scope(engine, Arc::clone(&identity), config, scope_a());
        let lookups = || identity.lookups.load(Ordering::Relaxed);
        // Without per-identity scopes an unversioned identity is never asked.
        assert_eq!(judged_scope(&f, OTHER_PEER), Some(true));
        let before = lookups();
        assert_eq!(before, u64::from(versioned));

        let scopes = AclFilterScopes::new()
            .with_default(scope_a())
            .with_identity(x, scope_b());
        f.replace_scopes(scopes).unwrap();
        for _ in 0..3 {
            assert_eq!(judged_scope(&f, PEER), Some(true));
            assert_eq!(judged_scope(&f, OTHER_PEER), Some(false));
        }
        if versioned {
            // Cached per peer under the identity generation: `PEER` once.
            assert_eq!(lookups(), before + 1);
        } else {
            // Asked by every packet that needs a scope: two outbound, one GRE.
            assert_eq!(lookups(), before + 18);
        }
    }

    // A closure is of the default identity: the default scope.
    let closure = |_: PeerId| Some(label_set(&[ADDR]));
    let scopes = AclFilterScopes::new()
        .with_default(scope_a())
        .with_identity(x, scope_b());
    let f = AclFilter::new(rules_engine(test_policy()), closure);
    f.replace_scopes(scopes).unwrap();
    assert_eq!(judged_scope(&f, OTHER_PEER), Some(true));
}

#[test]
fn replace_scopes_under_concurrency_never_tears_a_scope() {
    /// Counts a reader as done even when it panics, so the writer stops.
    struct Done<'a>(&'a std::sync::atomic::AtomicUsize);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    const READERS: u16 = 4;
    const PACKETS: u16 = 500;
    let [x, _] = local_identities();
    let map = identity();
    map.set_local_identity(OTHER_PEER, x);
    let config = AclFilterConfig::default();
    let f = AclFilter::with_scope(rules_engine(test_policy()), map, config, scope_a());
    // `OTHER_PEER` is under `scope_b` in odd generations, `scope_a` in even ones.
    let set = |generation: u64| {
        let scope = if generation % 2 == 1 {
            scope_b()
        } else {
            scope_a()
        };
        AclFilterScopes::new()
            .with_default(scope_a())
            .with_identity(x, scope)
    };
    let done = std::sync::atomic::AtomicUsize::new(0);
    let remote = addr("10.0.0.1");
    std::thread::scope(|threads| {
        for reader in 0..READERS {
            let (f, done) = (&f, &done);
            threads.spawn(move || {
                let _done = Done(done);
                for i in 0..PACKETS {
                    let id = reader * PACKETS + i;
                    // `scope_a` accepts the first source, `scope_b` the second.
                    let (src, a_accepts) = if i % 2 == 0 {
                        (addr("10.0.0.2"), true)
                    } else {
                        (addr("10.1.0.2"), false)
                    };
                    let before = f.scope_generation();
                    let request = ip(src, remote, protocol::ICMP, &icmp_echo(8, id));
                    let verdict = outbound(f, OTHER_PEER, request);
                    let after = f.scope_generation();
                    let accepted = verdict == Verdict::Accept;
                    if before == after {
                        let under_a = before % 2 == 0;
                        assert_eq!(accepted, a_accepts == under_a, "generation {before}");
                    }
                    // The reply passes exactly when its request was accepted.
                    let reply = ip(remote, src, protocol::ICMP, &icmp_echo(0, id));
                    let replied = inbound(f, OTHER_PEER, reply) == Verdict::Accept;
                    assert_eq!(replied, accepted, "torn scope, id {id}");
                }
            });
        }
        let mut generation = 0;
        while done.load(Ordering::Relaxed) < usize::from(READERS) {
            generation += 1;
            assert_eq!(f.replace_scopes(set(generation)), Ok(generation));
            std::thread::yield_now();
        }
        assert!(generation > 0);
    });
}

#[test]
fn filters_on_one_thread_never_share_cached_scopes() {
    let [x, _] = local_identities();
    let map = identity();
    map.set_local_identity(OTHER_PEER, x);
    let config = AclFilterConfig::default();
    let a = AclFilter::with_scope(
        rules_engine(test_policy()),
        Arc::clone(&map),
        config,
        scope_a(),
    );
    let b = AclFilter::with_scope(
        rules_engine(test_policy()),
        Arc::clone(&map),
        config,
        scope_b(),
    );
    // Same generation, different cells: each packet uses its own filter's set.
    for _ in 0..3 {
        assert_eq!(judged_scope(&a, PEER), Some(true));
        assert_eq!(judged_scope(&b, PEER), Some(false));
    }
    // A replace of one cell leaves the other one's set in place.
    let scopes = AclFilterScopes::new()
        .with_default(scope_b())
        .with_identity(x, scope_a());
    assert_eq!(a.replace_scopes(scopes), Ok(1));
    for _ in 0..3 {
        assert_eq!(judged_scope(&a, PEER), Some(false));
        assert_eq!(judged_scope(&a, OTHER_PEER), Some(true));
        assert_eq!(judged_scope(&b, OTHER_PEER), Some(false));
        assert_eq!(b.scope_generation(), 0);
    }
    // A filter built after another is dropped never uses its set.
    std::mem::drop(b);
    let c = AclFilter::new(rules_engine(test_policy()), map);
    assert_eq!(judged_scope(&c, PEER), None);
}
