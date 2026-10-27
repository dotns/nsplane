#![allow(clippy::unwrap_used, reason = "test harness")]

use super::*;

fn labeled(revocations: &Arc<Revocations>, label: u64) -> Arc<FlowState> {
    let label = NonZeroU64::new(label).unwrap();
    FlowState::labeled(
        Target::UdpFlow((
            SocketAddr::from(([192, 0, 2, 1], 5000)),
            SocketAddr::from(([192, 0, 2, 2], 9000)),
        )),
        Some(label),
        revocations,
    )
}

#[test]
fn registration_bounds_cleanup_and_eventually_reclaims_expired_entries() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live: Vec<_> = (0..1024).map(|_| labeled(&revocations, 1)).collect();
    let expired: Vec<_> = (0..64).map(|_| labeled(&revocations, 2)).collect();
    let expired_refs: Vec<_> = expired.iter().map(Arc::downgrade).collect();
    drop(expired);

    let fresh = labeled(&revocations, 3);
    // One insertion must not traverse and collect the entire expired population.
    let remaining = revocations
        .lock()
        .labeled
        .iter()
        .filter(|entry| entry.strong_count() == 0)
        .count();
    assert!(remaining >= 64 - LABEL_SWEEP_BUDGET);
    for _ in 0..4096 {
        drop(labeled(&revocations, 4));
    }
    {
        let queue = revocations.lock();
        assert!(!queue.labeled.iter().any(|entry| {
            expired_refs
                .iter()
                .any(|expired| Weak::ptr_eq(entry, expired))
        }));
        // Churn cannot leave an entry behind for every registration.
        assert!(queue.labeled.len() < live.len() * 2);
    }
    let matching = revocations.labeled(NonZeroU64::new(1).unwrap());
    assert_eq!(matching.len(), live.len());
    for flow in &live {
        assert!(matching.iter().any(|entry| Arc::ptr_eq(entry, flow)));
    }
    assert!(Arc::ptr_eq(
        &revocations.labeled(NonZeroU64::new(3).unwrap())[0],
        &fresh
    ));
}

#[test]
fn label_lookup_compaction_preserves_registration_and_repeated_lookup() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let old: Vec<_> = (0..128).map(|_| labeled(&revocations, 1)).collect();
    let retained = labeled(&revocations, 2);
    drop(old);
    let label = NonZeroU64::new(2).unwrap();
    for _ in 0..2 {
        let matches = revocations.labeled(label);
        assert_eq!(matches.len(), 1);
        assert!(Arc::ptr_eq(&matches[0], &retained));
    }
    assert!(revocations.labeled(NonZeroU64::new(1).unwrap()).is_empty());
    let fresh = labeled(&revocations, 1);
    assert!(Arc::ptr_eq(
        &revocations.labeled(NonZeroU64::new(1).unwrap())[0],
        &fresh
    ));
    drop(fresh);
    drop(retained);
    assert!(revocations.labeled(label).is_empty());
    let last = labeled(&revocations, 2);
    assert!(Arc::ptr_eq(&revocations.labeled(label)[0], &last));
}
