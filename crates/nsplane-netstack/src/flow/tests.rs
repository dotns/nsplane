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
fn clean_registry_skips_the_maintenance_lock() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let _live: Vec<_> = (0..1024).map(|_| labeled(&revocations, 1)).collect();
    let queue = revocations.lock();
    let (sent, received) = std::sync::mpsc::channel();
    let registry = Arc::clone(&revocations);
    let worker = std::thread::spawn(move || {
        registry.sweep_labeled();
        sent.send(()).unwrap();
    });
    let result = received.recv_timeout(std::time::Duration::from_secs(2));
    drop(queue);
    worker.join().unwrap();
    assert!(
        result.is_ok(),
        "clean maintenance must not acquire the registry lock"
    );
}

#[test]
fn only_the_last_labeled_reference_marks_a_release() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live = labeled(&revocations, 1);
    drop(Arc::clone(&live));
    drop(FlowState::new(
        Target::Label(NonZeroU64::new(2).unwrap()),
        &revocations,
    ));
    assert_eq!(revocations.label_generation.load(Ordering::Acquire), 0);
    // Release notifications must also work under the registry lock.
    let queue = revocations.lock();
    drop(live);
    assert_eq!(revocations.label_generation.load(Ordering::Acquire), 1);
    drop(queue);
    revocations.sweep_labeled();
    assert_eq!(revocations.lock().labeled.capacity(), 0);
    assert_eq!(
        revocations.clean_label_generation.load(Ordering::Acquire),
        1
    );
}

#[test]
fn a_release_during_a_pass_is_not_acknowledged_by_that_pass() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let mut live: Vec<_> = (0..512).map(|_| labeled(&revocations, 1)).collect();
    drop(labeled(&revocations, 2));
    revocations.sweep_labeled();
    assert_eq!(
        revocations.lock().labeled_end,
        513 - IDLE_LABEL_SWEEP_BUDGET
    );
    let visited = live.pop().unwrap();
    let released = Arc::downgrade(&visited);
    let queue = revocations.lock();
    // A release on another thread cannot take this lock or be lost on completion.
    std::thread::spawn(move || drop(visited)).join().unwrap();
    drop(queue);
    for _ in 0..2 {
        revocations.sweep_labeled();
    }
    assert_ne!(
        revocations.label_generation.load(Ordering::Acquire),
        revocations.clean_label_generation.load(Ordering::Acquire)
    );
    assert!(
        revocations
            .lock()
            .labeled
            .iter()
            .any(|entry| Weak::ptr_eq(entry, &released))
    );
    for _ in 0..3 {
        revocations.sweep_labeled();
    }
    assert_eq!(revocations.lock().labeled.len(), live.len());
    assert_eq!(
        revocations.label_generation.load(Ordering::Acquire),
        revocations.clean_label_generation.load(Ordering::Acquire)
    );
}

#[test]
fn appended_registrations_do_not_hide_unvisited_expired_entries() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live: Vec<_> = (0..512).map(|_| labeled(&revocations, 1)).collect();
    let expired: Vec<_> = (0..512).map(|_| labeled(&revocations, 2)).collect();
    drop(expired);
    let appended: Vec<_> = (0..256).map(|_| labeled(&revocations, 3)).collect();
    let queue = revocations.lock();
    assert_eq!(queue.labeled.len(), live.len() + appended.len());
    assert!(queue.labeled.iter().all(|entry| entry.strong_count() != 0));
    assert_eq!(
        revocations.label_generation.load(Ordering::Acquire),
        revocations.clean_label_generation.load(Ordering::Acquire)
    );
    drop(queue);
    assert_eq!(
        revocations.labeled(NonZeroU64::new(1).unwrap()).len(),
        live.len()
    );
    assert_eq!(
        revocations.labeled(NonZeroU64::new(3).unwrap()).len(),
        appended.len()
    );
}

#[test]
fn short_lived_registrations_reuse_expired_tail_during_a_long_pass() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live: Vec<_> = (0..4096).map(|_| labeled(&revocations, 1)).collect();
    for _ in 0..32 {
        drop(labeled(&revocations, 2));
    }
    assert!(revocations.lock().labeled.len() <= live.len() + 1);
    assert!(
        revocations
            .labeled(NonZeroU64::new(1).unwrap())
            .iter()
            .any(|entry| Arc::ptr_eq(entry, &live[0]))
    );
}

#[test]
fn full_lookup_resets_partial_coverage_and_releases_empty_storage() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live: Vec<_> = (0..512).map(|_| labeled(&revocations, 1)).collect();
    drop(labeled(&revocations, 2));
    revocations.sweep_labeled();
    assert_eq!(
        revocations.labeled(NonZeroU64::new(1).unwrap()).len(),
        live.len()
    );
    drop(live);
    for _ in 0..2 {
        revocations.sweep_labeled();
    }
    assert_eq!(revocations.lock().labeled.capacity(), 0);
    drop(labeled(&revocations, 3));
    assert!(revocations.labeled(NonZeroU64::new(3).unwrap()).is_empty());
    assert_eq!(revocations.lock().labeled.capacity(), 0);
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

#[test]
fn closing_releases_label_storage_and_prevents_new_registrations() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live = labeled(&revocations, 1);
    let pending = labeled(&revocations, 2);
    pending.revoke();
    let retiring = labeled(&revocations, 3);
    revocations.close(&mut vec![Arc::clone(&retiring)]);
    let late = labeled(&revocations, 4);
    late.revoke();
    let queue = revocations.lock();
    assert!(queue.closed);
    assert!(queue.labeled.is_empty());
    assert_eq!(queue.labeled.capacity(), 0);
    assert!(queue.pending.is_empty());
    assert_eq!(pending.outcome(), Some(RetirementOutcome::Unknown));
    assert_eq!(retiring.outcome(), Some(RetirementOutcome::Unknown));
    assert_eq!(late.outcome(), Some(RetirementOutcome::Unknown));
    assert_eq!(live.ingress_label(), NonZeroU64::new(1));
    drop(queue);
    revocations.close(&mut Vec::new());
    assert_eq!(revocations.lock().labeled.capacity(), 0);
}

#[test]
fn maintenance_is_bounded_and_preserves_live_labels() {
    let revocations = Arc::new(Revocations::new(Arc::new(Notify::new())));
    let live: Vec<_> = (0..1024).map(|_| labeled(&revocations, 1)).collect();
    let expired: Vec<_> = (0..1024).map(|_| labeled(&revocations, 2)).collect();
    drop(expired);
    let before = revocations.lock().labeled.len();
    revocations.sweep_labeled();
    assert!(revocations.lock().labeled.len() >= before - IDLE_LABEL_SWEEP_BUDGET);
    for _ in 0..before.div_ceil(IDLE_LABEL_SWEEP_BUDGET) {
        revocations.sweep_labeled();
    }
    assert_eq!(revocations.lock().labeled.len(), live.len());
    let matches = revocations.labeled(NonZeroU64::new(1).unwrap());
    assert_eq!(matches.len(), live.len());
    assert!(
        live.iter()
            .all(|flow| matches.iter().any(|entry| Arc::ptr_eq(entry, flow)))
    );
    drop(matches);
    drop(live);
    for _ in 0..1024_usize.div_ceil(IDLE_LABEL_SWEEP_BUDGET) {
        revocations.sweep_labeled();
    }
    assert_eq!(revocations.lock().labeled.capacity(), 0);
    let fresh = labeled(&revocations, 3);
    assert!(Arc::ptr_eq(
        &revocations.labeled(NonZeroU64::new(3).unwrap())[0],
        &fresh
    ));
}

#[tokio::test]
async fn idle_driver_reclaims_labels_without_new_registrations() {
    use std::time::Duration;

    let config = crate::NetStackConfig::new(vec![("192.0.2.1".parse().unwrap(), 24)], 1360);
    let (_stack, handle) = crate::NetStack::new(config);
    let socket = handle
        .connect_udp_labeled(
            "192.0.2.2:9000".parse().unwrap(),
            NonZeroU64::new(1).unwrap(),
        )
        .await
        .unwrap();
    let control = socket.control();
    let revocations = Arc::clone(&control.state.revocations);
    let expired: Vec<_> = (0..1024).map(|_| labeled(&revocations, 2)).collect();
    drop(expired);
    tokio::time::timeout(Duration::from_secs(3), async {
        while revocations.lock().labeled.len() != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(Arc::ptr_eq(
        &revocations.labeled(NonZeroU64::new(1).unwrap())[0],
        &control.state
    ));
    drop(socket);
    let receipt = control.revoke();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), receipt.wait())
            .await
            .unwrap(),
        RetirementOutcome::Retired
    );
    drop(receipt);
    drop(control);
    tokio::time::timeout(Duration::from_secs(3), async {
        while revocations.lock().labeled.capacity() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
