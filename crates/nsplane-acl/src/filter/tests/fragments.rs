//! IPv4 fragments following their first fragment.

use super::*;

#[test]
fn fragments_follow_an_allowed_first_fragment() {
    let f = filter();
    assert_eq!(inbound(&f, PEER, first_fragment(7, 80)), Verdict::Accept);
    assert_eq!(
        inbound(&f, PEER, fragment(7, 4, true, &[0; 16])),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, fragment(7, 6, false, &[0; 8])),
        Verdict::Accept
    );
    // The entry was freed by the last fragment.
    assert_eq!(
        inbound(&f, PEER, fragment(7, 6, false, &[0; 8])),
        drop(reasons::FRAGMENT)
    );
    // The entry is per peer.
    assert_eq!(inbound(&f, PEER, first_fragment(8, 80)), Verdict::Accept);
    assert_eq!(
        inbound(&f, OTHER_PEER, fragment(8, 4, false, &[0; 8])),
        drop(reasons::FRAGMENT)
    );
    assert_eq!(f.stats().accepted, 4);
}

#[test]
fn fragments_follow_a_denied_first_fragment() {
    let f = filter();
    assert_eq!(
        inbound(&f, PEER, first_fragment(9, 81)),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, PEER, fragment(9, 4, true, &[0; 8])),
        drop(reasons::DENIED)
    );
    assert_eq!(
        inbound(&f, PEER, fragment(9, 5, false, &[0; 8])),
        drop(reasons::DENIED)
    );
    assert_eq!(f.stats().denied, 3);
}

#[test]
fn orphan_fragment_is_dropped() {
    let f = filter();
    assert_eq!(
        inbound(&f, PEER, fragment(3, 4, true, &[0; 8])),
        drop(reasons::FRAGMENT)
    );
    assert_eq!(f.stats().fragment, 1);
}

#[test]
fn fragment_table_evicts_oldest() {
    let f = filter_with(AclFilterConfig {
        fragment_capacity: 2,
        ..AclFilterConfig::default()
    });
    for id in 1..=3 {
        assert_eq!(inbound(&f, PEER, first_fragment(id, 80)), Verdict::Accept);
    }
    assert_eq!(f.stats().fragment_evictions, 1);
    assert_eq!(
        inbound(&f, PEER, fragment(1, 4, false, &[0; 8])),
        drop(reasons::FRAGMENT)
    );
    assert_eq!(
        inbound(&f, PEER, fragment(2, 4, false, &[0; 8])),
        Verdict::Accept
    );
    assert_eq!(
        inbound(&f, PEER, fragment(3, 4, false, &[0; 8])),
        Verdict::Accept
    );
}
