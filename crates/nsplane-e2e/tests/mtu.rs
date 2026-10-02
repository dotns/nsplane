//! MTU changes of the packet source, through the harness's `ChannelSource` MTU watch.
//!
//! The engine reports the source's MTU through `EngineHandle::mtu` and publishes every
//! change to a different value once as `Event::MtuChanged`; while suspended, changes wait
//! for the resume.

use nsplane::{ChannelTransport, Event};
use nsplane_e2e::{MTU, Node, Options, TestResult, channel_pair};

/// Whether `event` reports an MTU change.
const fn is_mtu_change(event: &Event) -> bool {
    matches!(event, Event::MtuChanged { .. })
}

/// A single node; its peer is not needed.
fn node() -> Node<ChannelTransport> {
    channel_pair(Options::default()).0
}

/// Sets the source MTU of `node` to `mtu`.
fn set_mtu(node: &Node<ChannelTransport>, mtu: u16) -> TestResult {
    node.mtu.send(mtu)?;
    Ok(())
}

#[tokio::test]
async fn initial_mtu_is_reported() -> TestResult {
    let a = node();
    assert_eq!(a.handle.mtu().await?, MTU);
    Ok(())
}

#[tokio::test]
async fn a_change_publishes_one_event() -> TestResult {
    let a = node();
    let mut events = a.subscribe().await?;

    set_mtu(&a, 1280)?;
    assert_eq!(
        events.expect(is_mtu_change).await?,
        Event::MtuChanged { mtu: 1280 }
    );
    assert_eq!(a.handle.mtu().await?, 1280);
    events.expect_none(is_mtu_change).await?;
    Ok(())
}

#[tokio::test]
async fn two_changes_publish_one_event_each() -> TestResult {
    let a = node();
    let mut events = a.subscribe().await?;

    set_mtu(&a, 1280)?;
    assert_eq!(
        events.expect(is_mtu_change).await?,
        Event::MtuChanged { mtu: 1280 }
    );
    set_mtu(&a, 1500)?;
    assert_eq!(
        events.expect(is_mtu_change).await?,
        Event::MtuChanged { mtu: 1500 }
    );
    assert_eq!(a.handle.mtu().await?, 1500);
    events.expect_none(is_mtu_change).await?;
    Ok(())
}

#[tokio::test]
async fn the_same_value_publishes_nothing() -> TestResult {
    let a = node();
    let mut events = a.subscribe().await?;

    set_mtu(&a, MTU)?;
    events.expect_none(is_mtu_change).await?;
    assert_eq!(a.handle.mtu().await?, MTU);
    Ok(())
}

#[tokio::test]
async fn a_change_while_suspended_is_published_on_resume() -> TestResult {
    let a = node();
    let mut events = a.subscribe().await?;

    a.handle.suspend().await?;
    set_mtu(&a, 1300)?;
    set_mtu(&a, 1280)?;
    events.expect_none(is_mtu_change).await?;
    assert_eq!(a.handle.mtu().await?, MTU);

    a.handle.resume().await?;
    assert_eq!(
        events.expect(is_mtu_change).await?,
        Event::MtuChanged { mtu: 1280 }
    );
    assert_eq!(a.handle.mtu().await?, 1280);
    events.expect_none(is_mtu_change).await?;
    Ok(())
}
