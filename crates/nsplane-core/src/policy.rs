//! Per-peer path decisions.

use nsplane_packet::{Path, PeerId};

/// The kind of a WireGuard message, as seen by a [`PathPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Handshake initiation.
    HandshakeInit,
    /// Handshake response.
    HandshakeResponse,
    /// Cookie reply.
    CookieReply,
    /// Transport data carrying a packet.
    Data,
    /// Transport data without a payload.
    Keepalive,
}

/// Whether to adopt the path an authenticated message arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Roam {
    /// Make the path the peer's current path.
    Adopt,
    /// Keep the peer's current path.
    Keep,
}

/// Per-peer path decisions; the engine never changes a path on its own, it asks
/// [`PathPolicy::on_authenticated`].
pub trait PathPolicy: Send + Sync + 'static {
    /// Path for the next outgoing message of this kind; `None` means "use the peer's
    /// current path".
    fn select(&self, peer: PeerId, kind: MessageKind) -> Option<Path>;
    /// An authenticated message of this kind arrived from `from`. Returns whether to adopt
    /// it as the peer's path.
    ///
    /// The core asks about messages from a path other than the peer's current one; with
    /// [`PathPolicy::observe_every_message`], about every authenticated message. Never about
    /// cookie replies.
    fn on_authenticated(&self, peer: PeerId, from: &Path, kind: MessageKind) -> Roam;

    /// Whether [`PathPolicy::on_authenticated`] is called for every authenticated message,
    /// on the peer's current path too (where its answer changes nothing), e.g. to keep a
    /// path alive or detect its loss. Read once when the core is built; `false` by default,
    /// which spares the call on the data path.
    fn observe_every_message(&self) -> bool {
        false
    }
}

/// Standard WireGuard roaming: always send on the current path and adopt the source of every
/// authenticated message except cookie replies.
///
/// Cookie replies are encrypted with a key derived from the peer's public key only, so they do
/// not prove that the sender holds the peer's private key; they never cause roaming.
#[derive(Debug, Default, Clone, Copy)]
pub struct StandardRoaming;

impl PathPolicy for StandardRoaming {
    fn select(&self, _peer: PeerId, _kind: MessageKind) -> Option<Path> {
        None
    }

    fn on_authenticated(&self, _peer: PeerId, _from: &Path, kind: MessageKind) -> Roam {
        match kind {
            MessageKind::CookieReply => Roam::Keep,
            MessageKind::HandshakeInit
            | MessageKind::HandshakeResponse
            | MessageKind::Data
            | MessageKind::Keepalive => Roam::Adopt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::{Ecn, TransportId};

    const KINDS: [MessageKind; 5] = [
        MessageKind::HandshakeInit,
        MessageKind::HandshakeResponse,
        MessageKind::CookieReply,
        MessageKind::Data,
        MessageKind::Keepalive,
    ];

    fn path() -> Path {
        Path {
            transport: TransportId::new(0),
            addr: "192.0.2.1:51820".parse().unwrap(),
            ecn: Ecn::NotEct,
        }
    }

    #[test]
    fn standard_roaming_uses_the_current_path() {
        for kind in KINDS {
            assert_eq!(StandardRoaming.select(PeerId::new(1), kind), None);
        }
    }

    #[test]
    fn standard_roaming_adopts_every_authenticated_message_but_cookie_replies() {
        for kind in KINDS {
            let expected = if kind == MessageKind::CookieReply {
                Roam::Keep
            } else {
                Roam::Adopt
            };
            assert_eq!(
                StandardRoaming.on_authenticated(PeerId::new(1), &path(), kind),
                expected,
                "{kind:?}"
            );
        }
    }
}
