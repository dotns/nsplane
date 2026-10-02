//! WireGuard mac1, the relay's routing key for handshake messages.
//!
//! A handshake initiation carries `mac1 = MAC(HASH("mac1----" || responder static public),
//! msg[..mac1])`, where `HASH` is BLAKE2s-256 and `MAC` keyed BLAKE2s-128; a response
//! carries the same over the initiator's public key. Anyone who knows a public key can
//! check whether a handshake is addressed to it without decrypting anything, which is how
//! the relay tells handshakes for its own engine from handshakes it relays.

use blake2::digest::consts::U16;
use blake2::digest::{Digest as _, Mac as _};
use blake2::{Blake2s256, Blake2sMac};

use super::wire::{self, Frame, WgKind};

const LABEL_MAC1: &[u8; 8] = b"mac1----";
const MAC_LEN: usize = 16;
const INIT_MAC1_OFFSET: usize = 116;
const RESPONSE_MAC1_OFFSET: usize = 60;

/// The mac1 key of one WireGuard static public key.
///
/// Computing it is one BLAKE2s hash; a router that checks many packets against the same
/// targets keeps one per target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac1Key([u8; 32]);

impl Mac1Key {
    /// The key for handshake messages addressed to `public` (the responder's static
    /// public key for an initiation, the initiator's for a response).
    pub fn new(public: &[u8; 32]) -> Self {
        let mut hash = Blake2s256::new();
        hash.update(LABEL_MAC1);
        hash.update(public);
        Self(hash.finalize().into())
    }

    /// Whether `packet` is a handshake initiation or response whose mac1 was computed
    /// with this key. Anything else, including a short or malformed packet, is `false`.
    pub fn matches(&self, packet: &[u8]) -> bool {
        let offset = match wire::classify(packet) {
            Frame::WireGuard(WgKind::HandshakeInit) => INIT_MAC1_OFFSET,
            Frame::WireGuard(WgKind::HandshakeResponse) => RESPONSE_MAC1_OFFSET,
            _ => return false,
        };
        let (Some(input), Some(tag)) = (packet.get(..offset), packet.get(offset..offset + MAC_LEN))
        else {
            return false;
        };
        let mut mac = Blake2sMac::<U16>::new(&self.0.into());
        mac.update(input);
        mac.verify_slice(tag).is_ok()
    }
}

/// Whether `packet` is a handshake initiation or response addressed to `public`.
///
/// Shorthand for [`Mac1Key::new`] followed by [`Mac1Key::matches`].
pub fn mac1_matches(packet: &[u8], public: &[u8; 32]) -> bool {
    Mac1Key::new(public).matches(packet)
}

#[cfg(test)]
mod tests {
    use nsplane_noise::noise::{Tunn, TunnResult};
    use nsplane_noise::x25519::{PublicKey, StaticSecret};

    use super::*;

    fn key(byte: u8) -> StaticSecret {
        StaticSecret::from([byte; 32])
    }

    /// A real initiation and the matching response, produced by two nsplane tunnels.
    fn handshake() -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32]) {
        let (initiator_secret, responder_secret) = (key(1), key(2));
        let initiator_public = PublicKey::from(&initiator_secret);
        let responder_public = PublicKey::from(&responder_secret);
        let mut initiator = Tunn::new(initiator_secret, responder_public, None, None, 1, None);
        let mut responder = Tunn::new(responder_secret, initiator_public, None, None, 2, None);

        let mut buf = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(init) =
            initiator.format_handshake_initiation(&mut buf, false)
        else {
            panic!("no initiation");
        };
        let init = init.to_vec();
        let mut out = vec![0u8; 2048];
        let TunnResult::WriteToNetwork(response) = responder.decapsulate(None, &init, &mut out)
        else {
            panic!("no response");
        };
        (
            init,
            response.to_vec(),
            initiator_public.to_bytes(),
            responder_public.to_bytes(),
        )
    }

    #[test]
    fn initiation_matches_the_responder_key_only() {
        let (init, _, initiator, responder) = handshake();
        assert_eq!(
            wire::classify(&init),
            Frame::WireGuard(WgKind::HandshakeInit)
        );
        assert!(mac1_matches(&init, &responder));
        assert!(!mac1_matches(&init, &initiator));
        assert!(!mac1_matches(&init, &[7; 32]));
    }

    #[test]
    fn response_matches_the_initiator_key_only() {
        let (_, response, initiator, responder) = handshake();
        assert_eq!(
            wire::classify(&response),
            Frame::WireGuard(WgKind::HandshakeResponse)
        );
        assert!(mac1_matches(&response, &initiator));
        assert!(!mac1_matches(&response, &responder));
    }

    #[test]
    fn tampered_or_truncated_handshakes_do_not_match() {
        let (init, _, _, responder) = handshake();
        let key = Mac1Key::new(&responder);
        let mut tampered = init.clone();
        tampered[20] ^= 1;
        assert!(!key.matches(&tampered));
        let mut bad_tag = init.clone();
        bad_tag[INIT_MAC1_OFFSET] ^= 1;
        assert!(!key.matches(&bad_tag));
        assert!(!key.matches(&init[..init.len() - 1]));
        let mut as_data = init;
        as_data[0] = 4;
        assert!(!key.matches(&as_data));
    }
}
