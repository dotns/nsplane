//! The relay's control messages: ns `wg_relay.register_source` and `gateway.reflexive`.
//!
//! Payloads, API identifiers and timing are ns and nsgw's, unchanged. Only the framing
//! differs: ns prefixes a datagram with an 8-byte magic (`NSGWGRS1`, `NSGWP2P1`), this
//! relay with the 5-byte control header of [`super::wire`]. The functions here return and
//! take whole frames or the payload behind the header.
//!
//! - `register_source` (peer to relay): a signed envelope carrying the peer's WireGuard
//!   public key. The relay learns the peer's NAT source address from the datagram's source.
//! - `gateway.reflexive` request (peer to relay): a signed envelope carrying the peer's
//!   WireGuard key and a fresh nonce. The response (relay to peer) is unsigned and carries
//!   the observed source address; it is bound to the request by echoing the nonce, which
//!   the peer accepts once and only while it is outstanding ([`PendingNonces`]).
//!
//! ```
//! use nsplane_examples::relay::envelope::{MachineKey, ReplayGuard, unix_now_secs};
//! use nsplane_examples::relay::messages;
//! use nsplane_examples::relay::wire::{self, ControlType};
//!
//! let key = MachineKey::generate();
//! let frame = messages::build_register_source("machine-1", &key, [3; 32])?;
//! let (msg_type, payload) = wire::decode_control(&frame)?;
//! assert_eq!(msg_type, ControlType::RegisterSource);
//! let now = unix_now_secs()?;
//! let request = messages::open_register_source(payload, now)?;
//! request.admit("machine-1", &key.public(), &ReplayGuard::new(), now)?;
//! assert_eq!(request.payload.nsn_pubkey, [3; 32]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::envelope::{ControlEnvelope, Error, MachineKey, ReplayGuard, byte_array, random_nonce};
use super::wire::{self, ControlType};

/// API identifier of the source registration.
pub const WG_RELAY_REGISTER_SOURCE: &str = "wg_relay.register_source";

/// API identifier of the reflexive address discovery.
pub const GATEWAY_REFLEXIVE: &str = "gateway.reflexive";

/// The ns datagram prefix of `register_source`, which [`ControlType::RegisterSource`]
/// replaces on this relay's port.
pub const WG_RELAY_REGISTRATION_MAGIC: &[u8; 8] = b"NSGWGRS1";

/// The ns datagram prefix of both directions of `gateway.reflexive`, which
/// [`ControlType::ReflexiveRequest`] and [`ControlType::ReflexiveResponse`] replace.
pub const GATEWAY_REFLEXIVE_MAGIC: &[u8; 8] = b"NSGWP2P1";

/// How often a peer re-registers its source with each relay (ns `RELAY_REGISTER_INTERVAL`).
pub const RELAY_REGISTER_INTERVAL: Duration = Duration::from_secs(30);

/// How long a relay keeps a learned source without a fresh registration (nsgw
/// `LEARNED_SOURCE_TTL`).
pub const LEARNED_SOURCE_TTL: Duration = Duration::from_secs(90);

/// How long a relay keeps an idle receiver-index route (nsgw `SESSION_TTL`).
pub const SESSION_TTL: Duration = Duration::from_secs(180);

/// How often a peer sends a reflexive request (ns `REFLEXIVE_GATHER_INTERVAL`).
pub const REFLEXIVE_GATHER_INTERVAL: Duration = Duration::from_secs(20);

/// How long a reflexive nonce stays outstanding, and a consumed one remembered (ns
/// `NONCE_TTL`).
pub const REFLEXIVE_NONCE_TTL: Duration = Duration::from_secs(30);

/// Payload of `wg_relay.register_source` (ns `WgRelayRegistrationRequest`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgRelayRegistrationRequest {
    /// The registering peer's WireGuard public key: the relay's mac1 routing target.
    #[serde(with = "byte_array")]
    pub nsn_pubkey: [u8; 32],
}

/// Payload of a `gateway.reflexive` request (ns `GatewayReflexiveRequest`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayReflexiveRequest {
    /// The requesting peer's WireGuard public key.
    #[serde(with = "byte_array")]
    pub peer_key_pub: [u8; 32],
    /// A fresh nonce the response echoes.
    #[serde(with = "byte_array")]
    pub nonce: [u8; 16],
}

/// A `gateway.reflexive` response (ns `GatewayReflexiveResponse`). Unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayReflexiveResponse {
    /// The request's nonce.
    #[serde(with = "byte_array")]
    pub nonce: [u8; 16],
    /// The request's source address as the relay saw it: the peer's server-reflexive
    /// candidate.
    pub observed_addr: SocketAddr,
    /// The relay's identifier.
    pub gateway_id: String,
    /// The relay's own socket address.
    pub relay_socket_addr: SocketAddr,
    /// The relay's clock, Unix milliseconds.
    pub timestamp_unix_ms: u64,
}

/// Encodes a payload as CBOR (ns `control::api::to_cbor`).
pub fn to_cbor<T: Serialize>(payload: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(128);
    ciborium::into_writer(payload, &mut buf).map_err(|err| Error::CborEncode(err.to_string()))?;
    Ok(buf)
}

/// Decodes a CBOR payload (ns `control::api::from_cbor`).
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::from_reader(bytes).map_err(|err| Error::CborDecode(err.to_string()))
}

fn signed_frame(
    msg_type: ControlType,
    api: &str,
    machine_id: &str,
    key: &MachineKey,
    payload: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let envelope = ControlEnvelope::sign_request(
        api,
        Some(machine_id.to_owned()),
        key.public(),
        payload,
        |input| key.sign(input),
    )?;
    Ok(wire::encode_control(msg_type, &envelope.to_cbor()?))
}

/// A `register_source` frame (ns `build_register_source_datagram`).
///
/// It names the peer `machine_id` whose WireGuard key is `nsn_pubkey`. Sign a fresh one
/// per relay and send it from the WireGuard socket, so the relay learns that socket's NAT
/// mapping.
pub fn build_register_source(
    machine_id: &str,
    key: &MachineKey,
    nsn_pubkey: [u8; 32],
) -> Result<Vec<u8>, Error> {
    let payload = to_cbor(&WgRelayRegistrationRequest { nsn_pubkey })?;
    signed_frame(
        ControlType::RegisterSource,
        WG_RELAY_REGISTER_SOURCE,
        machine_id,
        key,
        payload,
    )
}

/// A `gateway.reflexive` request frame carrying `nonce` (ns
/// `build_gateway_reflexive_datagram`); take the nonce from [`PendingNonces::issue`].
pub fn build_reflexive_request(
    machine_id: &str,
    key: &MachineKey,
    peer_key_pub: [u8; 32],
    nonce: [u8; 16],
) -> Result<Vec<u8>, Error> {
    let payload = to_cbor(&GatewayReflexiveRequest {
        peer_key_pub,
        nonce,
    })?;
    signed_frame(
        ControlType::ReflexiveRequest,
        GATEWAY_REFLEXIVE,
        machine_id,
        key,
        payload,
    )
}

/// The response frame to an admitted reflexive `request` received from `observed_addr`,
/// echoing its nonce (as nsgw's `handle_reflexive_request` builds it).
pub fn build_reflexive_response(
    request: &GatewayReflexiveRequest,
    observed_addr: SocketAddr,
    gateway_id: &str,
    relay_socket_addr: SocketAddr,
    timestamp_unix_ms: u64,
) -> Result<Vec<u8>, Error> {
    let response = GatewayReflexiveResponse {
        nonce: request.nonce,
        observed_addr,
        gateway_id: gateway_id.to_owned(),
        relay_socket_addr,
        timestamp_unix_ms,
    };
    Ok(wire::encode_control(
        ControlType::ReflexiveResponse,
        &to_cbor(&response)?,
    ))
}

/// A signed request whose envelope verified and whose payload decoded, not yet admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authenticated<T> {
    /// The verified envelope.
    pub envelope: ControlEnvelope,
    /// The decoded payload.
    pub payload: T,
}

impl<T> Authenticated<T> {
    /// The machine id the envelope names.
    pub fn machine_id(&self) -> &str {
        self.envelope.machine_id.as_deref().unwrap_or_default()
    }

    /// Admits the request from the machine the relay's configuration expects for this
    /// payload: the machine id and Ed25519 key must be the pinned ones, then the nonce
    /// goes through `guard` (in that order, as nsgw does, so a foreign machine cannot burn
    /// another machine's nonce).
    pub fn admit(
        &self,
        machine_id: &str,
        machine_key_pub: &[u8; 32],
        guard: &ReplayGuard,
        now: u64,
    ) -> Result<(), Error> {
        if self.machine_id() != machine_id {
            return Err(Error::UnknownMachine);
        }
        if &self.envelope.machine_key_pub != machine_key_pub {
            return Err(Error::InvalidSignature);
        }
        guard.check(self.envelope.nonce, now)
    }
}

fn open<T: DeserializeOwned>(
    api: &str,
    envelope_cbor: &[u8],
    now: u64,
) -> Result<Authenticated<T>, Error> {
    let envelope = ControlEnvelope::from_cbor(envelope_cbor)?;
    if envelope.api != api {
        return Err(Error::UnexpectedApi(envelope.api));
    }
    if envelope.machine_id.is_none() {
        return Err(Error::UnknownMachine);
    }
    envelope.verify_request(now)?;
    let payload = from_cbor(&envelope.payload)?;
    Ok(Authenticated { envelope, payload })
}

/// Decodes and verifies a `register_source` payload.
///
/// This is nsgw `decode_registration` up to the target lookup: look up the target by
/// `payload.nsn_pubkey`, then [`Authenticated::admit`] with the target's pinned machine id
/// and key.
pub fn open_register_source(
    envelope_cbor: &[u8],
    now: u64,
) -> Result<Authenticated<WgRelayRegistrationRequest>, Error> {
    open(WG_RELAY_REGISTER_SOURCE, envelope_cbor, now)
}

/// Decodes and verifies a `gateway.reflexive` request payload.
///
/// This is nsgw `decode_reflexive_request` up to authorization: authorize by
/// `payload.peer_key_pub`, then [`Authenticated::admit`].
pub fn open_reflexive_request(
    envelope_cbor: &[u8],
    now: u64,
) -> Result<Authenticated<GatewayReflexiveRequest>, Error> {
    open(GATEWAY_REFLEXIVE, envelope_cbor, now)
}

/// Why a reflexive response was not accepted (ns `IngestOutcome`'s rejections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyError {
    /// The payload is not a CBOR `GatewayReflexiveResponse`.
    Decode(String),
    /// The echoed nonce is all-zero, which is never issued.
    ZeroNonce,
    /// The echoed nonce is not outstanding: foreign, spoofed or expired.
    UnknownNonce,
    /// The echoed nonce was already consumed by an earlier response.
    Replay,
}

impl fmt::Display for ReplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(err) => write!(f, "malformed reflexive response: {err}"),
            Self::ZeroNonce => f.write_str("reflexive response with a zero nonce"),
            Self::UnknownNonce => f.write_str("reflexive response with an unknown nonce"),
            Self::Replay => f.write_str("replayed reflexive response"),
        }
    }
}

impl std::error::Error for ReplyError {}

/// The peer's side of the nonce binding (ns `ReflexiveGatherer`'s nonce bookkeeping).
///
/// [`issue`](Self::issue) hands out a fresh nonce for a request and records it as
/// outstanding; [`accept`](Self::accept) takes a response only if it echoes an
/// outstanding nonce, consumes it, and remembers it to reject a replay. Both sets expire
/// after [`REFLEXIVE_NONCE_TTL`].
#[derive(Debug, Default)]
pub struct PendingNonces {
    outstanding: HashMap<[u8; 16], Instant>,
    consumed: HashMap<[u8; 16], Instant>,
}

impl PendingNonces {
    /// Backstop cap on each set (ns `MAX_NONCES`).
    const MAX_NONCES: usize = 256;

    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh non-zero nonce, outstanding from `now`.
    pub fn issue(&mut self, now: Instant) -> [u8; 16] {
        self.gc(now);
        let nonce = loop {
            let nonce = random_nonce();
            if nonce != [0; 16]
                && !self.outstanding.contains_key(&nonce)
                && !self.consumed.contains_key(&nonce)
            {
                break nonce;
            }
        };
        self.outstanding.insert(nonce, now);
        nonce
    }

    /// Accepts the payload of a [`ControlType::ReflexiveResponse`] frame if it echoes an
    /// outstanding nonce, and returns the response.
    pub fn accept(
        &mut self,
        payload: &[u8],
        now: Instant,
    ) -> Result<GatewayReflexiveResponse, ReplyError> {
        self.gc(now);
        let response: GatewayReflexiveResponse =
            from_cbor(payload).map_err(|err| ReplyError::Decode(err.to_string()))?;
        if response.nonce == [0; 16] {
            return Err(ReplyError::ZeroNonce);
        }
        if self.consumed.contains_key(&response.nonce) {
            return Err(ReplyError::Replay);
        }
        if self.outstanding.remove(&response.nonce).is_none() {
            return Err(ReplyError::UnknownNonce);
        }
        self.consumed.insert(response.nonce, now);
        Ok(response)
    }

    fn gc(&mut self, now: Instant) {
        let fresh = |at: &mut Instant| now.saturating_duration_since(*at) < REFLEXIVE_NONCE_TTL;
        self.outstanding.retain(|_, at| fresh(at));
        self.consumed.retain(|_, at| fresh(at));
        if self.outstanding.len() > Self::MAX_NONCES {
            self.outstanding.clear();
        }
        if self.consumed.len() > Self::MAX_NONCES {
            self.consumed.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::super::envelope::unix_now_secs;
    use super::*;

    fn now() -> u64 {
        unix_now_secs().unwrap()
    }

    fn payload_of(frame: &[u8], expected: ControlType) -> &[u8] {
        let (msg_type, payload) = wire::decode_control(frame).unwrap();
        assert_eq!(msg_type, expected);
        payload
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// ns `register_source_datagram_roundtrips_and_verifies`, with the same fixed key.
    #[test]
    fn register_source_round_trips_and_verifies() {
        let key = MachineKey::from_seed(&[9; 32]);
        let frame = build_register_source("m-1", &key, [3; 32]).unwrap();
        let payload = payload_of(&frame, ControlType::RegisterSource);
        let request = open_register_source(payload, now()).unwrap();
        assert_eq!(request.envelope.api, WG_RELAY_REGISTER_SOURCE);
        assert_eq!(request.machine_id(), "m-1");
        assert_eq!(request.envelope.machine_key_pub, key.public());
        assert_eq!(request.payload.nsn_pubkey, [3; 32]);
        request
            .admit("m-1", &key.public(), &ReplayGuard::new(), now())
            .unwrap();
    }

    /// The ns datagram is the ns magic followed by the same bytes this frame carries
    /// after its control header.
    #[test]
    fn ns_datagram_maps_to_the_control_frame() {
        let key = MachineKey::from_seed(&[9; 32]);
        let frame = build_register_source("m-1", &key, [3; 32]).unwrap();
        let mut ns_datagram = WG_RELAY_REGISTRATION_MAGIC.to_vec();
        ns_datagram.extend_from_slice(&frame[wire::CONTROL_HEADER_LEN..]);
        let body = ns_datagram
            .strip_prefix(WG_RELAY_REGISTRATION_MAGIC.as_slice())
            .unwrap();
        assert!(open_register_source(body, now()).is_ok());
    }

    /// ns `gateway_reflexive_datagram_roundtrips_and_verifies`, with the same fixed values.
    #[test]
    fn reflexive_request_round_trips_and_verifies() {
        let key = MachineKey::from_seed(&[7; 32]);
        let frame = build_reflexive_request("m-2", &key, [4; 32], [0xAB; 16]).unwrap();
        let payload = payload_of(&frame, ControlType::ReflexiveRequest);
        let request = open_reflexive_request(payload, now()).unwrap();
        assert_eq!(request.envelope.api, GATEWAY_REFLEXIVE);
        assert_eq!(request.machine_id(), "m-2");
        assert_eq!(
            request.payload,
            GatewayReflexiveRequest {
                peer_key_pub: [4; 32],
                nonce: [0xAB; 16]
            }
        );
    }

    #[test]
    fn payload_cbor_shapes_match_ns() {
        let value: Value = from_cbor(
            &to_cbor(&GatewayReflexiveRequest {
                peer_key_pub: [4; 32],
                nonce: [0xAB; 16],
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            value,
            Value::Map(vec![
                (
                    Value::Text("peer_key_pub".into()),
                    Value::Bytes(vec![4; 32])
                ),
                (Value::Text("nonce".into()), Value::Bytes(vec![0xAB; 16])),
            ])
        );
        let registration = to_cbor(&WgRelayRegistrationRequest {
            nsn_pubkey: [3; 32],
        })
        .unwrap();
        let mut golden = vec![0xA1, 0x6A];
        golden.extend_from_slice(b"nsn_pubkey");
        golden.extend_from_slice(&[0x58, 0x20]);
        golden.extend_from_slice(&[3; 32]);
        assert_eq!(registration, golden);
    }

    #[test]
    fn open_rejects_the_wrong_api() {
        let key = MachineKey::generate();
        let frame = build_reflexive_request("m-2", &key, [4; 32], [1; 16]).unwrap();
        let payload = payload_of(&frame, ControlType::ReflexiveRequest);
        assert!(matches!(
            open_register_source(payload, now()),
            Err(Error::UnexpectedApi(api)) if api == GATEWAY_REFLEXIVE
        ));
    }

    #[test]
    fn open_rejects_a_missing_machine_id() {
        let key = MachineKey::generate();
        let payload = to_cbor(&WgRelayRegistrationRequest {
            nsn_pubkey: [3; 32],
        })
        .unwrap();
        let envelope = ControlEnvelope::sign_request(
            WG_RELAY_REGISTER_SOURCE,
            None,
            key.public(),
            payload,
            |m| key.sign(m),
        )
        .unwrap();
        assert!(matches!(
            open_register_source(&envelope.to_cbor().unwrap(), now()),
            Err(Error::UnknownMachine)
        ));
    }

    #[test]
    fn open_rejects_bad_signature_and_expired_timestamp() {
        let key = MachineKey::generate();
        let frame = build_register_source("m-1", &key, [3; 32]).unwrap();
        let payload = payload_of(&frame, ControlType::RegisterSource);
        let mut envelope = ControlEnvelope::from_cbor(payload).unwrap();
        envelope.signature[10] ^= 1;
        assert!(matches!(
            open_register_source(&envelope.to_cbor().unwrap(), now()),
            Err(Error::InvalidSignature)
        ));
        let expired = now() + super::super::envelope::MAX_CLOCK_SKEW_SECS + 1;
        assert!(matches!(
            open_register_source(payload, expired),
            Err(Error::ClockSkew { .. })
        ));
    }

    #[test]
    fn open_rejects_a_request_signed_under_the_response_domain() {
        let key = MachineKey::generate();
        let payload = to_cbor(&WgRelayRegistrationRequest {
            nsn_pubkey: [3; 32],
        })
        .unwrap();
        let envelope = ControlEnvelope::sign_response(
            WG_RELAY_REGISTER_SOURCE,
            Some("m-1".into()),
            key.public(),
            payload,
            |m| key.sign(m),
        )
        .unwrap();
        assert!(matches!(
            open_register_source(&envelope.to_cbor().unwrap(), now()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn admit_pins_machine_and_rejects_replay() {
        let key = MachineKey::generate();
        let other = MachineKey::generate();
        let guard = ReplayGuard::new();
        let frame = build_register_source("m-1", &key, [3; 32]).unwrap();
        let request =
            open_register_source(payload_of(&frame, ControlType::RegisterSource), now()).unwrap();
        assert!(matches!(
            request.admit("m-2", &key.public(), &guard, now()),
            Err(Error::UnknownMachine)
        ));
        assert!(matches!(
            request.admit("m-1", &other.public(), &guard, now()),
            Err(Error::InvalidSignature)
        ));
        // Rejected admissions did not consume the nonce.
        request.admit("m-1", &key.public(), &guard, now()).unwrap();
        assert!(matches!(
            request.admit("m-1", &key.public(), &guard, now()),
            Err(Error::Replay)
        ));
    }

    fn response_payload(nonce: [u8; 16]) -> Vec<u8> {
        let request = GatewayReflexiveRequest {
            peer_key_pub: [4; 32],
            nonce,
        };
        let frame = build_reflexive_response(
            &request,
            addr("203.0.113.9:51820"),
            "gw-1",
            addr("198.51.100.1:51821"),
            1_700_000_000_000,
        )
        .unwrap();
        payload_of(&frame, ControlType::ReflexiveResponse).to_vec()
    }

    #[test]
    fn reflexive_reply_binds_to_the_request_nonce() {
        let mut pending = PendingNonces::new();
        let t0 = Instant::now();
        let nonce = pending.issue(t0);
        assert_ne!(nonce, [0; 16]);
        let response = pending.accept(&response_payload(nonce), t0).unwrap();
        assert_eq!(response.nonce, nonce);
        assert_eq!(response.observed_addr, addr("203.0.113.9:51820"));
        assert_eq!(response.gateway_id, "gw-1");
        assert_eq!(response.relay_socket_addr, addr("198.51.100.1:51821"));
        assert_eq!(response.timestamp_unix_ms, 1_700_000_000_000);
    }

    #[test]
    fn reflexive_reply_rejections() {
        let mut pending = PendingNonces::new();
        let t0 = Instant::now();
        let nonce = pending.issue(t0);
        assert_eq!(
            pending.accept(&response_payload([5; 16]), t0),
            Err(ReplyError::UnknownNonce)
        );
        assert_eq!(
            pending.accept(&response_payload([0; 16]), t0),
            Err(ReplyError::ZeroNonce)
        );
        assert!(matches!(
            pending.accept(b"\xFF", t0),
            Err(ReplyError::Decode(_))
        ));
        pending.accept(&response_payload(nonce), t0).unwrap();
        assert_eq!(
            pending.accept(&response_payload(nonce), t0),
            Err(ReplyError::Replay)
        );
    }

    #[test]
    fn reflexive_nonce_expires() {
        let mut pending = PendingNonces::new();
        let t0 = Instant::now();
        let nonce = pending.issue(t0);
        let late = t0 + REFLEXIVE_NONCE_TTL;
        assert_eq!(
            pending.accept(&response_payload(nonce), late),
            Err(ReplyError::UnknownNonce)
        );
    }

    #[test]
    fn reflexive_response_round_trips_through_cbor() {
        let response = GatewayReflexiveResponse {
            nonce: [1; 16],
            observed_addr: addr("[2001:db8::1]:4000"),
            gateway_id: "gw".into(),
            relay_socket_addr: addr("192.0.2.1:51820"),
            timestamp_unix_ms: 42,
        };
        let decoded: GatewayReflexiveResponse = from_cbor(&to_cbor(&response).unwrap()).unwrap();
        assert_eq!(decoded, response);
    }
}
