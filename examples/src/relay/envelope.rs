//! The ns signed control envelope and the machine key that signs it.
//!
//! A port of ns `control::envelope` (same owner): field names, CBOR encoding, signing input,
//! domain strings, clock skew and replay window are unchanged, so an envelope built here
//! verifies in ns and nsgw and the other way round. The wire format is CBOR (RFC 8949) via
//! `ciborium`; the Ed25519 signature covers a length-prefixed binary signing input, not the
//! CBOR bytes, so verification does not depend on a canonical encoder.
//!
//! ```
//! use nsplane_examples::relay::envelope::{ControlEnvelope, MachineKey, unix_now_secs};
//!
//! let key = MachineKey::generate();
//! let envelope = ControlEnvelope::sign_request(
//!     "info.get", None, key.public(), vec![0xA0], |input| key.sign(input),
//! )?;
//! let decoded = ControlEnvelope::from_cbor(&envelope.to_cbor()?)?;
//! decoded.verify_request(unix_now_secs()?)?;
//! # Ok::<(), nsplane_examples::relay::envelope::Error>(())
//! ```

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Wire-format version of the envelope.
pub const ENVELOPE_VERSION: u8 = 1;

/// Domain separator of request (client to server) signatures.
pub const DOMAIN_REQUEST: &[u8] = b"nsio-ctrl-v1\0";

/// Domain separator of response (server to client) signatures.
pub const DOMAIN_RESPONSE: &[u8] = b"nsio-ctrl-v1-resp\0";

/// Maximum accepted clock skew between peers, in seconds.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Replay window: a nonce is remembered this long, in seconds.
pub const REPLAY_WINDOW_SECS: u64 = 120;

/// Errors of envelope construction, encoding, verification and admission.
#[derive(Debug)]
pub enum Error {
    /// The envelope version is not [`ENVELOPE_VERSION`].
    InvalidVersion(u8),
    /// The timestamp is more than [`MAX_CLOCK_SKEW_SECS`] away from `now`.
    ClockSkew {
        /// The envelope timestamp.
        ts: u64,
        /// The verifier's clock.
        now: u64,
    },
    /// The Ed25519 signature does not verify, or a pinned key does not match.
    InvalidSignature,
    /// The bytes are not the expected CBOR.
    CborDecode(String),
    /// CBOR encoding failed.
    CborEncode(String),
    /// The machine key bytes are not an Ed25519 public key.
    InvalidKey,
    /// The system clock is before the Unix epoch.
    ClockBeforeEpoch,
    /// The nonce was already accepted inside the replay window.
    Replay,
    /// The envelope carries a different API than the message expects.
    UnexpectedApi(String),
    /// The request carries no machine id, or not the pinned one.
    UnknownMachine,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(v) => write!(f, "unsupported envelope version: {v}"),
            Self::ClockSkew { ts, now } => write!(
                f,
                "clock skew exceeds {MAX_CLOCK_SKEW_SECS}s: ts={ts}, now={now}"
            ),
            Self::InvalidSignature => f.write_str("signature verification failed"),
            Self::CborDecode(err) => write!(f, "malformed CBOR: {err}"),
            Self::CborEncode(err) => write!(f, "cbor encode: {err}"),
            Self::InvalidKey => f.write_str("invalid verifying key bytes"),
            Self::ClockBeforeEpoch => f.write_str("system clock before epoch"),
            Self::Replay => f.write_str("replayed envelope nonce"),
            Self::UnexpectedApi(api) => write!(f, "unexpected api {api}"),
            Self::UnknownMachine => f.write_str("missing or unexpected machine_id"),
        }
    }
}

impl std::error::Error for Error {}

/// Sliding-window nonce cache that rejects a replayed envelope.
///
/// Signature and clock-skew checks alone accept a captured envelope again while it is
/// fresh. The guard records each accepted nonce for [`REPLAY_WINDOW_SECS`] and rejects a
/// second sighting. Clones share the state.
#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    inner: Arc<Mutex<HashMap<[u8; 16], u64>>>,
}

impl ReplayGuard {
    /// Hard cap on retained nonces; a backstop against a flood of distinct nonces.
    const MAX_ENTRIES: usize = 4096;

    /// An empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `nonce` as seen at `now` (Unix seconds), rejecting a duplicate inside the
    /// window. Entries older than the window are evicted on each call; past the entry cap
    /// the cache is cleared rather than grown.
    pub fn check(&self, nonce: [u8; 16], now: u64) -> Result<(), Error> {
        let mut seen = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.retain(|_, &mut ts| now.saturating_sub(ts) <= REPLAY_WINDOW_SECS);
        if seen.len() >= Self::MAX_ENTRIES {
            seen.clear();
        }
        if seen.contains_key(&nonce) {
            return Err(Error::Replay);
        }
        seen.insert(nonce, now);
        Ok(())
    }
}

/// The signed envelope every ns control message rides in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlEnvelope {
    /// Wire-format version, [`ENVELOPE_VERSION`].
    pub v: u8,
    /// Logical API identifier, e.g. `wg_relay.register_source`.
    pub api: String,
    /// Unix seconds at construction.
    pub ts: u64,
    /// 16 random bytes; the replay-cache key.
    #[serde(with = "byte_array")]
    pub nonce: [u8; 16],
    /// The calling machine; `None` only before one is assigned.
    pub machine_id: Option<String>,
    /// Ed25519 public key of the signer: the machine key on requests, the server key on
    /// responses.
    #[serde(with = "byte_array")]
    pub machine_key_pub: [u8; 32],
    /// The CBOR-encoded inner payload, opaque to the envelope.
    #[serde(with = "byte_vec")]
    pub payload: Vec<u8>,
    /// Ed25519 signature over the signing input.
    #[serde(with = "byte_array")]
    pub signature: [u8; 64],
}

impl ControlEnvelope {
    /// Builds and signs a request envelope with a fresh nonce and the current time.
    ///
    /// `sign` returns the Ed25519 signature of its input, e.g. `|m| key.sign(m)` for a
    /// [`MachineKey`].
    pub fn sign_request(
        api: impl Into<String>,
        machine_id: Option<String>,
        machine_key_pub: [u8; 32],
        payload_cbor: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<Self, Error> {
        Ok(Self::unsigned(
            api.into(),
            unix_now_secs()?,
            random_nonce(),
            machine_id,
            machine_key_pub,
            payload_cbor,
        )
        .signed(DOMAIN_REQUEST, sign))
    }

    /// Builds and signs a response envelope under [`DOMAIN_RESPONSE`] with the server key.
    /// `machine_id` names the target machine so the response cannot be re-targeted.
    pub fn sign_response(
        api: impl Into<String>,
        machine_id: Option<String>,
        server_key_pub: [u8; 32],
        payload_cbor: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<Self, Error> {
        Ok(Self::unsigned(
            api.into(),
            unix_now_secs()?,
            random_nonce(),
            machine_id,
            server_key_pub,
            payload_cbor,
        )
        .signed(DOMAIN_RESPONSE, sign))
    }

    const fn unsigned(
        api: String,
        ts: u64,
        nonce: [u8; 16],
        machine_id: Option<String>,
        machine_key_pub: [u8; 32],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            v: ENVELOPE_VERSION,
            api,
            ts,
            nonce,
            machine_id,
            machine_key_pub,
            payload,
            signature: [0; 64],
        }
    }

    fn signed(mut self, domain: &[u8], sign: impl FnOnce(&[u8]) -> [u8; 64]) -> Self {
        self.signature = sign(&self.signing_input(domain));
        self
    }

    /// Verifies a request envelope against its own `machine_key_pub`: version, clock skew
    /// against `now` (Unix seconds) and signature. Replay and key pinning are the
    /// caller's (see [`ReplayGuard`] and `messages::Authenticated::admit`).
    pub fn verify_request(&self, now: u64) -> Result<(), Error> {
        self.verify_with_domain(DOMAIN_REQUEST, now)
    }

    /// Verifies a response envelope signed by the pinned `expected_server_key`.
    pub fn verify_response(&self, now: u64, expected_server_key: &[u8; 32]) -> Result<(), Error> {
        if &self.machine_key_pub != expected_server_key {
            return Err(Error::InvalidSignature);
        }
        self.verify_with_domain(DOMAIN_RESPONSE, now)
    }

    fn verify_with_domain(&self, domain: &[u8], now: u64) -> Result<(), Error> {
        if self.v != ENVELOPE_VERSION {
            return Err(Error::InvalidVersion(self.v));
        }
        if now.abs_diff(self.ts) > MAX_CLOCK_SKEW_SECS {
            return Err(Error::ClockSkew { ts: self.ts, now });
        }
        let key = VerifyingKey::from_bytes(&self.machine_key_pub).map_err(|_| Error::InvalidKey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify(&self.signing_input(domain), &signature)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Encodes the envelope as CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(256 + self.payload.len());
        ciborium::into_writer(self, &mut buf).map_err(|err| Error::CborEncode(err.to_string()))?;
        Ok(buf)
    }

    /// Decodes a CBOR envelope.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        ciborium::from_reader(bytes).map_err(|err| Error::CborDecode(err.to_string()))
    }

    /// The signing input:
    ///
    /// ```text
    /// domain || u8(v) || u32_be(len(api)) || api || u64_be(ts) || nonce[16]
    ///        || u8(0)                                if machine_id is None
    ///        || u8(1) || u32_be(len) || machine_id   if Some
    ///        || machine_key_pub[32] || sha256(payload)[32]
    /// ```
    fn signing_input(&self, domain: &[u8]) -> Vec<u8> {
        let api = self.api.as_bytes();
        let mut out = Vec::with_capacity(domain.len() + 1 + 4 + api.len() + 8 + 16 + 64 + 64);
        out.extend_from_slice(domain);
        out.push(self.v);
        push_len_prefixed(&mut out, api);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        match &self.machine_id {
            None => out.push(0),
            Some(id) => {
                out.push(1);
                push_len_prefixed(&mut out, id.as_bytes());
            }
        }
        out.extend_from_slice(&self.machine_key_pub);
        out.extend_from_slice(&Sha256::digest(&self.payload));
        out
    }
}

/// Appends `u32_be(len) || bytes`. Lengths beyond `u32::MAX` saturate; such an envelope
/// does not fit a datagram anyway.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The current time in Unix seconds.
pub fn unix_now_secs() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| Error::ClockBeforeEpoch)
}

/// 16 random bytes from the OS.
pub fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// A machine's Ed25519 signing key.
///
/// The file format is one line: the standard base64 of the 32-byte Ed25519 secret seed
/// (`openssl rand -base64 32` produces one).
#[derive(Debug, Clone)]
pub struct MachineKey(SigningKey);

impl MachineKey {
    /// A fresh random key.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self(SigningKey::from_bytes(&seed))
    }

    /// The key whose secret seed is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Parses the base64 file format.
    pub fn from_base64(text: &str) -> io::Result<Self> {
        let seed = STANDARD
            .decode(text.trim())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "machine key must decode to 32 bytes",
            )
        })?;
        Ok(Self::from_seed(&seed))
    }

    /// Reads a key file.
    pub fn load(path: &Path) -> io::Result<Self> {
        Self::from_base64(&fs::read_to_string(path)?)
    }

    /// The base64 file format of the secret seed.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0.to_bytes())
    }

    /// The Ed25519 public key, as carried in `machine_key_pub`.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The public key, standard base64.
    pub fn public_b64(&self) -> String {
        STANDARD.encode(self.public())
    }

    /// The Ed25519 signature of `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

/// Serde for fixed byte arrays as CBOR byte strings (major type 2), as ns encodes them.
pub(crate) mod byte_array {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        deserializer.deserialize_bytes(ArrayVisitor::<N>)
    }

    struct ArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{N} bytes")
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            bytes
                .try_into()
                .map_err(|_| E::invalid_length(bytes.len(), &self))
        }

        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
            let bytes = super::byte_vec::collect_seq(seq)?;
            self.visit_bytes(&bytes)
        }
    }
}

/// Serde for a byte vector as a CBOR byte string, as ns `serde_bytes::ByteBuf` encodes it.
pub(crate) mod byte_vec {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_byte_buf(VecVisitor)
    }

    pub(crate) fn collect_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        Ok(bytes)
    }

    struct VecVisitor;

    impl<'de> Visitor<'de> for VecVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a byte string")
        }

        fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            Ok(bytes.to_vec())
        }

        fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Ok(bytes)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
            collect_seq(seq)
        }
    }
}

#[cfg(test)]
mod tests {
    use ciborium::Value;

    use super::*;

    fn now() -> u64 {
        unix_now_secs().unwrap()
    }

    fn request(key: &MachineKey, api: &str, machine_id: Option<&str>) -> ControlEnvelope {
        ControlEnvelope::sign_request(
            api,
            machine_id.map(str::to_owned),
            key.public(),
            vec![1, 2, 3],
            |m| key.sign(m),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_cbor() {
        let key = MachineKey::generate();
        let envelope = request(&key, "machine.heartbeat", Some("machine-1"));
        let decoded = ControlEnvelope::from_cbor(&envelope.to_cbor().unwrap()).unwrap();
        assert_eq!(decoded, envelope);
        decoded.verify_request(now()).unwrap();
    }

    #[test]
    fn rejects_clock_skew_both_ways() {
        let key = MachineKey::generate();
        let envelope = request(&key, "info.get", None);
        let late = envelope.ts + MAX_CLOCK_SKEW_SECS + 1;
        let early = envelope.ts - MAX_CLOCK_SKEW_SECS - 1;
        assert!(matches!(
            envelope.verify_request(late),
            Err(Error::ClockSkew { .. })
        ));
        assert!(matches!(
            envelope.verify_request(early),
            Err(Error::ClockSkew { .. })
        ));
        envelope
            .verify_request(envelope.ts + MAX_CLOCK_SKEW_SECS)
            .unwrap();
    }

    #[test]
    fn rejects_wrong_version() {
        let key = MachineKey::generate();
        let mut envelope = request(&key, "info.get", None);
        envelope.v = 99;
        assert!(matches!(
            envelope.verify_request(now()),
            Err(Error::InvalidVersion(99))
        ));
    }

    #[test]
    fn tampered_fields_fail_the_signature() {
        let key = MachineKey::generate();
        let other = MachineKey::generate();
        let envelope = request(&key, "machine.heartbeat", Some("m-1"));
        let tampers: [fn(&mut ControlEnvelope, &MachineKey); 6] = [
            |e, _| e.api = "machine.register".into(),
            |e, _| e.machine_id = Some("m-2".into()),
            |e, _| e.machine_id = None,
            |e, _| e.nonce[0] ^= 1,
            |e, _| e.payload = vec![9, 9, 9],
            |e, other| e.machine_key_pub = other.public(),
        ];
        for tamper in tampers {
            let mut forged = envelope.clone();
            tamper(&mut forged, &other);
            assert!(matches!(
                forged.verify_request(now()),
                Err(Error::InvalidSignature)
            ));
        }
        let mut bad_signature = envelope;
        bad_signature.signature[0] ^= 1;
        assert!(matches!(
            bad_signature.verify_request(now()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn domains_are_isolated() {
        let key = MachineKey::generate();
        let envelope = request(&key, "info.get", None);
        assert!(matches!(
            envelope.verify_response(now(), &key.public()),
            Err(Error::InvalidSignature)
        ));
        let response =
            ControlEnvelope::sign_response("info.get", None, key.public(), vec![], |m| key.sign(m))
                .unwrap();
        response.verify_response(now(), &key.public()).unwrap();
        assert!(matches!(
            response.verify_request(now()),
            Err(Error::InvalidSignature)
        ));
        assert!(matches!(
            response.verify_response(now(), &[0; 32]),
            Err(Error::InvalidSignature)
        ));
    }

    /// ns `golden_sig_input_shape`, byte for byte.
    #[test]
    fn golden_sig_input_shape() {
        let api = "machine.heartbeat";
        let ts: u64 = 0x0102_0304_0506_0708;
        let nonce = [0xAAu8; 16];
        let key = [0xBBu8; 32];
        let payload = b"hello";
        let envelope = ControlEnvelope {
            v: ENVELOPE_VERSION,
            api: api.into(),
            ts,
            nonce,
            machine_id: Some("m-id".into()),
            machine_key_pub: key,
            payload: payload.to_vec(),
            signature: [0; 64],
        };
        let out = envelope.signing_input(DOMAIN_REQUEST);
        assert_eq!(out.len(), 13 + 1 + 4 + 17 + 8 + 16 + 9 + 32 + 32);
        assert_eq!(&out[0..13], DOMAIN_REQUEST);
        assert_eq!(out[13], ENVELOPE_VERSION);
        assert_eq!(&out[14..18], &17u32.to_be_bytes());
        assert_eq!(&out[18..35], api.as_bytes());
        assert_eq!(&out[35..43], &ts.to_be_bytes());
        assert_eq!(&out[43..59], &nonce);
        assert_eq!(out[59], 1);
        assert_eq!(&out[60..64], &4u32.to_be_bytes());
        assert_eq!(&out[64..68], b"m-id");
        assert_eq!(&out[68..100], &key);
        assert_eq!(&out[100..132], Sha256::digest(payload).as_slice());
    }

    /// ns `none_machine_id_encoded_as_zero_byte`.
    #[test]
    fn none_machine_id_encoded_as_zero_byte() {
        let envelope = ControlEnvelope {
            v: ENVELOPE_VERSION,
            api: "info.get".into(),
            ts: 0,
            nonce: [0; 16],
            machine_id: None,
            machine_key_pub: [0; 32],
            payload: vec![],
            signature: [0; 64],
        };
        let out = envelope.signing_input(DOMAIN_REQUEST);
        assert_eq!(out.len(), 13 + 1 + 4 + 8 + 8 + 16 + 1 + 32 + 32);
        assert_eq!(out[13 + 1 + 4 + 8 + 8 + 16], 0);
    }

    /// The CBOR shape ns produces: a map in declaration order, fixed arrays and the payload
    /// as byte strings, `machine_id` as null when absent.
    #[test]
    fn cbor_shape_matches_ns() {
        let key = MachineKey::from_seed(&[9; 32]);
        let envelope = ControlEnvelope::unsigned(
            "info.get".into(),
            1_700_000_000,
            [0xAB; 16],
            None,
            key.public(),
            vec![0xA0],
        )
        .signed(DOMAIN_REQUEST, |m| key.sign(m));
        let bytes = envelope.to_cbor().unwrap();
        let Value::Map(entries) = ciborium::from_reader::<Value, _>(&bytes[..]).unwrap() else {
            panic!("not a map");
        };
        let keys: Vec<_> = entries
            .iter()
            .map(|(k, _)| k.as_text().unwrap().to_owned())
            .collect();
        assert_eq!(
            keys,
            [
                "v",
                "api",
                "ts",
                "nonce",
                "machine_id",
                "machine_key_pub",
                "payload",
                "signature"
            ]
        );
        assert_eq!(entries[0].1, Value::Integer(1.into()));
        assert_eq!(entries[3].1, Value::Bytes(vec![0xAB; 16]));
        assert_eq!(entries[4].1, Value::Null);
        assert_eq!(entries[5].1, Value::Bytes(key.public().to_vec()));
        assert_eq!(entries[6].1, Value::Bytes(vec![0xA0]));
        assert!(matches!(&entries[7].1, Value::Bytes(sig) if sig.len() == 64));
        // Ed25519 is deterministic: the same inputs give the same bytes.
        let again = ControlEnvelope::unsigned(
            "info.get".into(),
            1_700_000_000,
            [0xAB; 16],
            None,
            key.public(),
            vec![0xA0],
        )
        .signed(DOMAIN_REQUEST, |m| key.sign(m));
        assert_eq!(again.to_cbor().unwrap(), bytes);
    }

    #[test]
    fn decodes_byte_fields_sent_as_arrays() {
        let key = MachineKey::generate();
        let envelope = request(&key, "info.get", None);
        let as_array = |bytes: &[u8]| {
            Value::Array(bytes.iter().map(|b| Value::Integer((*b).into())).collect())
        };
        let value = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (Value::Text("api".into()), Value::Text(envelope.api.clone())),
            (Value::Text("ts".into()), Value::Integer(envelope.ts.into())),
            (Value::Text("nonce".into()), as_array(&envelope.nonce)),
            (Value::Text("machine_id".into()), Value::Null),
            (
                Value::Text("machine_key_pub".into()),
                as_array(&envelope.machine_key_pub),
            ),
            (Value::Text("payload".into()), as_array(&envelope.payload)),
            (
                Value::Text("signature".into()),
                as_array(&envelope.signature),
            ),
        ]);
        let mut bytes = Vec::new();
        ciborium::into_writer(&value, &mut bytes).unwrap();
        assert_eq!(ControlEnvelope::from_cbor(&bytes).unwrap(), envelope);
    }

    #[test]
    fn rejects_wrong_lengths_and_garbage() {
        let key = MachineKey::generate();
        let envelope = request(&key, "info.get", None);
        let mut bytes = envelope.to_cbor().unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(
            ControlEnvelope::from_cbor(&bytes),
            Err(Error::CborDecode(_))
        ));
        let Value::Map(mut entries) =
            ciborium::from_reader::<Value, _>(&envelope.to_cbor().unwrap()[..]).unwrap()
        else {
            panic!("not a map");
        };
        entries[3].1 = Value::Bytes(vec![0; 15]);
        let mut short_nonce = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut short_nonce).unwrap();
        assert!(matches!(
            ControlEnvelope::from_cbor(&short_nonce),
            Err(Error::CborDecode(_))
        ));
    }

    #[test]
    fn replay_guard_rejects_duplicates_within_the_window() {
        let guard = ReplayGuard::new();
        guard.check([7; 16], 1_000).unwrap();
        assert!(matches!(guard.check([7; 16], 1_001), Err(Error::Replay)));
        guard.check([8; 16], 1_002).unwrap();
        assert!(matches!(guard.check([8; 16], 1_003), Err(Error::Replay)));
    }

    #[test]
    fn replay_guard_forgets_after_the_window() {
        let guard = ReplayGuard::new();
        guard.check([9; 16], 1_000).unwrap();
        guard
            .check([9; 16], 1_000 + REPLAY_WINDOW_SECS + 1)
            .unwrap();
    }

    #[test]
    fn machine_key_file_round_trip() {
        let key = MachineKey::generate();
        let path = std::env::temp_dir().join(format!("nsplane-machine-key-{}", std::process::id()));
        fs::write(&path, format!("{}\n", key.to_base64())).unwrap();
        let loaded = MachineKey::load(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(loaded.public(), key.public());
        assert_eq!(STANDARD.decode(key.public_b64()).unwrap(), key.public());
        assert!(MachineKey::from_base64("AAAA").is_err());
        assert!(MachineKey::from_base64("not base64!").is_err());
    }
}
