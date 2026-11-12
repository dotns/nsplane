//! Property tests of the request parser: the requests come from whoever may write to the
//! control socket.
//!
//! The cases come from a seeded generator, so every run tests the same inputs. A model of
//! the protocol says which `errno` a `set` request ends with and what `get` reports after
//! it; the engine runs an external transport, so no request binds a socket.

use std::collections::{BTreeMap, BTreeSet};

use nsplane::{ChannelSink, ChannelSource, ChannelTransport, Engine, EngineBuilder};

use super::*;

const PORT: u16 = 51820;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    const fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    const fn u16(&mut self) -> u16 {
        let b = self.next().to_le_bytes();
        u16::from_le_bytes([b[0], b[1]])
    }

    fn key(&mut self) -> [u8; 32] {
        std::array::from_fn(|_| self.byte())
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// Base64 with padding (RFC 4648 section 4).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (bits >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[usize::try_from(index).unwrap()]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A key as a client may write it: hex in either case, or base64 with or without padding.
fn key_text(rng: &mut Rng, key: &[u8; 32]) -> String {
    match rng.below(4) {
        0 => hex::encode(key),
        1 => hex::encode_upper(key),
        2 => base64(key),
        _ => base64(key).trim_end_matches('=').to_owned(),
    }
}

#[test]
fn a_key_parses_only_from_its_hex_or_base64_form() {
    let mut rng = Rng(0x5eed_0a01);
    let mut refused = 0;
    for _ in 0..20_000 {
        let key = rng.key();
        let text = key_text(&mut rng, &key);
        assert_eq!(parse_key(&text), Some(key), "{text}");

        // A changed character gives another key or none, and what parses is one of the
        // forms of the key it gives.
        let mut changed = text.into_bytes();
        match rng.below(4) {
            0 => {
                let at = rng.below(changed.len());
                changed[at] = rng.pick(b"0aAfFgZz+/=_- \n\xc3");
            }
            1 => {
                changed.pop();
            }
            2 => changed.push(rng.pick(b"0a=A")),
            _ => {
                let at = rng.below(changed.len());
                changed.swap(0, at);
            }
        }
        let Ok(changed) = String::from_utf8(changed) else {
            continue;
        };
        let Some(parsed) = parse_key(&changed) else {
            refused += 1;
            continue;
        };
        let padded = base64(&parsed);
        assert!(
            changed.eq_ignore_ascii_case(&hex::encode(parsed))
                || changed == padded
                || changed == padded.trim_end_matches('='),
            "{changed}"
        );
    }
    assert!(refused > 5_000, "{refused}");
}

/// What `get` reports of a peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeerModel {
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
    keepalive: u16,
    allowed_ips: BTreeSet<String>,
}

/// What `get` reports of the interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Model {
    private_key: Option<[u8; 32]>,
    peers: BTreeMap<[u8; 32], PeerModel>,
}

/// The settings of one peer section, as written.
#[derive(Debug, Default)]
struct SectionModel {
    key: [u8; 32],
    remove: bool,
    update_only: bool,
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    replace_allowed_ips: bool,
    allowed_ips: Vec<String>,
}

/// What one line of a `set` request does.
#[derive(Debug, Clone)]
enum Effect {
    Nothing,
    PrivateKey([u8; 32]),
    ReplacePeers,
    Peer([u8; 32]),
    Remove(bool),
    UpdateOnly(bool),
    PresharedKey([u8; 32]),
    Endpoint(SocketAddr),
    Keepalive(u16),
    ReplaceAllowedIps(bool),
    AllowedIp(String),
    /// The request ends here with this `errno`.
    Fail(i32),
    /// A `public_key` line whose value is not a key: it ends the section before it, which
    /// is applied, and then the request ends with `EINVAL`.
    BrokenPeer,
}

impl Model {
    /// Applies a finished peer section.
    fn commit(&mut self, section: SectionModel) -> Result<(), i32> {
        if section.remove {
            self.peers.remove(&section.key);
            return Ok(());
        }
        if section.update_only && !self.peers.contains_key(&section.key) {
            return Ok(());
        }
        if self.private_key.is_none() {
            return Err(ENOSPC);
        }
        let peer = self.peers.entry(section.key).or_default();
        if let Some(key) = section.preshared_key {
            peer.preshared_key = (key != [0; 32]).then_some(key);
        }
        if let Some(endpoint) = section.endpoint {
            peer.endpoint = Some(endpoint);
        }
        if let Some(keepalive) = section.keepalive {
            peer.keepalive = keepalive;
        }
        if section.replace_allowed_ips {
            peer.allowed_ips.clear();
        }
        peer.allowed_ips.extend(section.allowed_ips);
        Ok(())
    }

    /// Applies the lines of a `set` request and returns its `errno`. Interface settings
    /// take effect at their line; a peer section takes effect when the next one starts or
    /// the request ends, so the section a failing line stands in is not applied.
    ///
    /// A `public_key` line starts the next section even when its value is not a key: the
    /// model used to drop the section before such a line, as the implementation did, which
    /// went against "the settings before a failing one stay applied" for a section that
    /// was already complete. Its own failure, if any, is the one reported.
    fn set(&mut self, effects: &[Effect]) -> i32 {
        let mut section: Option<SectionModel> = None;
        for effect in effects {
            match (effect.clone(), &mut section) {
                (Effect::Fail(errno), _) => return errno,
                (Effect::BrokenPeer, _) => {
                    return section
                        .take()
                        .map_or(EINVAL, |done| self.commit(done).err().unwrap_or(EINVAL));
                }
                (Effect::Peer(key), _) => {
                    let started = SectionModel {
                        key,
                        ..SectionModel::default()
                    };
                    if let Some(done) = section.replace(started)
                        && let Err(errno) = self.commit(done)
                    {
                        return errno;
                    }
                }
                (Effect::Nothing, _) => {}
                (Effect::PrivateKey(key), None) => self.private_key = Some(key),
                (Effect::ReplacePeers, None) => self.peers.clear(),
                (Effect::Remove(remove), Some(s)) => s.remove = remove,
                (Effect::UpdateOnly(update_only), Some(s)) => s.update_only = update_only,
                (Effect::PresharedKey(key), Some(s)) => s.preshared_key = Some(key),
                (Effect::Endpoint(endpoint), Some(s)) => s.endpoint = Some(endpoint),
                (Effect::Keepalive(keepalive), Some(s)) => s.keepalive = Some(keepalive),
                (Effect::ReplaceAllowedIps(replace), Some(s)) => s.replace_allowed_ips = replace,
                (Effect::AllowedIp(ip), Some(s)) => s.allowed_ips.push(ip),
                (other, _) => panic!("{other:?} in the wrong part of a request"),
            }
        }
        section.map_or(0, |done| self.commit(done).err().unwrap_or(0))
    }

    /// Reads the model back from a `get` response.
    fn read(response: &str) -> Self {
        let mut model = Self::default();
        let mut current = None;
        let body = response.strip_suffix("errno=0\n\n").unwrap();
        for line in body.lines() {
            let (key, value) = line.split_once('=').unwrap();
            let peer = current.and_then(|key| model.peers.get_mut(&key));
            match (key, peer) {
                ("private_key", None) => model.private_key = parse_key(value),
                ("listen_port", None) => assert_eq!(value, PORT.to_string()),
                ("public_key", _) => {
                    let key = parse_key(value).unwrap();
                    assert_eq!(model.peers.insert(key, PeerModel::default()), None);
                    current = Some(key);
                }
                ("preshared_key", Some(peer)) => peer.preshared_key = parse_key(value),
                ("endpoint", Some(peer)) => peer.endpoint = Some(value.parse().unwrap()),
                ("persistent_keepalive_interval", Some(peer)) => {
                    peer.keepalive = value.parse().unwrap();
                }
                ("allowed_ip", Some(peer)) => {
                    assert!(peer.allowed_ips.insert(value.to_owned()), "{line} twice");
                }
                ("protocol_version", Some(_)) => assert_eq!(value, "1"),
                // Counters, not settings: a peer with an endpoint and a keepalive may have
                // been sent a handshake initiation by now.
                (
                    "last_handshake_time_sec"
                    | "last_handshake_time_nsec"
                    | "rx_bytes"
                    | "tx_bytes",
                    Some(_),
                ) => assert!(value.parse::<u64>().is_ok(), "{line}"),
                _ => panic!("unexpected line {line:?}"),
            }
        }
        model
    }
}

fn boolean(rng: &mut Rng) -> bool {
    rng.chance(50)
}

/// A line that fails wherever it stands, with its `errno`.
fn broken_line(rng: &mut Rng, peers: &[[u8; 32]]) -> (String, i32) {
    let key = hex::encode(peers[0]);
    let (line, errno) = match rng.below(12) {
        0 => ("no separator".to_owned(), EPROTO),
        1 => ("unknown_key=1".to_owned(), EINVAL),
        2 => (" listen_port=51820".to_owned(), EINVAL),
        3 => (format!("public_key={}", &key[1..]), EINVAL),
        4 => (
            format!("public_key={}", key.replacen(|_| true, "x", 1)),
            EINVAL,
        ),
        5 => ("public_key=".to_owned(), EINVAL),
        6 => ("=value".to_owned(), EINVAL),
        7 => ("Public_Key=00".to_owned(), EINVAL),
        8 => ("\u{feff}set=1".to_owned(), EINVAL),
        9 => ("allowed_ip".to_owned(), EPROTO),
        10 => ("get=1".to_owned(), EINVAL),
        _ => ("\t".to_owned(), EPROTO),
    };
    (line, errno)
}

/// A line of the interface part of a request.
fn interface_line(rng: &mut Rng) -> (String, Effect) {
    let fail = Effect::Fail(EINVAL);
    // Mostly settings that apply.
    let kind = if rng.chance(85) {
        rng.below(9)
    } else {
        9 + rng.below(7)
    };
    match kind {
        0..4 => {
            let key = rng.key();
            (
                format!("private_key={}", key_text(rng, &key)),
                Effect::PrivateKey(key),
            )
        }
        4 => (format!("listen_port={PORT}"), Effect::Nothing),
        5 => ("fwmark=0".to_owned(), Effect::Nothing),
        6 => ("replace_peers=false".to_owned(), Effect::Nothing),
        7 | 8 => ("replace_peers=true".to_owned(), Effect::ReplacePeers),
        // The transport is not the UAPI's to rebind.
        9 => (
            format!("listen_port={}", rng.pick(&[0, 1, 51821, 65535])),
            Effect::Fail(EADDRINUSE),
        ),
        10 => ("fwmark=7".to_owned(), Effect::Fail(EADDRINUSE)),
        11 => (
            format!(
                "listen_port={}",
                rng.pick(&["65536", "-1", "", "0x10", "5 "])
            ),
            fail,
        ),
        12 => (
            format!("fwmark={}", rng.pick(&["4294967296", "-1", "", "off"])),
            fail,
        ),
        13 => (
            format!("replace_peers={}", rng.pick(&["1", "True", "", "yes"])),
            fail,
        ),
        14 => (format!("private_key={}", rng.pick(&["", "00", "zz"])), fail),
        // A peer setting before any peer.
        _ => (
            rng.pick(&[
                "remove=true",
                "allowed_ip=10.0.0.0/8",
                "endpoint=192.0.2.9:1",
            ])
            .to_owned(),
            fail,
        ),
    }
}

/// A line of the section of peer `index`, whose allowed IPs lie in ranges of its own.
fn peer_line(rng: &mut Rng, index: usize) -> (String, Effect) {
    let kind = if rng.chance(93) { rng.below(14) } else { 14 };
    match kind {
        0 => {
            let remove = rng.chance(30);
            (format!("remove={remove}"), Effect::Remove(remove))
        }
        1 => {
            let update_only = boolean(rng);
            (
                format!("update_only={update_only}"),
                Effect::UpdateOnly(update_only),
            )
        }
        2 | 3 => {
            let key = if rng.chance(25) { [0; 32] } else { rng.key() };
            (
                format!("preshared_key={}", key_text(rng, &key)),
                Effect::PresharedKey(key),
            )
        }
        4 | 5 => {
            let port = rng.u16();
            let endpoint = if boolean(rng) {
                SocketAddr::from(([198, 51, 100, rng.byte()], port))
            } else {
                SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.u16()], port))
            };
            (format!("endpoint={endpoint}"), Effect::Endpoint(endpoint))
        }
        6 | 7 => {
            let keepalive = rng.pick(&[0, 1, 25, 65535]);
            (
                format!("persistent_keepalive_interval={keepalive}"),
                Effect::Keepalive(keepalive),
            )
        }
        8 => {
            let replace = boolean(rng);
            (
                format!("replace_allowed_ips={replace}"),
                Effect::ReplaceAllowedIps(replace),
            )
        }
        9..13 => {
            let ip = if boolean(rng) {
                format!("10.{index}.{}.0/24", rng.below(4))
            } else {
                format!("fd00:{index}:{}::/64", 1 + rng.below(4))
            };
            (format!("allowed_ip={ip}"), Effect::AllowedIp(ip))
        }
        13 => ("protocol_version=1".to_owned(), Effect::Nothing),
        _ => (broken_peer_line(rng), Effect::Fail(EINVAL)),
    }
}

/// A line that fails in a peer section with `EINVAL`: a value that does not parse, or an
/// interface setting.
fn broken_peer_line(rng: &mut Rng) -> String {
    let (key, value) = match rng.below(8) {
        0 => ("protocol_version", rng.pick(&["0", "2", "", "v1"])),
        1 => ("remove", rng.pick(&["1", "TRUE", "", "no"])),
        2 => ("preshared_key", rng.pick(&["", "0", "!"])),
        3 => (
            "endpoint",
            rng.pick(&["", "192.0.2.1", "host:1", "::1:53", "1.2.3.4:65536"]),
        ),
        4 => (
            "persistent_keepalive_interval",
            rng.pick(&["65536", "-1", "", "1s"]),
        ),
        5 => (
            "allowed_ip",
            rng.pick(&[
                "10.0.0.0",
                "10.0.0.0/33",
                "::/129",
                "10.0.0.0/8/8",
                "",
                "/8",
                "a/8",
            ]),
        ),
        6 => rng.pick(&[
            ("replace_peers", "true"),
            ("listen_port", "51820"),
            ("fwmark", "0"),
        ]),
        _ => return format!("private_key={}", hex::encode(rng.key())),
    };
    format!("{key}={value}")
}

/// The lines of a `set` request behind `set=1`, with what each does.
fn set_request(rng: &mut Rng, peers: &[[u8; 32]]) -> Vec<(String, Effect)> {
    let mut lines = Vec::new();
    for _ in 0..rng.below(4) {
        lines.push(interface_line(rng));
    }
    for _ in 0..rng.below(4) {
        let index = rng.below(peers.len());
        let key = peers[index];
        lines.push((
            format!("public_key={}", key_text(rng, &key)),
            Effect::Peer(key),
        ));
        for _ in 0..rng.below(6) {
            lines.push(peer_line(rng, index));
        }
    }
    if rng.chance(15) {
        let (line, errno) = broken_line(rng, peers);
        let at = rng.below(lines.len() + 1);
        let effect = if line.starts_with("public_key=") {
            Effect::BrokenPeer
        } else {
            Effect::Fail(errno)
        };
        lines.insert(at, (line, effect));
    }
    lines
}

/// An engine on in-memory ends with a transport the UAPI does not own.
fn external_engine() -> (Engine, Uapi, impl Sized) {
    let near = SocketAddr::from(([192, 0, 2, 1], 1000));
    let far = SocketAddr::from(([192, 0, 2, 2], 1000));
    let (transport, far_end) =
        ChannelTransport::pair(16, (TRANSPORT_ID, near), (TRANSPORT_ID, far));
    let (source, local, mtu) = ChannelSource::new(16, 1420);
    let (sink, delivered) = ChannelSink::new(16);
    let engine = EngineBuilder::new(source, sink)
        .transport(transport)
        .build()
        .unwrap();
    let uapi = Uapi::with_external_transport(engine.handle(), PORT);
    (engine, uapi, (far_end, local, mtu, delivered))
}

async fn get(uapi: &Uapi) -> String {
    let mut out = Vec::new();
    let more = uapi
        .handle_request(&mut &b"get=1\n\n"[..], &mut out)
        .await
        .unwrap();
    assert!(more);
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn set_requests_end_with_the_errno_and_the_state_of_the_protocol() {
    let mut rng = Rng(0x5eed_0a02);
    let peers: Vec<[u8; 32]> = (0..4).map(|_| rng.key()).collect();
    let mut errnos: BTreeMap<i32, u32> = BTreeMap::new();
    for _ in 0..30 {
        let (_engine, uapi, _ends) = external_engine();
        let mut model = Model::default();
        for _ in 0..30 {
            // Several requests on one connection, each ended by an empty line, the last
            // one also by the end of the input.
            let requests: Vec<_> = (0..=rng.below(2))
                .map(|_| set_request(&mut rng, &peers))
                .collect();
            let mut input = String::new();
            for (i, lines) in requests.iter().enumerate() {
                input.push_str("set=1\n");
                for (line, _) in lines {
                    input.push_str(line);
                    input.push('\n');
                }
                if i + 1 < requests.len() || rng.chance(70) {
                    input.push('\n');
                }
            }
            let mut reader = input.as_bytes();
            for lines in &requests {
                let effects: Vec<Effect> = lines.iter().map(|(_, effect)| effect.clone()).collect();
                let errno = model.set(&effects);
                let mut out = Vec::new();
                let more = uapi.handle_request(&mut reader, &mut out).await.unwrap();
                assert_eq!(
                    String::from_utf8(out).unwrap(),
                    format!("errno={errno}\n\n"),
                    "{lines:?}"
                );
                assert_eq!(Model::read(&get(&uapi).await), model, "{lines:?}");
                *errnos.entry(errno).or_default() += 1;
                // A failed request ends the connection: the rest is not a request.
                assert_eq!(more, errno == 0);
                if !more {
                    break;
                }
            }
        }
    }
    for errno in [0, EINVAL, ENOSPC, EPROTO, EADDRINUSE] {
        assert!(
            errnos.get(&errno).is_some_and(|&count| count > 5),
            "{errnos:?}"
        );
    }
}

/// Bytes on the control socket: requests with some bytes changed, lines of any length.
fn untrusted(rng: &mut Rng, peers: &[[u8; 32]]) -> Vec<u8> {
    let mut input = Vec::new();
    for _ in 0..=rng.below(2) {
        input.extend_from_slice(rng.pick(&[
            &b"set=1\n"[..],
            b"set=1\n",
            b"get=1\n",
            b"set=2\n",
            b"\n",
        ]));
        for (line, _) in set_request(rng, peers) {
            input.extend_from_slice(line.as_bytes());
            input.push(b'\n');
        }
        input.push(b'\n');
    }
    for _ in 0..rng.below(4) {
        let at = rng.below(input.len() + 1);
        match rng.below(6) {
            0 => {
                let long = rng.pick(&[MAX_LINE_LEN - 1, MAX_LINE_LEN, MAX_LINE_LEN + 1, 9000]);
                let line = vec![rng.pick(b"a=\x00"); long];
                input.splice(at..at, line);
            }
            1 => input.insert(at, rng.pick(b"\n\r\x00\xff\xc3= ")),
            2 if at < input.len() => {
                input.remove(at);
            }
            3 if at < input.len() => input[at] ^= 1 << rng.below(8),
            4 => input.truncate(at),
            _ => {}
        }
    }
    input
}

#[tokio::test]
async fn arbitrary_bytes_get_an_errno_or_end_the_connection() {
    let mut rng = Rng(0x5eed_0a03);
    let peers: Vec<[u8; 32]> = (0..4).map(|_| rng.key()).collect();
    let (_engine, uapi, _ends) = external_engine();
    let (mut answered, mut failed) = (0, 0);
    for _ in 0..3_000 {
        let input = untrusted(&mut rng, &peers);
        let well_formed = std::str::from_utf8(&input)
            .is_ok_and(|text| text.split('\n').all(|line| line.len() <= MAX_LINE_LEN));
        let mut reader = &input[..];
        loop {
            let left = reader.len();
            let mut out = Vec::new();
            match uapi.handle_request(&mut reader, &mut out).await {
                Ok(more) => {
                    // A response is the settings of a `get` and one final errno.
                    let text = String::from_utf8(out).unwrap();
                    if left == 0 {
                        assert!(!more && text.is_empty());
                        break;
                    }
                    let errno = text
                        .strip_suffix("\n\n")
                        .and_then(|text| text.rsplit('\n').next())
                        .and_then(|line| line.strip_prefix("errno="))
                        .and_then(|errno| errno.parse::<i32>().ok());
                    assert!(
                        matches!(errno, Some(0 | EIO | EINVAL | ENOSPC | EPROTO | EADDRINUSE)),
                        "{text:?}"
                    );
                    assert_eq!(more, errno == Some(0));
                    assert!(reader.len() < left, "a request consumes input");
                    answered += 1;
                    if !more {
                        break;
                    }
                }
                Err(err) => {
                    // Only a line that is not text, or too long, where a command stands.
                    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
                    assert!(!well_formed && out.is_empty(), "{input:02x?}");
                    failed += 1;
                    break;
                }
            }
        }
        // Whatever was sent, the interface still answers and reports a state.
        let _ = Model::read(&get(&uapi).await);
    }
    assert!(answered > 3_000 && failed > 100, "{answered} {failed}");
}
