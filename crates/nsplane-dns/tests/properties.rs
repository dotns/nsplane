//! Property tests of the paths that take bytes from clients and upstreams: `Query::decode`,
//! `encode_response`, `Server::handle` with and without passthrough, the CNAME splice of
//! `PolicyResolver` and the bindings of `FakePool`.
//!
//! The cases come from a seeded generator, so every run tests the same inputs. Messages are
//! built by the encoder of this file, not by the codec under test.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use nsplane_dns::{
    Action, Answer, DecodeError, EncodeOptions, FakePool, FakePoolConfig, Forwarder,
    ForwarderConfig, NameMatch, PolicyResolver, PolicyTable, Query, Record, RecordData, RecordType,
    Resolver, ResolverSet, ResponseCode, Rule, Server, ServerConfig, Transport, encode_response,
};
use simple_dns::rdata::RData;
use simple_dns::{Packet, PacketFlag, PacketView, header_buffer};
use tokio::net::UdpSocket;
use tokio::time::Instant;

const HEADER: usize = 12;
const QR: u16 = 0x8000;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;
/// The reserved bit: the codec refuses a message that sets it.
const Z: u16 = 0x0040;
const OPCODE: u16 = 0x7800;
/// The server's default EDNS payload size.
const SERVER_UDP: usize = 1232;

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

    const fn u32(&mut self) -> u32 {
        let b = self.next().to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Question {
    labels: Vec<Vec<u8>>,
    qtype: u16,
    qclass: u16,
}

impl Question {
    fn encode(&self, out: &mut Vec<u8>) {
        for label in &self.labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
    }

    /// The name as the client wrote it, labels joined by dots.
    fn name(&self) -> String {
        let labels: Vec<&str> = self
            .labels
            .iter()
            .map(|label| std::str::from_utf8(label).unwrap())
            .collect();
        labels.join(".")
    }
}

/// A DNS message: questions, answer records of `(type, RDATA)` owned by the root name, and
/// an OPT record when `edns` holds a payload size.
#[derive(Debug, Clone)]
struct Message {
    id: u16,
    flags: u16,
    questions: Vec<Question>,
    answers: Vec<(u16, Vec<u8>)>,
    edns: Option<u16>,
}

impl Message {
    fn question_section(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for question in &self.questions {
            question.encode(&mut out);
        }
        out
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for count in [
            self.questions.len(),
            self.answers.len(),
            0,
            usize::from(self.edns.is_some()),
        ] {
            out.extend_from_slice(&u16::try_from(count).unwrap().to_be_bytes());
        }
        out.extend_from_slice(&self.question_section());
        for (rtype, rdata) in &self.answers {
            out.push(0);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
            out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            out.extend_from_slice(rdata);
        }
        if let Some(size) = self.edns {
            out.extend_from_slice(&[0, 0, 41]);
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&[0; 6]);
        }
        out
    }
}

fn label(rng: &mut Rng) -> Vec<u8> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";
    let len = if rng.chance(5) { 63 } else { 1 + rng.below(12) };
    (0..len).map(|_| rng.pick(CHARS)).collect()
}

fn question(rng: &mut Rng) -> Question {
    let labels = rng.below(5);
    Question {
        labels: (0..labels).map(|_| label(rng)).collect(),
        qtype: if rng.chance(70) {
            rng.pick(&[1, 28, 5, 12, 16, 255, 65])
        } else {
            rng.u16()
        },
        // Every class the codec knows, some with the mDNS unicast-response bit.
        qclass: rng.pick(&[1, 1, 1, 1, 3, 4, 254, 255, 0x8001]),
    }
}

/// A query `Query::decode` must accept: one question, opcode QUERY.
fn query(rng: &mut Rng) -> Message {
    let extra = if rng.chance(20) { 1 + rng.below(2) } else { 0 };
    let flags = if rng.chance(5) {
        // A client may set anything but QR and the opcode.
        rng.u16() & !(QR | OPCODE | Z)
    } else {
        rng.pick(&[0, RD, RD, RD | 0x0020, 0x0010])
    };
    Message {
        id: rng.u16(),
        flags,
        questions: vec![question(rng)],
        answers: (0..extra)
            .map(|_| {
                let len = rng.below(20);
                (0xff00 | u16::from(rng.byte()), rng.bytes(len))
            })
            .collect(),
        edns: rng
            .chance(50)
            .then(|| rng.pick(&[0, 512, 600, 1232, 4096, 65535])),
    }
}

/// A well-formed message that is not a query `Query::decode` accepts: another opcode, or a
/// question count other than one.
fn other_message(rng: &mut Rng) -> Message {
    let mut message = query(rng);
    message.answers.clear();
    if rng.chance(10) {
        // Questions that do not fit a 512-byte response.
        message.questions = (0..3)
            .map(|_| Question {
                labels: vec![vec![b'q'; 63]; 3],
                ..question(rng)
            })
            .collect();
        return message;
    }
    if rng.chance(50) {
        message.flags |= rng.pick(&[1, 2, 4, 5]) << 11;
    }
    if message.flags & OPCODE == 0 || rng.chance(30) {
        message.questions = (0..rng.pick(&[0, 2, 2, 3]))
            .map(|_| question(rng))
            .collect();
    }
    message
}

fn mutate(rng: &mut Rng, bytes: &mut Vec<u8>) {
    for _ in 0..=rng.below(2) {
        match rng.below(6) {
            0 if !bytes.is_empty() => {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
            1 if !bytes.is_empty() => {
                let at = rng.below(bytes.len());
                bytes[at] = rng.byte();
            }
            2 => bytes.truncate(rng.below(bytes.len() + 1)),
            3 => {
                let len = 1 + rng.below(8);
                let tail = rng.bytes(len);
                bytes.extend_from_slice(&tail);
            }
            // A section count.
            4 if bytes.len() >= HEADER => {
                let at = 4 + 2 * rng.below(4);
                bytes[at + 1] = rng.pick(&[0, 1, 2, 3]);
            }
            // A compression pointer somewhere behind the header.
            _ if bytes.len() > HEADER + 2 => {
                let at = HEADER + rng.below(bytes.len() - HEADER - 1);
                bytes[at] = 0xc0;
                bytes[at + 1] = rng.pick(&[0, 12, 13, 40, 255]);
            }
            _ => {}
        }
    }
}

/// A message from the network: a query, a query with a few bytes changed, or noise.
fn untrusted(rng: &mut Rng) -> Vec<u8> {
    match rng.below(100) {
        0..40 => query(rng).encode(),
        40..55 => other_message(rng).encode(),
        55..90 => {
            let mut bytes = if rng.chance(80) {
                query(rng).encode()
            } else {
                other_message(rng).encode()
            };
            mutate(rng, &mut bytes);
            bytes
        }
        _ => {
            let len = rng.below(40);
            rng.bytes(len)
        }
    }
}

const fn read16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn client() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 40000))
}

/// What the header alone says about a message, checked against the decoder's verdict.
fn assert_verdict_matches_header(bytes: &[u8], decoded: &Result<Query, DecodeError>) {
    if bytes.len() < HEADER {
        assert_eq!(*decoded, Err(DecodeError::Short));
        return;
    }
    let id = read16(bytes, 0);
    let flags = read16(bytes, 2);
    let questions = read16(bytes, 4);
    match decoded {
        Err(DecodeError::Short) => panic!("{bytes:02x?} has a header"),
        Err(DecodeError::Response { id: got }) => {
            assert_eq!((*got, flags & QR), (id, QR));
        }
        Err(DecodeError::Opcode { id: got }) => {
            assert_eq!((*got, flags & QR), (id, 0));
            assert_ne!(flags & OPCODE, 0);
        }
        Err(DecodeError::Malformed { id: got }) => {
            assert_eq!((*got, flags & (QR | OPCODE)), (id, 0));
        }
        Err(DecodeError::QuestionCount { id: got, count }) => {
            assert_eq!((*got, flags & (QR | OPCODE)), (id, 0));
            assert_eq!(*count, usize::from(questions));
            assert_ne!(questions, 1);
        }
        Ok(query) => {
            assert_eq!(flags & (QR | OPCODE), 0);
            assert_eq!(questions, 1);
            assert_eq!(query.id(), id);
            assert_eq!(query.recursion_desired(), flags & RD != 0);
            assert_eq!(query.raw().as_ref(), bytes);
            assert_eq!(query.name(), query.name().to_ascii_lowercase());
            assert!(!query.name().ends_with('.'));
        }
        Err(other) => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn decode_reads_what_the_header_and_the_question_say() {
    let mut rng = Rng(0x5eed_0d01);
    let mut seen = [0_u32; 6];
    for _ in 0..30_000 {
        let valid = rng.chance(30).then(|| query(&mut rng));
        let bytes = valid
            .as_ref()
            .map_or_else(|| untrusted(&mut rng), Message::encode);
        let decoded = Query::decode(&bytes);
        assert_verdict_matches_header(&bytes, &decoded);
        seen[match &decoded {
            Ok(_) => 0,
            Err(DecodeError::Short) => 1,
            Err(DecodeError::Response { .. }) => 2,
            Err(DecodeError::Opcode { .. }) => 3,
            Err(DecodeError::Malformed { .. }) => 4,
            Err(_) => 5,
        }] += 1;

        let Some(message) = valid else { continue };
        let query = decoded.unwrap_or_else(|err| panic!("{bytes:02x?}: {err}"));
        let asked = &message.questions[0];
        assert_eq!(query.name(), asked.name().to_ascii_lowercase());
        assert_eq!(query.record_type(), RecordType(asked.qtype));
        assert_eq!(query.class(), asked.qclass & 0x7fff);
        assert_eq!(query.udp_payload_size(), message.edns);
    }
    assert!(seen[0] > 15_000, "{seen:?}");
    assert!(seen[1..].iter().all(|&count| count > 300), "{seen:?}");
}

/// A name the codec encodes as a record owner: its labels neither start nor end with a
/// hyphen.
fn record_name(rng: &mut Rng) -> String {
    let labels: Vec<String> = (0..=rng.below(2))
        .map(|_| {
            let mut label = label(rng);
            label[0] = b'x';
            *label.last_mut().unwrap() = b'x';
            String::from_utf8(label).unwrap()
        })
        .collect();
    labels.join(".")
}

/// A record the codec encodes, with a lower and an upper bound of its encoded size: the
/// owner as a compression pointer or in full, and the same for a name in the RDATA.
fn record(rng: &mut Rng) -> (Record, usize, usize) {
    let name = record_name(rng);
    let owner = name.len() + 2;
    let (data, low, high) = match rng.below(4) {
        0 => (RecordData::A(Ipv4Addr::from(rng.u32())), 4, 4),
        1 => {
            let addr = u128::from(rng.next()) << 64 | u128::from(rng.next());
            (RecordData::Aaaa(Ipv6Addr::from(addr)), 16, 16)
        }
        2 => {
            let target = record_name(rng);
            let len = target.len() + 2;
            (RecordData::Cname(target), 1, len)
        }
        _ => {
            let strings: Vec<String> = (0..=rng.below(2))
                .map(|_| "t".repeat(rng.below(120)))
                .collect();
            let len = strings.iter().map(|s| s.len() + 1).sum();
            (RecordData::Txt(strings), len, len)
        }
    };
    let ttl = rng.u32();
    (
        Record::new(name, ttl, data),
        2 + 10 + low,
        owner + 10 + high,
    )
}

/// A record the codec cannot encode.
fn broken_record(rng: &mut Rng) -> Record {
    if rng.chance(50) {
        Record::a(format!("{}.test", "a".repeat(64)), 30, Ipv4Addr::LOCALHOST)
    } else {
        Record::txt("txt.test", 30, vec!["t".repeat(256)])
    }
}

const fn flags_of(bytes: &[u8]) -> u16 {
    read16(bytes, 2)
}

const fn rcode_of(bytes: &[u8]) -> u8 {
    bytes[3] & 0x0f
}

/// Asserts that `response` is a reply built for `query`: its ID, `QR`, `RD` as asked, `RA`,
/// the question as the client wrote it and an OPT record exactly for an EDNS query.
fn assert_built_reply<'a>(response: &'a [u8], message: &Message, bytes: &[u8]) -> Packet<'a> {
    let packet = Packet::parse(response)
        .unwrap_or_else(|err| panic!("reply {response:02x?} to {bytes:02x?}: {err}"));
    let flags = flags_of(response);
    assert_eq!(packet.id(), message.id);
    assert_eq!(flags & (QR | OPCODE | RA), QR | RA);
    assert_eq!(flags & RD, message.flags & RD);
    let question_end = HEADER + message.question_section().len();
    assert_eq!(read16(response, 4), 1);
    assert_eq!(response[HEADER..question_end], bytes[HEADER..question_end]);
    assert_eq!(
        packet.opt().map(|opt| opt.udp_packet_size),
        message.edns.map(|_| 1232)
    );
    packet
}

fn assert_records_arrived(packet: &Packet<'_>, records: &[Record]) {
    for (got, sent) in packet.answers.iter().zip(records) {
        assert_eq!(got.name.to_string(), sent.name);
        assert_eq!(got.ttl, sent.ttl);
        match (&got.rdata, &sent.data) {
            (RData::A(a), RecordData::A(addr)) => {
                assert_eq!(Ipv4Addr::from(a.address), *addr);
            }
            (RData::AAAA(a), RecordData::Aaaa(addr)) => {
                assert_eq!(Ipv6Addr::from(a.address), *addr);
            }
            (RData::CNAME(c), RecordData::Cname(target)) => {
                assert_eq!(c.0.to_string(), *target);
            }
            (RData::TXT(_), RecordData::Txt(_)) => {}
            other => panic!("record changed: {other:?}"),
        }
    }
}

#[test]
fn a_response_echoes_the_query_and_fits_the_limit() {
    let mut rng = Rng(0x5eed_0d02);
    let options = EncodeOptions::default();
    let (mut whole, mut truncated, mut raw_passed) = (0, 0, 0);
    for _ in 0..8_000 {
        let message = query(&mut rng);
        let bytes = message.encode();
        let query = Query::decode(&bytes).unwrap();
        let max_size = if rng.chance(20) {
            65535
        } else {
            512 + rng.below(1000)
        };
        let fixed = HEADER + message.question_section().len();
        let opt = if message.edns.is_some() { 11 } else { 0 };

        match rng.below(4) {
            0 => {
                let code = rng.pick(&[
                    ResponseCode::NoError,
                    ResponseCode::FormErr,
                    ResponseCode::ServFail,
                    ResponseCode::NxDomain,
                    ResponseCode::NotImp,
                    ResponseCode::Refused,
                ]);
                let response = encode_response(&query, &Answer::Code(code), max_size, options);
                let packet = assert_built_reply(&response, &message, &bytes);
                assert_eq!(rcode_of(&response), code.value());
                assert_eq!(flags_of(&response) & TC, 0);
                assert_eq!(response.len(), fixed + opt);
                assert_eq!(packet.answers.len(), 0);
            }
            1 => {
                let count = rng.below(40);
                let mut records = Vec::new();
                let (mut low, mut high) = (fixed + opt, fixed + opt);
                for _ in 0..count {
                    let (record, least, most) = record(&mut rng);
                    records.push(record);
                    low += least;
                    high += most;
                }
                let answer = Answer::Records(records.clone());
                let response = encode_response(&query, &answer, max_size, options);
                let packet = assert_built_reply(&response, &message, &bytes);
                assert!(response.len() <= max_size);
                assert_eq!(rcode_of(&response), 0);
                if flags_of(&response) & TC == 0 {
                    assert!(low <= max_size, "{low} bytes at least, limit {max_size}");
                    assert!((low..=high).contains(&response.len()));
                    assert_eq!(packet.answers.len(), records.len());
                    assert_records_arrived(&packet, &records);
                    whole += 1;
                } else {
                    assert!(high > max_size, "{high} bytes at most, limit {max_size}");
                    assert_eq!(response.len(), fixed + opt);
                    truncated += 1;
                }
            }
            2 => {
                let mut records: Vec<Record> =
                    (0..rng.below(3)).map(|_| record(&mut rng).0).collect();
                let at = rng.below(records.len() + 1);
                records.insert(at, broken_record(&mut rng));
                let response =
                    encode_response(&query, &Answer::Records(records), max_size, options);
                let packet = assert_built_reply(&response, &message, &bytes);
                assert_eq!(rcode_of(&response), ResponseCode::ServFail.value());
                assert_eq!(packet.answers.len(), 0);
            }
            _ => {
                let len = rng.pick(&[0, 5, 11, 12, 13, 100, 511, 512, 513, 1400, 3000]);
                let raw = rng.bytes(len);
                let answer = Answer::Raw(Bytes::from(raw.clone()));
                let response = encode_response(&query, &answer, max_size, options);
                assert!(response.len() <= max_size);
                if (HEADER..=max_size).contains(&len) {
                    assert_eq!(read16(&response, 0), message.id);
                    assert_eq!(response[2..], raw[2..]);
                    raw_passed += 1;
                } else {
                    let packet = assert_built_reply(&response, &message, &bytes);
                    assert_eq!(packet.answers.len(), 0);
                    let (tc, rcode) = if len < HEADER {
                        (0, ResponseCode::ServFail.value())
                    } else {
                        (TC, 0)
                    };
                    assert_eq!(flags_of(&response) & TC, tc);
                    assert_eq!(rcode_of(&response), rcode);
                }
            }
        }
    }
    assert!(whole > 500 && truncated > 500 && raw_passed > 500);
}

/// A resolver that gives the answer put into it last.
#[derive(Clone)]
struct Scripted(Arc<Mutex<Answer>>);

impl Scripted {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Answer::Code(ResponseCode::NoError))))
    }

    fn set(&self, answer: Answer) {
        *self.0.lock().unwrap() = answer;
    }
}

impl Resolver for Scripted {
    fn resolve(&self, _query: &Query, _client: SocketAddr) -> impl Future<Output = Answer> + Send {
        std::future::ready(self.0.lock().unwrap().clone())
    }
}

/// The UDP size limit of the server for a message with this EDNS payload size.
fn udp_limit(edns: Option<u16>) -> usize {
    edns.map_or(512, |size| usize::from(size).clamp(512, SERVER_UDP))
}

#[tokio::test]
async fn the_server_answers_every_message_with_a_readable_header_within_the_limit() {
    let mut rng = Rng(0x5eed_0d03);
    let resolver = Scripted::new();
    let server = Server::new(resolver.clone(), ServerConfig::default());
    let (mut responses, mut errors, mut truncated) = (0, 0, 0);
    let cases = 12_000;
    for _ in 0..cases {
        let bytes = untrusted(&mut rng);
        resolver.set(match rng.below(3) {
            0 => Answer::Code(ResponseCode::NxDomain),
            1 => Answer::Records((0..rng.below(30)).map(|_| record(&mut rng).0).collect()),
            _ => {
                let len = rng.pick(&[0, 12, 40, 600, 2000]);
                Answer::Raw(Bytes::from(rng.bytes(len)))
            }
        });
        let transport = rng.pick(&[Transport::Udp, Transport::Tcp]);
        let decoded = Query::decode(&bytes);
        errors += u64::from(decoded.is_err());
        let response = server.handle(&bytes, client(), transport).await;

        let silent = bytes.len() < HEADER || flags_of(&bytes) & QR != 0;
        assert_eq!(response.is_none(), silent, "{bytes:02x?}");
        let Some(response) = response else { continue };
        responses += 1;
        assert!(response.len() >= HEADER, "{bytes:02x?} -> {response:02x?}");
        assert_eq!(read16(&response, 0), read16(&bytes, 0));
        truncated += u64::from(flags_of(&response) & TC != 0);
        match decoded {
            Ok(query) => {
                if transport == Transport::Udp {
                    assert!(response.len() <= udp_limit(query.udp_payload_size()));
                }
            }
            Err(err) => {
                // An error reply: the header alone, with the code of the decode error.
                assert_eq!(response.len(), HEADER);
                assert_eq!(flags_of(&response) & QR, QR);
                assert_eq!(
                    Some(rcode_of(&response)),
                    err.response_code().map(ResponseCode::value)
                );
                assert_eq!(response[4..], [0; 8]);
            }
        }
    }
    let stats = server.stats();
    assert_eq!(stats.queries, cases);
    assert_eq!(stats.responses, responses);
    assert_eq!(stats.decode_errors, errors);
    assert_eq!(stats.truncated, truncated);
    assert!(errors > 2_000 && truncated > 500 && responses > 8_000);
}

/// The stub upstream's response to `request`, a message of this file's encoder: its header
/// with `QR` set, its questions and one answer record with `pad` bytes of RDATA.
fn upstream_response(request: &Message, pad: usize) -> Vec<u8> {
    Message {
        id: request.id,
        // Not truncated, or the forwarder would ask again over TCP.
        flags: (request.flags | QR) & !TC,
        questions: request.questions.clone(),
        answers: vec![(0xff01, vec![0x55; pad])],
        edns: None,
    }
    .encode()
}

#[tokio::test]
async fn a_passed_response_arrives_whole_or_cut_to_its_questions() {
    let mut rng = Rng(0x5eed_0d04);
    // The upstream answers what the test told it to expect: the server handles one message
    // at a time.
    let expected: Arc<Mutex<Vec<u8>>> = Arc::default();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    let script = Arc::clone(&expected);
    tokio::spawn(async move {
        let mut buf = vec![0; 65535];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut response = script.lock().unwrap().clone();
            response[..2].copy_from_slice(&buf[..2]);
            assert!(len >= HEADER);
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    let mut config = ForwarderConfig::new(vec![upstream]);
    config.timeout = Duration::from_secs(5);
    let forwarder = Arc::new(Forwarder::new(config).unwrap());
    let server = Server::new(Scripted::new(), ServerConfig::default())
        .with_passthrough(Arc::clone(&forwarder));

    let (mut whole, mut cut, mut bare) = (0, 0, 0);
    let cases = 400;
    for _ in 0..cases {
        let message = other_message(&mut rng);
        let bytes = message.encode();
        let pad = rng.pick(&[0, 100, 300, 480, 700, 1100, 1300, 3000]);
        let response = upstream_response(&message, pad);
        expected.lock().unwrap().clone_from(&response);
        let transport = rng.pick(&[Transport::Udp, Transport::Udp, Transport::Tcp]);
        let got = server.handle(&bytes, client(), transport).await.unwrap();

        let limit = match transport {
            Transport::Udp => udp_limit(message.edns),
            Transport::Tcp => 65535,
        };
        if response.len() <= limit {
            assert_eq!(got.as_ref(), response);
            whole += 1;
            continue;
        }
        // Too long for the client: the upstream's header with TC, and its questions when
        // they fit.
        let questions = message.question_section();
        assert_eq!(got[..2], response[..2]);
        assert_eq!(flags_of(&got), flags_of(&response) | TC);
        assert_eq!(got[6..HEADER], [0; 6]);
        if HEADER + questions.len() <= limit {
            assert_eq!(usize::from(read16(&got, 4)), message.questions.len());
            assert_eq!(got[HEADER..], questions);
            cut += 1;
        } else {
            assert_eq!(got.len(), HEADER);
            assert_eq!(read16(&got, 4), 0);
            bare += 1;
        }
    }
    let stats = server.stats();
    assert_eq!((stats.passed, stats.pass_failed), (cases, 0));
    assert_eq!(forwarder.stats().forwarded, cases);
    assert!(whole > 100 && cut > 100 && bare > 0, "{whole} {cut} {bare}");
}

#[tokio::test]
async fn an_upstream_response_behind_a_cname_rule_keeps_the_clients_question() {
    let mut rng = Rng(0x5eed_0d05);
    let upstream = Scripted::new();
    let table = PolicyTable::new([
        Rule::new(
            NameMatch::Exact("alias.test".into()),
            Action::Cname("target.test".into()),
        ),
        Rule::new(
            NameMatch::Exact("target.test".into()),
            Action::Resolve("up".into()),
        ),
    ])
    .unwrap();
    let resolvers = ResolverSet::new().with("up", upstream.clone());
    let server = Server::new(
        PolicyResolver::new(resolvers, table).unwrap(),
        ServerConfig::default(),
    );

    let (mut spliced, mut chain_only) = (0, 0);
    for _ in 0..4_000 {
        // The client asks for the alias, in its own letter case.
        let mut labels = vec![b"alias".to_vec(), b"test".to_vec()];
        for byte in labels.iter_mut().flatten() {
            if rng.chance(30) {
                byte.make_ascii_uppercase();
            }
        }
        let asked = Message {
            id: rng.u16(),
            flags: RD,
            questions: vec![Question {
                labels,
                qtype: rng.pick(&[1, 28, 16]),
                qclass: 1,
            }],
            answers: Vec::new(),
            edns: rng.chance(50).then_some(1232),
        };
        let bytes = asked.encode();

        // The upstream answers for the target: A records, changed in half the cases.
        let addresses: Vec<Vec<u8>> = (0..rng.below(4)).map(|_| rng.bytes(4)).collect();
        let mut raw = Message {
            id: rng.u16(),
            flags: QR | RD | RA | u16::from(rng.pick(&[0_u8, 0, 2, 3])),
            questions: vec![Question {
                labels: vec![b"target".to_vec(), b"test".to_vec()],
                qtype: asked.questions[0].qtype,
                qclass: 1,
            }],
            answers: addresses.iter().map(|a| (1, a.clone())).collect(),
            edns: None,
        }
        .encode();
        let code = raw[3] & 0x0f;
        let intact = rng.chance(50);
        if !intact {
            mutate(&mut rng, &mut raw);
            // A forwarder only takes a message with QR for a response.
            if let Some(flags) = raw.get_mut(2) {
                *flags |= 0x80;
            }
        }
        upstream.set(Answer::Raw(Bytes::from(raw)));

        let response = server
            .handle(&bytes, client(), Transport::Tcp)
            .await
            .unwrap();
        let packet = assert_built_or_spliced(&response, &asked, &bytes);
        let first = packet.answers.first().unwrap();
        assert_eq!(first.name.to_string(), "alias.test");
        let RData::CNAME(target) = &first.rdata else {
            panic!("the chain is not in front: {first:?}");
        };
        assert_eq!(target.0.to_string(), "target.test");
        if intact {
            assert_eq!(rcode_of(&response), code);
            assert_eq!(packet.answers.len(), 1 + addresses.len());
            for (got, sent) in packet.answers[1..].iter().zip(&addresses) {
                let RData::A(a) = &got.rdata else {
                    panic!("not the upstream's record: {got:?}");
                };
                assert_eq!(a.address.to_be_bytes().as_slice(), sent);
            }
            spliced += 1;
        } else if packet.answers.len() == 1 {
            chain_only += 1;
        }
    }
    assert!(
        spliced > 1_500 && chain_only > 300,
        "{spliced} {chain_only}"
    );
}

/// Asserts that `response` answers the client's own question under its ID, whether the
/// server built it or took it from an upstream.
fn assert_built_or_spliced<'a>(response: &'a [u8], asked: &Message, bytes: &[u8]) -> Packet<'a> {
    let packet = Packet::parse(response)
        .unwrap_or_else(|err| panic!("reply {response:02x?} to {bytes:02x?}: {err}"));
    assert_eq!(packet.id(), asked.id);
    assert!(packet.has_flags(PacketFlag::RESPONSE));
    let view = PacketView::parse(response).unwrap();
    assert_eq!(view.questions.len(), 1);
    assert_eq!(
        packet.questions[0].qname.to_string(),
        asked.questions[0].name()
    );
    assert_eq!(
        u16::from(packet.questions[0].qtype),
        asked.questions[0].qtype
    );
    assert_eq!(header_buffer::id(response).unwrap(), asked.id);
    packet
}

const NET4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
const NET6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
const TTL: Duration = Duration::from_secs(60);

fn name_query(rng: &mut Rng, name: &str, qtype: u16, qclass: u16) -> Query {
    let labels = name
        .split('.')
        .map(|label| {
            let mut label = label.as_bytes().to_vec();
            if rng.chance(30) {
                label.make_ascii_uppercase();
            }
            label
        })
        .collect();
    let message = Message {
        id: rng.u16(),
        flags: RD,
        questions: vec![Question {
            labels,
            qtype,
            qclass,
        }],
        answers: Vec::new(),
        edns: None,
    };
    Query::decode(&message.encode()).unwrap()
}

/// What the test knows about a name the pool answered.
struct Bound {
    index: u32,
    last_use: Instant,
}

/// Asserts that every bound name has one address of its own in both families, the one it
/// was answered with, and that a name answered within the TTL is still bound.
fn assert_bindings_hold(pool: &FakePool, names: &[String], known: &HashMap<String, Bound>) {
    let now = Instant::now();
    let mut taken = HashSet::new();
    for name in names {
        let state = known.get(name);
        if let Some((v4, v6)) = pool.lookup_name(name) {
            let index = state.unwrap().index;
            assert_eq!(v4, Some(Ipv4Addr::from(u32::from(NET4) + index)));
            assert_eq!(
                v6,
                Some(Ipv6Addr::from(u128::from(NET6) + u128::from(index)))
            );
            assert!(taken.insert(index), "{name} shares its address");
        } else if let Some(state) = state {
            assert!(
                now.duration_since(state.last_use) >= TTL,
                "{name} lost its address within the TTL"
            );
        }
    }
    assert_eq!(pool.len(), taken.len());
    assert!(taken.len() <= pool.capacity());
}

#[tokio::test(start_paused = true)]
async fn a_fake_address_stays_with_its_name_while_it_may_be_cached() {
    let mut rng = Rng(0x5eed_0d06);
    let (mut refused, mut rebound) = (0, 0);
    for round in 0..60 {
        let capacity = 2 + rng.below(9);
        let mut pool = FakePool::new(FakePoolConfig {
            ipv4: Some((NET4, 28)),
            ipv6: Some((NET6, 120)),
            capacity,
            ttl: TTL,
        })
        .unwrap();
        if round % 2 == 0 {
            pool = pool.with_client_limit(1 + rng.below(capacity));
        }
        let names: Vec<String> = (0..16).map(|i| format!("host{i}.fake.test")).collect();
        let mut known: HashMap<String, Bound> = HashMap::new();
        let (mut created, mut failed) = (0_u64, 0_u64);

        for _ in 0..300 {
            let now = Instant::now();
            match rng.below(10) {
                0..6 => {
                    let any = rng.below(16);
                    let name = &names[rng.pick(&[0, 1, 2, 3, any])];
                    let v4 = rng.chance(60);
                    let query = name_query(&mut rng, name, if v4 { 1 } else { 28 }, 1);
                    let from = SocketAddr::from(([10, 0, 0, rng.pick(&[1, 1, 2, 3])], 5353));
                    let before = pool.lookup_name(name);
                    let idle = known
                        .values()
                        .all(|bound| now.duration_since(bound.last_use) >= TTL);
                    match pool.resolve(&query, from).await {
                        Answer::Records(records) => {
                            let [record] = records.as_slice() else {
                                panic!("{records:?}");
                            };
                            assert_eq!((record.name.as_str(), record.ttl), (name.as_str(), 60));
                            let index = match record.data {
                                RecordData::A(addr) if v4 => u32::from(addr) - u32::from(NET4),
                                RecordData::Aaaa(addr) if !v4 => {
                                    u32::try_from(u128::from(addr) - u128::from(NET6)).unwrap()
                                }
                                ref other => panic!("wrong family: {other:?}"),
                            };
                            assert!((1..=u32::try_from(capacity).unwrap()).contains(&index));
                            created += u64::from(before.is_none());
                            rebound += u64::from(before.is_none() && known.contains_key(name));
                            known.insert(
                                name.clone(),
                                Bound {
                                    index,
                                    last_use: now,
                                },
                            );
                        }
                        Answer::Code(ResponseCode::ServFail) => {
                            assert_eq!(before, None, "a bound name is always answered");
                            assert!(!idle, "every binding was unused for the TTL");
                            failed += 1;
                        }
                        other => panic!("{other:?}"),
                    }
                }
                6 => {
                    // Other types and classes are not the pool's and bind nothing.
                    let (qtype, qclass) = rng.pick(&[(16, 1), (5, 1), (1, 3), (28, 255)]);
                    let query = name_query(&mut rng, "other.fake.test", qtype, qclass);
                    let answer = pool.resolve(&query, client()).await;
                    assert_eq!(answer, Answer::Records(Vec::new()));
                    assert_eq!(pool.lookup_name("other.fake.test"), None);
                }
                7 | 8 => {
                    // A connection to an address of the prefix, bound or not, or outside it.
                    let index = u32::try_from(rng.below(18)).unwrap();
                    let addr = if rng.chance(50) {
                        IpAddr::V4(Ipv4Addr::from(u32::from(NET4) + index))
                    } else {
                        IpAddr::V6(Ipv6Addr::from(u128::from(NET6) + u128::from(index)))
                    };
                    let owner = names.iter().find(|name| {
                        pool.lookup_name(name).is_some()
                            && known.get(*name).is_some_and(|bound| bound.index == index)
                    });
                    assert_eq!(pool.lookup(addr).as_ref(), owner);
                    if let Some(bound) = owner.and_then(|name| known.get_mut(name)) {
                        bound.last_use = now;
                    }
                }
                _ => {
                    let secs = rng.pick(&[1, 5, 20, 59, 60, 61, 200]);
                    tokio::time::advance(Duration::from_secs(secs)).await;
                }
            }

            assert_bindings_hold(&pool, &names, &known);
            let stats = pool.stats();
            assert_eq!(stats.allocated + stats.reused, created);
            assert!(stats.allocated <= u64::try_from(capacity).unwrap());
            assert_eq!(stats.exhausted + pool.client_limited(), failed);
        }
        refused += failed;
    }
    assert!(refused > 200 && rebound > 200, "{refused} {rebound}");
}
