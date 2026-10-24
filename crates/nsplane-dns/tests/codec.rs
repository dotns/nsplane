//! Wire codec round trips against simple-dns.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test harness")]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use nsplane_dns::{
    Answer, DecodeError, EncodeOptions, Query, Record, RecordType, ResponseCode, encode_error,
    encode_response, max_udp_response_size,
};
use simple_dns::rdata::{OPT, RData};
use simple_dns::{CLASS, Name, OPCODE, Packet, PacketFlag, QTYPE, Question, RCODE, TYPE};

fn query_message(id: u16, name: &str, qtype: TYPE, rd: bool, edns: Option<u16>) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    packet.questions.push(Question::new(
        Name::new_unchecked(name),
        qtype.into(),
        CLASS::IN.into(),
        false,
    ));
    if rd {
        packet.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    if let Some(size) = edns {
        *packet.opt_mut() = Some(OPT {
            opt_codes: Vec::new(),
            udp_packet_size: size,
            version: 0,
        });
    }
    packet.build_bytes_vec().unwrap()
}

fn decode(id: u16, name: &str, qtype: TYPE, edns: Option<u16>) -> Query {
    Query::decode(&query_message(id, name, qtype, true, edns)).unwrap()
}

fn options() -> EncodeOptions {
    EncodeOptions::default()
}

#[test]
fn decode_reads_the_question() {
    let message = query_message(0xbeef, "WWW.Example.COM", TYPE::AAAA, true, Some(4096));
    let query = Query::decode(&message).unwrap();
    assert_eq!(query.id(), 0xbeef);
    assert_eq!(query.name(), "www.example.com");
    assert_eq!(query.record_type(), RecordType::AAAA);
    assert_eq!(query.class(), 1);
    assert!(query.recursion_desired());
    assert_eq!(query.udp_payload_size(), Some(4096));
    assert_eq!(query.raw(), &Bytes::from(message));

    let plain = Query::decode(&query_message(1, "a.example", TYPE::TXT, false, None)).unwrap();
    assert!(!plain.recursion_desired());
    assert_eq!(plain.udp_payload_size(), None);
    assert_eq!(plain.record_type(), RecordType::TXT);
}

#[test]
fn decode_reads_the_any_type() {
    let mut packet = Packet::new_query(3);
    packet.questions.push(Question::new(
        Name::new_unchecked("example.org"),
        QTYPE::ANY,
        CLASS::IN.into(),
        false,
    ));
    let query = Query::decode(&packet.build_bytes_vec().unwrap()).unwrap();
    assert_eq!(query.record_type(), RecordType::ANY);
}

#[test]
fn decode_errors_map_to_response_codes() {
    let short = Query::decode(&[0; 11]).unwrap_err();
    assert_eq!(short, DecodeError::Short);
    assert_eq!(short.response_code(), None);
    assert_eq!(short.id(), None);

    let mut response = query_message(7, "a.example", TYPE::A, false, None);
    response[2] |= 0x80;
    let err = Query::decode(&response).unwrap_err();
    assert_eq!(err.response_code(), None);
    assert_eq!(err.id(), Some(7));

    let mut two = Packet::new_query(8);
    for name in ["a.example", "b.example"] {
        two.questions.push(Question::new(
            Name::new_unchecked(name),
            TYPE::A.into(),
            CLASS::IN.into(),
            false,
        ));
    }
    let err = Query::decode(&two.build_bytes_vec().unwrap()).unwrap_err();
    assert_eq!(err.response_code(), Some(ResponseCode::FormErr));
    assert_eq!(err.id(), Some(8));

    let none = Packet::new_query(9).build_bytes_vec().unwrap();
    let err = Query::decode(&none).unwrap_err();
    assert_eq!(err.response_code(), Some(ResponseCode::FormErr));

    let mut notify = Packet::new_query(10);
    *notify.opcode_mut() = OPCODE::Notify;
    let err = Query::decode(&notify.build_bytes_vec().unwrap()).unwrap_err();
    assert_eq!(err.response_code(), Some(ResponseCode::NotImp));
    assert_eq!(err.id(), Some(10));

    let mut truncated = query_message(11, "a.example", TYPE::A, false, None);
    truncated.truncate(truncated.len() - 3);
    let err = Query::decode(&truncated).unwrap_err();
    assert_eq!(err.response_code(), Some(ResponseCode::FormErr));
    assert_eq!(err.id(), Some(11));
}

#[test]
fn records_answer_echoes_the_question() {
    let query = decode(0x4242, "Host.Example", TYPE::A, None);
    let answer = Answer::Records(vec![
        Record::a("host.example", 60, Ipv4Addr::new(192, 0, 2, 1)),
        Record::a("host.example", 60, Ipv4Addr::new(192, 0, 2, 2)),
    ]);
    let bytes = encode_response(&query, &answer, 512, options());
    let packet = Packet::parse(&bytes).unwrap();

    assert_eq!(packet.id(), 0x4242);
    assert!(packet.has_flags(
        PacketFlag::RESPONSE
            | PacketFlag::AUTHORITATIVE_ANSWER
            | PacketFlag::RECURSION_DESIRED
            | PacketFlag::RECURSION_AVAILABLE
    ));
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.opcode(), OPCODE::StandardQuery);
    assert_eq!(packet.rcode(), RCODE::NoError);
    assert_eq!(packet.questions.len(), 1);
    // The question keeps the client's case.
    assert_eq!(packet.questions[0].qname.to_string(), "Host.Example");
    assert_eq!(packet.questions[0].qtype, TYPE::A.into());
    assert!(packet.opt().is_none());

    let addrs: Vec<_> = packet
        .answers
        .iter()
        .map(|rr| match &rr.rdata {
            RData::A(a) => Ipv4Addr::from(a.address),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(
        addrs,
        [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
    );
    assert_eq!(packet.answers[0].ttl, 60);
    assert_eq!(packet.answers[0].name.to_string(), "host.example");
}

#[test]
fn every_record_kind_encodes() {
    let query = decode(1, "x.example", TYPE::A, None);
    let answer = Answer::Records(vec![
        Record::aaaa("x.example.", 1, Ipv6Addr::LOCALHOST),
        Record::cname("x.example", 2, "y.example."),
        Record::ptr("x.example", 3, "z.example"),
        Record::txt("x.example", 4, vec!["a=1".into(), "b".into()]),
    ]);
    let packet_bytes = encode_response(&query, &answer, 512, options());
    let packet = Packet::parse(&packet_bytes).unwrap();
    assert_eq!(packet.rcode(), RCODE::NoError);
    let types: Vec<_> = packet
        .answers
        .iter()
        .map(|rr| rr.rdata.type_code())
        .collect();
    assert_eq!(types, [TYPE::AAAA, TYPE::CNAME, TYPE::PTR, TYPE::TXT]);
    match &packet.answers[1].rdata {
        RData::CNAME(cname) => assert_eq!(cname.0.to_string(), "y.example"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unencodable_records_answer_servfail() {
    let query = decode(1, "x.example", TYPE::TXT, None);
    let answer = Answer::Records(vec![Record::txt("x.example", 1, vec!["x".repeat(256)])]);
    let packet_bytes = encode_response(&query, &answer, 512, options());
    let packet = Packet::parse(&packet_bytes).unwrap();
    assert_eq!(packet.rcode(), RCODE::ServerFailure);
    assert_eq!(packet.answers.len(), 0);
}

#[test]
fn code_answer_sets_rcode_and_edns() {
    let query = decode(5, "missing.example", TYPE::A, Some(1400));
    let mut options = options();
    options.udp_payload_size = 1300;
    let bytes = encode_response(&query, &Answer::Code(ResponseCode::NxDomain), 512, options);
    let packet = Packet::parse(&bytes).unwrap();
    assert_eq!(packet.id(), 5);
    assert_eq!(packet.rcode(), RCODE::NameError);
    assert!(packet.has_flags(PacketFlag::AUTHORITATIVE_ANSWER));
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.opt().map(|opt| opt.udp_packet_size), Some(1300));

    for (code, rcode) in [
        (ResponseCode::Refused, RCODE::Refused),
        (ResponseCode::ServFail, RCODE::ServerFailure),
        (ResponseCode::NoError, RCODE::NoError),
    ] {
        let bytes = encode_response(&query, &Answer::Code(code), 512, options);
        assert_eq!(Packet::parse(&bytes).unwrap().rcode(), rcode);
    }
}

#[test]
fn raw_answer_only_rewrites_the_id() {
    let query = decode(0x0102, "fwd.example", TYPE::A, None);
    let mut upstream = Packet::new_reply(0xffff);
    upstream.questions.push(Question::new(
        Name::new_unchecked("fwd.example"),
        TYPE::A.into(),
        CLASS::IN.into(),
        false,
    ));
    upstream.answers.push(simple_dns::ResourceRecord::new(
        Name::new_unchecked("fwd.example"),
        CLASS::IN,
        30,
        RData::A(Ipv4Addr::new(198, 51, 100, 9).into()),
    ));
    let upstream = upstream.build_bytes_vec().unwrap();

    let bytes = encode_response(
        &query,
        &Answer::Raw(Bytes::from(upstream.clone())),
        512,
        options(),
    );
    assert_eq!(&bytes[..2], &[0x01, 0x02]);
    assert_eq!(&bytes[2..], &upstream[2..]);
}

#[test]
fn oversized_responses_are_truncated() {
    let query = decode(77, "big.example", TYPE::A, Some(4096));
    let records = (0..=255)
        .map(|i| Record::a("big.example", 60, Ipv4Addr::new(10, 0, 0, i)))
        .collect();
    let answer = Answer::Records(records);

    let limit = max_udp_response_size(&query, options());
    assert_eq!(limit, 1232);
    let bytes = encode_response(&query, &answer, limit, options());
    assert!(bytes.len() <= limit);
    let packet = Packet::parse(&bytes).unwrap();
    assert_eq!(packet.id(), 77);
    assert!(packet.has_flags(PacketFlag::TRUNCATION | PacketFlag::RESPONSE));
    assert_eq!(packet.answers.len(), 0);
    assert_eq!(packet.questions.len(), 1);
    assert_eq!(packet.rcode(), RCODE::NoError);
    assert!(packet.opt().is_some());

    // The same answer fits a TCP-sized limit.
    let bytes = encode_response(&query, &answer, 65535, options());
    let packet = Packet::parse(&bytes).unwrap();
    assert!(!packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 256);

    // An oversized raw response becomes the truncated form built from the query.
    let raw = Answer::Raw(bytes);
    let truncated = encode_response(&query, &raw, 512, options());
    assert!(truncated.len() <= 512);
    let packet = Packet::parse(&truncated).unwrap();
    assert_eq!(packet.id(), 77);
    assert!(packet.has_flags(PacketFlag::TRUNCATION));
    assert_eq!(packet.answers.len(), 0);
}

#[test]
fn udp_response_size_is_clamped() {
    let opts = options();
    assert_eq!(
        max_udp_response_size(&decode(1, "a.example", TYPE::A, None), opts),
        512
    );
    assert_eq!(
        max_udp_response_size(&decode(1, "a.example", TYPE::A, Some(100)), opts),
        512
    );
    assert_eq!(
        max_udp_response_size(&decode(1, "a.example", TYPE::A, Some(1000)), opts),
        1000
    );
    assert_eq!(
        max_udp_response_size(&decode(1, "a.example", TYPE::A, Some(9000)), opts),
        1232
    );
}

#[test]
fn error_response_has_no_question() {
    let bytes = encode_error(0x0a0b, ResponseCode::NotImp);
    let packet = Packet::parse(&bytes).unwrap();
    assert_eq!(packet.id(), 0x0a0b);
    assert!(packet.has_flags(PacketFlag::RESPONSE));
    assert_eq!(packet.rcode(), RCODE::NotImplemented);
    assert_eq!(packet.questions.len(), 0);
}

#[test]
fn record_type_display() {
    assert_eq!(RecordType::AAAA.to_string(), "AAAA");
    assert_eq!(RecordType::HTTPS.to_string(), "HTTPS");
    assert_eq!(RecordType(52).to_string(), "TYPE52");
    assert_eq!(ResponseCode::NxDomain.value(), 3);
}
