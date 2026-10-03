use super::*;
use std::net::IpAddr;

// ── Encode/decode roundtrips (ns tunnel-ws frame/tests.rs) ─────────────────

fn roundtrip(frame: &WsFrame) -> WsFrame {
    WsFrame::decode(&frame.encode()).unwrap()
}

fn open(stream_id: u32, ip: IpAddr, port: u16, protocol: Protocol) -> WsFrame {
    WsFrame::open(stream_id, SocketAddr::new(ip, port), protocol)
}

#[test]
fn data_frame_roundtrips() {
    let frame = WsFrame::data(42, Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]));
    let decoded = roundtrip(&frame);
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(decoded.command, FrameCommand::Data);
    assert_eq!(decoded.payload, [0xDE, 0xAD, 0xBE, 0xEF][..]);
}

#[test]
fn close_frame_roundtrips() {
    let decoded = roundtrip(&WsFrame::close(7));
    assert_eq!(decoded.stream_id, 7);
    assert_eq!(decoded.command, FrameCommand::Close);
    assert!(decoded.payload.is_empty());
}

#[test]
fn close_ack_frame_roundtrips() {
    let decoded = roundtrip(&WsFrame::close_ack(99));
    assert_eq!(decoded.stream_id, 99);
    assert_eq!(decoded.command, FrameCommand::CloseAck);
}

#[test]
fn open_v4_tcp_frame_roundtrips() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let decoded = roundtrip(&open(1, ip, 8080, Protocol::Tcp));
    assert_eq!(decoded.stream_id, 1);
    assert_eq!(
        decoded.command,
        FrameCommand::Open {
            target: SocketAddr::new(ip, 8080),
            protocol: Protocol::Tcp,
        }
    );
}

#[test]
fn open_v4_udp_frame_roundtrips() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let decoded = roundtrip(&open(2, ip, 53, Protocol::Udp));
    assert!(matches!(
        decoded.command,
        FrameCommand::Open {
            protocol: Protocol::Udp,
            ..
        }
    ));
}

#[test]
fn open_v6_frame_roundtrips() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    let decoded = roundtrip(&open(5, ip, 443, Protocol::Tcp));
    assert_eq!(
        decoded.command,
        FrameCommand::Open {
            target: SocketAddr::new(ip, 443),
            protocol: Protocol::Tcp,
        }
    );
}

#[test]
fn stream_id_zero_and_max_roundtrip() {
    for id in [0, u32::MAX] {
        assert_eq!(roundtrip(&WsFrame::close(id)).stream_id, id);
    }
}

#[test]
fn decode_rejects_too_short_frame() {
    assert_eq!(
        WsFrame::decode(&Bytes::from_static(&[0x00, 0x00, 0x00])),
        Err(FrameError::TooShort { len: 3 })
    );
}

#[test]
fn decode_rejects_unknown_command_byte() {
    let data = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0xFF]);
    assert_eq!(
        WsFrame::decode(&data),
        Err(FrameError::UnknownCommand(0xFF))
    );
}

#[test]
fn decode_rejects_open_v4_body_too_short() {
    let data = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01, 0x01, 0xC0, 0xA8, 0x01]);
    assert_eq!(
        WsFrame::decode(&data),
        Err(FrameError::OpenTooShort {
            command: OPEN_V4,
            len: 8
        })
    );
    // One byte short of the protocol.
    let data = Bytes::from_static(&[0, 0, 0, 1, 0x01, 10, 0, 0, 1, 0, 53]);
    assert!(WsFrame::decode(&data).is_err());
}

#[test]
fn decode_rejects_open_v6_body_too_short() {
    let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x02];
    data.extend_from_slice(&[0u8; 10]);
    assert!(matches!(
        WsFrame::decode(&Bytes::from(data)),
        Err(FrameError::OpenTooShort {
            command: OPEN_V6,
            ..
        })
    ));
    let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x02];
    data.extend_from_slice(&[0u8; 18]);
    assert!(WsFrame::decode(&Bytes::from(data)).is_err());
}

#[test]
fn data_frame_with_empty_payload_roundtrips() {
    let decoded = roundtrip(&WsFrame::data(0, Bytes::new()));
    assert!(decoded.payload.is_empty());
}

// ── Wire vectors: exact bytes, as ns encodes them ─────────────────────────

/// ns `proxy/wire.rs` `build_open_frame`, extended to IPv6 as `tunnel-ws` encodes it.
fn ns_open(stream_id: u32, target_ip: IpAddr, target_port: u16, proto: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(24);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    match target_ip {
        IpAddr::V4(ip) => {
            frame.push(0x01);
            frame.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            frame.push(0x02);
            frame.extend_from_slice(&ip.octets());
        }
    }
    frame.extend_from_slice(&target_port.to_be_bytes());
    frame.push(proto);
    frame
}

/// ns `proxy/wire.rs` `build_data_frame`.
fn ns_data(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + data.len());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(0x10);
    frame.extend_from_slice(data);
    frame
}

/// ns `proxy/wire.rs` `build_close_frame`, and the `CLOSE_ACK` `tunnel-ws` sends.
fn ns_close(stream_id: u32, cmd: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(cmd);
    frame
}

/// Every command encodes to the exact bytes of the ns frame vectors, and those bytes
/// decode back to the frame.
#[test]
fn wire_vectors_match_ns() {
    let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    let v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    let vectors: [(WsFrame, &[u8]); 7] = [
        (
            open(1, v4, 8080, Protocol::Tcp),
            &[0, 0, 0, 1, 0x01, 192, 168, 1, 10, 0x1F, 0x90, 0x00],
        ),
        (
            open(2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53, Protocol::Udp),
            &[0, 0, 0, 2, 0x01, 10, 0, 0, 1, 0x00, 0x35, 0x01],
        ),
        (
            open(5, v6, 443, Protocol::Tcp),
            &[
                0, 0, 0, 5, 0x02, 0xFD, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01,
                0xBB, 0x00,
            ],
        ),
        (
            WsFrame::data(42, Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF])),
            &[0, 0, 0, 42, 0x10, 0xDE, 0xAD, 0xBE, 0xEF],
        ),
        (WsFrame::data(0, Bytes::new()), &[0, 0, 0, 0, 0x10]),
        (WsFrame::close(7), &[0, 0, 0, 7, 0x20]),
        (
            WsFrame::close_ack(u32::MAX),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x21],
        ),
    ];
    for (frame, bytes) in vectors {
        assert_eq!(frame.encode(), bytes, "{frame:?}");
        assert_eq!(frame.encoded_len(), bytes.len());
        assert_eq!(
            WsFrame::decode(&Bytes::copy_from_slice(bytes)).unwrap(),
            frame
        );
    }
}

/// The codec agrees with the ns builders over ids, addresses, ports and protocols.
#[test]
fn encoding_matches_the_ns_builders() {
    let ips = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)),
    ];
    for id in [1, 0x0102_0304, u32::MAX] {
        for ip in ips {
            for port in [0, 1, 0x1234, u16::MAX] {
                for protocol in [Protocol::Tcp, Protocol::Udp] {
                    let frame = open(id, ip, port, protocol);
                    assert_eq!(frame.encode(), ns_open(id, ip, port, protocol.to_byte()));
                }
            }
        }
        let payload: Vec<u8> = (0..=255).collect();
        assert_eq!(encode_data(id, &payload), ns_data(id, &payload));
        assert_eq!(
            WsFrame::data(id, Bytes::from(payload.clone())).encode(),
            ns_data(id, &payload)
        );
        assert_eq!(WsFrame::close(id).encode(), ns_close(id, 0x20));
        assert_eq!(WsFrame::close_ack(id).encode(), ns_close(id, 0x21));
    }
}

/// Decoding is as lenient as ns: any protocol byte but 1 is TCP, bytes after a complete
/// OPEN or CLOSE are ignored, and a DATA payload shares the message buffer.
#[test]
fn decoding_is_as_lenient_as_ns() {
    let data = Bytes::from_static(&[0, 0, 0, 3, 0x01, 127, 0, 0, 1, 0, 80, 0x07, 0xAA]);
    assert_eq!(
        WsFrame::decode(&data).unwrap().command,
        FrameCommand::Open {
            target: "127.0.0.1:80".parse().unwrap(),
            protocol: Protocol::Tcp,
        }
    );
    assert_eq!(Protocol::from_byte(1), Protocol::Udp);
    assert_eq!(Protocol::from_byte(0), Protocol::Tcp);
    assert_eq!(Protocol::from_byte(2), Protocol::Tcp);

    let decoded = WsFrame::decode(&Bytes::from_static(&[0, 0, 0, 3, 0x20, 1, 2])).unwrap();
    assert_eq!(decoded, WsFrame::close(3));

    let message = Bytes::from(ns_data(9, b"payload"));
    let decoded = WsFrame::decode(&message).unwrap();
    assert_eq!(decoded.payload, &b"payload"[..]);
    assert_eq!(decoded.payload.as_ptr(), message[HEADER_LEN..].as_ptr());
}

/// The payload of a non-DATA frame is not encoded, as in ns.
#[test]
fn only_data_frames_carry_a_payload() {
    let mut frame = WsFrame::close(1);
    frame.payload = Bytes::from_static(b"ignored");
    assert_eq!(frame.encode(), [0, 0, 0, 1, 0x20][..]);
    assert_eq!(frame.encoded_len(), HEADER_LEN);

    let mut buf = BytesMut::from(&b"x"[..]);
    WsFrame::close_ack(2).encode_into(&mut buf);
    assert_eq!(buf, [b'x', 0, 0, 0, 2, 0x21][..]);
}
