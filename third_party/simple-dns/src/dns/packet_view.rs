use super::{Header, PacketFlag, Question, WireFormat, OPCODE};
use crate::{
    bytes_buffer::BytesBuffer,
    lib::Vec,
    rdata::{RData, OPT},
    RCODE, TYPE,
};

/// A lenient view of a DNS message: the header, the questions and the [OPT] record.
///
/// Unlike [Packet::parse](crate::Packet::parse), the answer, authority and additional sections
/// are only walked: each record is skipped by its RDLENGTH, without decoding its owner name,
/// class or RDATA. Records of unknown types or classes, or with RDATA this crate cannot parse,
/// do not make the message fail. The first OPT record of the additional section is decoded,
/// with its options kept as opaque [OPTCode](crate::rdata::OPTCode) values; its TTL is read
/// as EXTENDED-RCODE, VERSION and flags as laid out in RFC 6891.
#[derive(Debug, Clone)]
pub struct PacketView<'a> {
    header: Header<'a>,
    edns_flags: u16,
    /// Questions section
    pub questions: Vec<Question<'a>>,
}

impl<'a> PacketView<'a> {
    /// Parses a view of the message in `data`.
    ///
    /// Fails when the header or a question does not parse, when a record of the other
    /// sections is cut off or its owner name is not a sequence of labels ending with a root
    /// label or a compression pointer, or when the OPT record does not parse.
    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        let mut data = BytesBuffer::new(data);
        let mut header = Header::parse(&mut data)?;

        let mut questions = Vec::with_capacity(header.questions as usize);
        for _ in 0..header.questions {
            questions.push(Question::parse(&mut data)?);
        }

        for _ in 0..u32::from(header.answers) + u32::from(header.name_servers) {
            skip_record(&mut data)?;
        }

        let mut edns_flags = 0;
        for _ in 0..header.additional_records {
            skip_name(&mut data)?;
            if header.opt.is_none() && TYPE::from(data.peek_u16_in(0)?) == TYPE::OPT {
                let ttl = data.peek_u32_in(4)?;
                if let RData::OPT(mut opt) = RData::parse(&mut data)? {
                    // RFC 6891 section 6.1.3: EXTENDED-RCODE, VERSION, then the flags.
                    let extended_rcode = (ttl >> 24) as u16;
                    header.response_code =
                        RCODE::from(extended_rcode << 4 | header.response_code as u16);
                    opt.version = (ttl >> 16) as u8;
                    header.opt = Some(opt);
                    edns_flags = ttl as u16;
                }
            } else {
                skip_record_fields(&mut data)?;
            }
        }

        Ok(Self {
            header,
            edns_flags,
            questions,
        })
    }

    /// Get packet id
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Check if the packet has flags set
    pub fn has_flags(&self, flags: PacketFlag) -> bool {
        self.header.has_flags(flags)
    }

    /// Get this packet [RCODE] information, extended by the [OPT] record when present
    pub fn rcode(&self) -> RCODE {
        self.header.response_code
    }

    /// Get this packet [OPCODE] information
    pub fn opcode(&self) -> OPCODE {
        self.header.opcode
    }

    /// Get the [OPT] resource record for this packet, if present
    pub fn opt(&self) -> Option<&OPT<'a>> {
        self.header.opt.as_ref()
    }

    /// Get the EDNS flags of the [OPT] record (the low 16 bits of its TTL, `DO` is `0x8000`),
    /// if present
    pub fn edns_flags(&self) -> Option<u16> {
        self.header.opt.as_ref().map(|_| self.edns_flags)
    }
}

/// Skips a resource record.
fn skip_record(data: &mut BytesBuffer) -> crate::Result<()> {
    skip_name(data)?;
    skip_record_fields(data)
}

/// Skips TYPE, CLASS, TTL, RDLENGTH and RDATA.
fn skip_record_fields(data: &mut BytesBuffer) -> crate::Result<()> {
    data.advance(8)?;
    let rdlength = data.get_u16()?;
    data.advance(rdlength as usize)
}

/// Skips a name without following compression pointers.
fn skip_name(data: &mut BytesBuffer) -> crate::Result<()> {
    loop {
        match data.get_u8()? {
            0 => return Ok(()),
            len if len & 0b1100_0000 == 0b1100_0000 => return data.advance(1),
            len if len & 0b1100_0000 != 0 => return Err(crate::SimpleDnsError::InvalidDnsPacket),
            len => data.advance(len as usize)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lib::ToString, lib::Vec, SimpleDnsError, QTYPE};

    /// A query header for `example.com. A` with the given section counts, followed by the
    /// question.
    fn query(answers: u16, name_servers: u16, additional_records: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1]);
        out.extend_from_slice(&answers.to_be_bytes());
        out.extend_from_slice(&name_servers.to_be_bytes());
        out.extend_from_slice(&additional_records.to_be_bytes());
        out.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        out
    }

    /// A record with a compressed owner name pointing at the question name.
    fn record(out: &mut Vec<u8>, rtype: u16, class: u16, rdata: &[u8]) {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    /// An OPT record with the given UDP size, TTL and options.
    fn opt(out: &mut Vec<u8>, udp_size: u16, ttl: u32, options: &[(u16, &[u8])]) {
        let mut rdata = Vec::new();
        for (code, data) in options {
            rdata.extend_from_slice(&code.to_be_bytes());
            rdata.extend_from_slice(&(data.len() as u16).to_be_bytes());
            rdata.extend_from_slice(data);
        }
        out.push(0);
        out.extend_from_slice(&41u16.to_be_bytes());
        out.extend_from_slice(&udp_size.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }

    #[test]
    fn parses_header_and_question() {
        let data = query(0, 0, 0);
        let view = PacketView::parse(&data).unwrap();

        assert_eq!(0x1234, view.id());
        assert_eq!(OPCODE::StandardQuery, view.opcode());
        assert!(view.has_flags(PacketFlag::RECURSION_DESIRED));
        assert!(!view.has_flags(PacketFlag::RESPONSE));
        assert_eq!(RCODE::NoError, view.rcode());
        assert_eq!(1, view.questions.len());
        assert_eq!("example.com", view.questions[0].qname.to_string());
        assert_eq!(QTYPE::TYPE(TYPE::A), view.questions[0].qtype);
        assert!(view.opt().is_none());
        assert_eq!(None, view.edns_flags());
    }

    #[test]
    fn skips_records_packet_parse_rejects() {
        let mut data = query(1, 1, 2);
        // Unknown type, unknown class.
        record(&mut data, 65280, 1, b"\x01\x02\x03");
        // Known type with RDATA that does not parse (an A record of 3 bytes), unknown class.
        record(&mut data, 1, 77, b"\x01\x02\x03");
        // Unknown type in the additional section, before the OPT record.
        record(&mut data, 65281, 1, b"");
        opt(&mut data, 1400, 0, &[]);

        assert!(crate::Packet::parse(&data).is_err());

        let view = PacketView::parse(&data).unwrap();
        assert_eq!(1, view.questions.len());
        assert_eq!(1400, view.opt().unwrap().udp_packet_size);
    }

    #[test]
    fn keeps_unknown_edns_options() {
        let mut data = query(0, 0, 2);
        // Version 1, DO flag set.
        opt(
            &mut data,
            4096,
            0x0001_8000,
            &[(65001, b"\xaa\xbb"), (10, b"")],
        );
        record(&mut data, 65280, 1, b"\x00");

        let view = PacketView::parse(&data).unwrap();
        let opt = view.opt().unwrap();
        assert_eq!(4096, opt.udp_packet_size);
        assert_eq!(1, opt.version);
        assert_eq!(2, opt.opt_codes.len());
        assert_eq!(65001, opt.opt_codes[0].code);
        assert_eq!(&b"\xaa\xbb"[..], &opt.opt_codes[0].data[..]);
        assert_eq!(Some(0x8000), view.edns_flags());
    }

    #[test]
    fn extends_rcode_from_opt() {
        let mut data = query(0, 0, 1);
        data[2] |= 0x80;
        // Extended RCODE 1 (BADVERS = 16 with the header's 0).
        opt(&mut data, 1232, 0x0100_0000, &[]);

        let view = PacketView::parse(&data).unwrap();
        assert_eq!(RCODE::BADVERS, view.rcode());
    }

    #[test]
    fn uses_first_opt_record() {
        let mut data = query(0, 0, 2);
        opt(&mut data, 1400, 0, &[]);
        opt(&mut data, 512, 0, &[]);

        let view = PacketView::parse(&data).unwrap();
        assert_eq!(1400, view.opt().unwrap().udp_packet_size);
    }

    #[test]
    fn ignores_opt_outside_additional_section() {
        let mut data = query(1, 0, 0);
        opt(&mut data, 1400, 0, &[]);

        let view = PacketView::parse(&data).unwrap();
        assert!(view.opt().is_none());
    }

    #[test]
    fn skips_uncompressed_and_compressed_names() {
        let mut data = query(2, 0, 0);
        data.extend_from_slice(
            b"\x03www\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x0a\x00\x00\x01",
        );
        data.extend_from_slice(b"\x03foo\x03bar\x00\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x02\x01x");

        let view = PacketView::parse(&data).unwrap();
        assert_eq!(1, view.questions.len());
    }

    #[test]
    fn does_not_follow_compression_pointers() {
        let mut data = query(1, 0, 0);
        // A pointer past the end of the message, never dereferenced.
        data.extend_from_slice(b"\xff\xff\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x00");

        assert!(PacketView::parse(&data).is_ok());
    }

    #[test]
    fn compressed_question_name() {
        let mut data = query(0, 0, 0);
        data[5] = 2;
        data.extend_from_slice(b"\x03www\xc0\x0c\x00\x1c\x00\x01");

        let view = PacketView::parse(&data).unwrap();
        assert_eq!(2, view.questions.len());
        assert_eq!("www.example.com", view.questions[1].qname.to_string());
    }

    #[test]
    fn rejects_truncated_records() {
        let mut full = query(1, 0, 1);
        record(&mut full, 65280, 1, b"\x01\x02\x03\x04");
        opt(&mut full, 1400, 0, &[(65001, b"\xaa\xbb")]);
        assert!(PacketView::parse(&full).is_ok());

        let question_end = query(0, 0, 0).len();
        for len in question_end..full.len() {
            assert_eq!(
                Err(SimpleDnsError::InsufficientData),
                PacketView::parse(&full[..len]).map(|_| ()),
                "cut at {len}"
            );
        }
    }

    #[test]
    fn rejects_malformed_opt_options() {
        let mut data = query(0, 0, 1);
        // An option claiming 4 bytes with 2 present inside RDLENGTH.
        data.extend_from_slice(
            b"\x00\x00\x29\x05\x78\x00\x00\x00\x00\x00\x06\xfd\xe9\x00\x04\xaa\xbb",
        );

        assert!(PacketView::parse(&data).is_err());
    }

    #[test]
    fn rejects_extended_label_types() {
        let mut data = query(1, 0, 0);
        data.extend_from_slice(b"\x41\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x00");

        assert_eq!(
            Err(SimpleDnsError::InvalidDnsPacket),
            PacketView::parse(&data).map(|_| ())
        );
    }

    #[test]
    fn rejects_malformed_question() {
        let mut data = query(0, 0, 0);
        data.truncate(data.len() - 2);

        assert!(PacketView::parse(&data).is_err());
    }
}
