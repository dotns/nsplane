//! Property tests of the checks an upstream response passes before it is taken for the
//! answer: `is_response`, `matches_query` and `echoes_questions`.
//!
//! The cases come from a seeded generator, so every run tests the same inputs.

use super::{echoes_questions, is_response, matches_query};
use crate::message::Query;

const HEADER: usize = 12;
const QR: u8 = 0x80;

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

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

type Question = (Vec<Vec<u8>>, u16, u16);

fn question(rng: &mut Rng) -> Question {
    let labels = (0..=rng.below(4))
        .map(|_| {
            (0..=rng.below(10))
                .map(|_| rng.pick(b"abcxyz019\xff"))
                .collect()
        })
        .collect();
    (
        labels,
        rng.pick(&[1, 28, 5, 16, 255, 4660]),
        rng.pick(&[1, 3, 255]),
    )
}

/// A message with `questions` and `tail` behind them; the section counts say one answer
/// record when there is a tail.
fn message(id: u16, flags: [u8; 2], questions: &[Question], tail: &[u8]) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(&flags);
    out.extend_from_slice(&u16::try_from(questions.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, u8::from(!tail.is_empty()), 0, 0, 0, 0]);
    for (labels, qtype, qclass) in questions {
        for label in labels {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&qclass.to_be_bytes());
    }
    out.extend_from_slice(tail);
    out
}

/// One answer record of an unknown type owned by the root name.
fn answer(rng: &mut Rng) -> Vec<u8> {
    let len = rng.below(30);
    let mut out = vec![
        0,
        0xff,
        0x01,
        0,
        1,
        0,
        0,
        0,
        30,
        0,
        u8::try_from(len).unwrap(),
    ];
    out.extend((0..len).map(|_| rng.byte()));
    out
}

/// The same question as a server may echo it: some letters in the other case.
fn recased(rng: &mut Rng, question: &Question) -> Question {
    let mut echoed = question.clone();
    for byte in echoed.0.iter_mut().flatten() {
        if rng.chance(40) {
            *byte = byte.to_ascii_uppercase();
        }
    }
    echoed
}

/// A question that differs from `question` in its name, type or class.
fn different(rng: &mut Rng, question: &Question) -> Question {
    let mut other = question.clone();
    match rng.below(7) {
        // Two names that read the same once written carelessly: two labels and one label
        // with a dot in it, and two octets that are no UTF-8. They were taken for the
        // same question while names were compared as lossy text.
        5 if other.0.len() > 1 => {
            let second = other.0.remove(1);
            other.0[0].push(b'.');
            other.0[0].extend(second);
        }
        5 | 6 => {
            let label = rng.below(other.0.len());
            let at = rng.below(other.0[label].len());
            other.0[label][at] = if other.0[label][at] == 0xff {
                0xfe
            } else {
                0xff
            };
        }
        0 => other.1 ^= 1 << rng.below(8),
        1 => other.2 = if other.2 == 1 { 3 } else { 1 },
        2 => {
            let label = rng.below(other.0.len());
            let at = rng.below(other.0[label].len());
            other.0[label][at] = if other.0[label][at] == b'q' {
                b'r'
            } else {
                b'q'
            };
        }
        3 => other.0.push(b"sub".to_vec()),
        _ => {
            let label = rng.below(other.0.len());
            other.0[label].push(b'q');
        }
    }
    other
}

/// The question as the forwarder keeps it: the name in lowercase text, an octet outside
/// printable ASCII as `\DDD` (the generator makes no dot or backslash to ask for).
fn key(question: &Question) -> (String, u16, u16) {
    let labels: Vec<String> = question
        .0
        .iter()
        .map(|label| {
            label
                .iter()
                .map(|&octet| match octet {
                    0x21..=0x7e => char::from(octet.to_ascii_lowercase()).to_string(),
                    _ => format!("\\{octet:03}"),
                })
                .collect()
        })
        .collect();
    (labels.join("."), question.1, question.2)
}

#[test]
fn a_response_matches_only_its_own_id_and_question() {
    let mut rng = Rng(0x5eed_f0a1);
    for _ in 0..20_000 {
        let asked = question(&mut rng);
        let query = Query::decode(&message(
            rng.u16(),
            [1, 0],
            std::slice::from_ref(&asked),
            &[],
        ))
        .unwrap();
        let id = rng.u16();
        let flags = [
            QR | rng.pick(&[0, 1, 4, 5]),
            rng.pick(&[0x80, 0x83, 0x82, 0xa0]),
        ];
        let tail = if rng.chance(60) {
            answer(&mut rng)
        } else {
            Vec::new()
        };
        let echoed = recased(&mut rng, &asked);
        let response = message(id, flags, std::slice::from_ref(&echoed), &tail);
        assert!(is_response(&response, id));
        assert!(matches_query(&response, id, &query), "{response:02x?}");

        let changed = match rng.below(6) {
            // Another transaction.
            0 => {
                let other = id ^ (1 << rng.below(16));
                assert!(!is_response(&response, other));
                assert!(!matches_query(&response, other, &query));
                continue;
            }
            // Not a response.
            1 => message(id, [flags[0] & !QR, flags[1]], &[echoed], &tail),
            // Another question, or not exactly one.
            2 => message(id, flags, &[different(&mut rng, &echoed)], &tail),
            3 => message(id, flags, &[], &tail),
            4 => message(id, flags, &[echoed.clone(), echoed], &tail),
            // Cut off anywhere.
            _ => response[..rng.below(response.len())].to_vec(),
        };
        assert!(!matches_query(&changed, id, &query), "{changed:02x?}");
    }
}

#[test]
fn a_passed_response_with_questions_carries_the_ones_asked() {
    let mut rng = Rng(0x5eed_f0a2);
    for _ in 0..20_000 {
        let asked: Vec<Question> = (0..=rng.below(3)).map(|_| question(&mut rng)).collect();
        let keys: Vec<_> = asked.iter().map(key).collect();
        let flags = [QR | (rng.pick(&[0, 2, 4, 5]) << 3), 0];
        let tail = if rng.chance(50) {
            answer(&mut rng)
        } else {
            Vec::new()
        };
        let echoed: Vec<Question> = asked.iter().map(|q| recased(&mut rng, q)).collect();
        let response = message(1, flags, &echoed, &tail);
        assert!(echoes_questions(&response, &keys), "{response:02x?}");
        // A server that refuses a message may leave the questions out.
        assert!(echoes_questions(&message(1, flags, &[], &tail), &keys));
        // Nothing was read from the message, so there is nothing to compare.
        assert!(echoes_questions(&response, &[]));

        let mut others = echoed.clone();
        match rng.below(4) {
            0 => {
                let at = rng.below(others.len());
                others[at] = different(&mut rng, &others[at]);
            }
            1 => others.push(question(&mut rng)),
            2 if others.len() > 1 => {
                others.pop();
            }
            _ => {
                let extra = different(&mut rng, &others[0]);
                others.insert(0, extra);
            }
        }
        let changed = message(1, flags, &others, &tail);
        assert!(!echoes_questions(&changed, &keys), "{changed:02x?}");
    }
}

#[test]
fn arbitrary_bytes_match_a_query_only_as_a_response_with_one_question() {
    let mut rng = Rng(0x5eed_f0a3);
    let mut matched = 0;
    for _ in 0..30_000 {
        let asked = question(&mut rng);
        let query = Query::decode(&message(7, [1, 0], std::slice::from_ref(&asked), &[])).unwrap();
        let id = rng.u16();
        let mut bytes = if rng.chance(70) {
            let tail = answer(&mut rng);
            message(id, [QR, 0x80], &[recased(&mut rng, &asked)], &tail)
        } else {
            (0..rng.below(40)).map(|_| rng.byte()).collect()
        };
        for _ in 0..rng.below(3) {
            if !bytes.is_empty() {
                let at = rng.below(bytes.len());
                bytes[at] ^= 1 << rng.below(8);
            }
        }
        let asked_id = if rng.chance(90) { id } else { rng.u16() };
        let header =
            bytes.len() >= HEADER && bytes[..2] == asked_id.to_be_bytes() && bytes[2] & QR != 0;
        assert_eq!(is_response(&bytes, asked_id), header, "{bytes:02x?}");
        if matches_query(&bytes, asked_id, &query) {
            assert!(header && bytes[4..6] == [0, 1], "{bytes:02x?}");
            matched += 1;
        }
        // Never a panic, whatever the bytes.
        let _ = echoes_questions(&bytes, &[key(&asked)]);
    }
    assert!(matched > 5_000, "{matched}");
}
