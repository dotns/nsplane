//! Parsing of 32-byte keys.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

/// Parses a key encoded as 64 hex digits or as base64 (43 characters unpadded, 44 padded).
pub(crate) fn parse_key(s: &str) -> Option<[u8; 32]> {
    let mut key = [0u8; 32];
    match s.len() {
        64 => hex::decode_to_slice(s, &mut key).ok()?,
        43 | 44 => {
            let engine = if s.len() == 43 {
                STANDARD_NO_PAD
            } else {
                STANDARD
            };
            key = engine.decode(s).ok()?.try_into().ok()?;
        }
        _ => return None,
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test harness")]

    use super::*;

    #[test]
    fn rejects_malformed_keys() {
        // 44 characters, but not valid base64: must not turn into an all-zero key.
        assert_eq!(parse_key(&"!".repeat(44)), None);
        assert_eq!(parse_key(&"?".repeat(43)), None);
        assert_eq!(parse_key(&"g".repeat(64)), None);
        // 64 bytes, but not 64 characters: must not split a character.
        assert_eq!(parse_key(&"é".repeat(32)), None);
        assert_eq!(parse_key("0102"), None);
    }

    #[test]
    fn parses_base64_and_hex_keys() {
        let base64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let expected: [u8; 32] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
        assert_eq!(parse_key(base64), Some(expected));
        assert_eq!(parse_key(hex), Some(expected));
        assert_eq!(parse_key(&base64[..43]), Some(expected));
    }
}
