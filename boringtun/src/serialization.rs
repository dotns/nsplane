use base64::Engine as _;

pub(crate) struct KeyBytes(pub(crate) [u8; 32]);

impl std::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                let engine = if s.len() == 43 {
                    base64::engine::general_purpose::STANDARD_NO_PAD
                } else {
                    base64::engine::general_purpose::STANDARD
                };
                let decoded_key = engine.decode(s).map_err(|_| "Illegal character in key")?;
                if decoded_key.len() != internal.len() {
                    return Err("Illegal key size");
                }
                internal.copy_from_slice(&decoded_key);
            }
            _ => return Err("Illegal key size"),
        }

        Ok(Self(internal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_base64_keys() {
        // 44 characters, but not valid base64: must not turn into an all-zero key.
        assert!("!".repeat(44).parse::<KeyBytes>().is_err());
        assert!("?".repeat(43).parse::<KeyBytes>().is_err());
    }

    #[test]
    fn parses_base64_and_hex_keys() {
        let base64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
        let hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let expected: [u8; 32] = std::array::from_fn(|i| u8::try_from(i + 1).unwrap());
        assert_eq!(base64.parse::<KeyBytes>().unwrap().0, expected);
        assert_eq!(hex.parse::<KeyBytes>().unwrap().0, expected);
        assert_eq!(base64[..43].parse::<KeyBytes>().unwrap().0, expected);
    }
}
