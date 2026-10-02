//! Pure helpers for the macOS/iOS utun framing and naming; also compiled for tests.

use std::io;

/// Darwin's `AF_INET` (`sys/socket.h`).
const AF_INET: u8 = 2;
/// Darwin's `AF_INET6` (`sys/socket.h`).
const AF_INET6: u8 = 30;

/// Parses `utun` or `utunN` into the control unit (`0` lets the kernel pick, `N + 1`
/// selects `utunN`).
pub(crate) fn parse_utun_name(name: &str) -> io::Result<u32> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid utun name {name:?}: expected \"utun\" or \"utunN\""),
        )
    };
    let index = name.strip_prefix("utun").ok_or_else(invalid)?;
    if index.is_empty() {
        return Ok(0);
    }
    if !index.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    index
        .parse::<u32>()
        .ok()
        .and_then(|unit| unit.checked_add(1))
        .ok_or_else(invalid)
}

/// The utun header for `packet`, chosen from its IP version nibble.
pub(crate) fn af_header(packet: &[u8]) -> Option<[u8; 4]> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => Some([0, 0, 0, AF_INET]),
        Some(6) => Some([0, 0, 0, AF_INET6]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utun_names() {
        assert_eq!(parse_utun_name("utun").unwrap(), 0);
        assert_eq!(parse_utun_name("utun0").unwrap(), 1);
        assert_eq!(parse_utun_name("utun12").unwrap(), 13);
    }

    #[test]
    fn rejects_bad_utun_names() {
        for name in [
            "",
            "tun0",
            "utun-1",
            "utun+1",
            "utunx",
            "utun4294967295",
            "utun0 ",
        ] {
            let err = parse_utun_name(name).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
    }

    #[test]
    fn af_header_follows_version() {
        assert_eq!(af_header(&[0x45, 0]), Some([0, 0, 0, 2]));
        assert_eq!(af_header(&[0x60, 0]), Some([0, 0, 0, 30]));
        assert_eq!(af_header(&[0x50]), None);
        assert_eq!(af_header(&[]), None);
    }
}
