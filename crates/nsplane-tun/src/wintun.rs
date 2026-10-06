//! The Windows service TUN checks that need no Windows API: the `wintun.dll` pin and its
//! verification, the typed [`WintunError`], the open/create/refuse decision and MTU
//! validation. Compiled on Windows and, for the unit tests, on every host.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The largest `wintun.dll` that is hashed; the released DLLs are well under 1 MiB, so
/// anything larger is refused without reading it all.
const MAX_DLL_LEN: u64 = 16 << 20;

/// The smallest interface MTU accepted: the IPv4 minimum datagram every host must
/// accept (RFC 791).
const MIN_MTU: u16 = 576;

/// The `wintun.dll` the caller expects, for `TunOptions::wintun_pin`.
///
/// The DLL is pinned by its SHA-256 only (no length, no Authenticode signer): before
/// loading, `Tun::create_with` reads the file at [`WintunPin::path`], compares its digest
/// and then loads that same absolute path. The file could still be replaced between the
/// check and the load, so the directory should be writable by administrators only (the
/// install directory of a service). [`WintunPin::driver_version`] additionally pins the
/// running driver, which the DLL does not determine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WintunPin {
    sha256: [u8; 32],
    path: Option<PathBuf>,
    driver_version: Option<(u16, u16)>,
}

impl WintunPin {
    /// A pin on the SHA-256 digest `sha256` of `wintun.dll` next to the executable.
    pub const fn new(sha256: [u8; 32]) -> Self {
        Self {
            sha256,
            path: None,
            driver_version: None,
        }
    }

    /// Like [`WintunPin::new`], from the digest as 64 hex digits (either case). Anything
    /// else fails with [`io::ErrorKind::InvalidInput`].
    pub fn from_hex(hex: &str) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a Wintun SHA-256 pin is 64 hex digits",
            )
        };
        if hex.len() != 64 {
            return Err(invalid());
        }
        let mut sha256 = [0; 32];
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (byte, &[high, low]) in sha256.iter_mut().zip(pairs) {
            let (Some(high), Some(low)) = (nibble(high), nibble(low)) else {
                return Err(invalid());
            };
            *byte = high << 4 | low;
        }
        Ok(Self::new(sha256))
    }

    /// Verifies and loads the DLL at `path` instead of `wintun.dll` next to the
    /// executable. A relative path is made absolute against the current directory.
    #[must_use]
    pub fn path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Also requires the running Wintun driver to report version `major.minor`, checked
    /// once the adapter is open and before the session starts.
    #[must_use]
    pub const fn driver_version(mut self, major: u16, minor: u16) -> Self {
        self.driver_version = Some((major, minor));
        self
    }

    /// The expected digest.
    pub(crate) const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// The expected driver version, if pinned.
    pub(crate) const fn expected_driver_version(&self) -> Option<(u16, u16)> {
        self.driver_version
    }

    /// The absolute path to verify and load.
    pub(crate) fn resolved_path(&self) -> io::Result<PathBuf> {
        match &self.path {
            Some(path) => std::path::absolute(path),
            None => Ok(std::env::current_exe()?.with_file_name("wintun.dll")),
        }
    }
}

/// The value of one hex digit.
const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Reads the file at `path` (at most [`MAX_DLL_LEN`] bytes) and compares its SHA-256
/// with `expected`.
///
/// A missing file fails with [`io::ErrorKind::NotFound`] naming the path and how to
/// install the DLL; a larger file with [`io::ErrorKind::InvalidData`]; a digest
/// mismatch with [`WintunError::HashMismatch`].
pub(crate) fn verify(path: &Path, expected: &[u8; 32]) -> io::Result<()> {
    let file = File::open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} not found: {}",
                    path.display(),
                    remedy(path, std::env::consts::ARCH)
                ),
            )
        } else {
            e
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_DLL_LEN + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_DLL_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} is larger than {MAX_DLL_LEN} bytes; not a wintun.dll",
                path.display()
            ),
        ));
    }
    check(path, &bytes, expected)?;
    Ok(())
}

/// Compares the SHA-256 of `bytes`, read from `path`, with `expected`.
fn check(path: &Path, bytes: &[u8], expected: &[u8; 32]) -> Result<(), WintunError> {
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual == *expected {
        Ok(())
    } else {
        Err(WintunError::HashMismatch {
            path: path.to_path_buf(),
            expected: *expected,
            actual,
        })
    }
}

/// How to install `wintun.dll` at `path` for the architecture `arch`
/// (`std::env::consts::ARCH`). wintun.net ships one DLL per architecture under
/// `bin\<arch>\`; the wrong one fails like a missing file, so the directory is named.
fn remedy(path: &Path, arch: &str) -> String {
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!(
        "download wintun.zip from https://www.wintun.net/ and copy bin\\{arch}\\wintun.dll \
         to {}, then run from an elevated terminal",
        path.display()
    )
}

/// What `Tun::create_with` does with the adapter name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Use the existing adapter.
    Open,
    /// Create the adapter.
    Create,
    /// Fail with [`WintunError::AdapterExists`].
    Refuse,
}

/// Decides by whether an adapter or interface with the name exists and whether the
/// caller asked for an exclusive one.
pub(crate) const fn plan(existing: bool, exclusive: bool) -> Plan {
    match (existing, exclusive) {
        (false, _) => Plan::Create,
        (true, false) => Plan::Open,
        (true, true) => Plan::Refuse,
    }
}

/// Checks an MTU for `TunOptions::mtu`: below 576 (the IPv4 minimum) fails with
/// [`io::ErrorKind::InvalidInput`].
pub(crate) fn validate_mtu(mtu: u16) -> io::Result<u16> {
    if mtu < MIN_MTU {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("MTU {mtu} is below the IPv4 minimum of {MIN_MTU}"),
        ));
    }
    Ok(mtu)
}

/// A refusal by the Windows service TUN checks of `Tun::create_with`.
///
/// It is returned inside an [`io::Error`] (kind from [`WintunError::kind`]), so the
/// signatures stay `io::Result`; recover it with
/// `err.get_ref().and_then(|e| e.downcast_ref::<WintunError>())`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WintunError {
    /// The DLL's SHA-256 differs from the pin; nothing was loaded.
    HashMismatch {
        /// The file that was hashed.
        path: PathBuf,
        /// The pinned digest.
        expected: [u8; 32],
        /// The file's digest.
        actual: [u8; 32],
    },
    /// The running Wintun driver is not the pinned version (`(major, minor)`).
    DriverVersionMismatch {
        /// The pinned version.
        expected: (u16, u16),
        /// The running driver's version.
        actual: (u16, u16),
    },
    /// An adapter or interface with the requested name already exists and the options
    /// asked for an exclusive one.
    AdapterExists {
        /// The requested name.
        name: String,
    },
}

impl WintunError {
    /// The [`io::ErrorKind`] of the [`io::Error`] carrying this error:
    /// [`io::ErrorKind::InvalidData`] for the pins, [`io::ErrorKind::AlreadyExists`] for
    /// an existing adapter.
    pub const fn kind(&self) -> io::ErrorKind {
        match self {
            Self::HashMismatch { .. } | Self::DriverVersionMismatch { .. } => {
                io::ErrorKind::InvalidData
            }
            Self::AdapterExists { .. } => io::ErrorKind::AlreadyExists,
        }
    }
}

impl fmt::Display for WintunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "{} has SHA-256 {}, expected {}; refusing to load it",
                path.display(),
                Hex(actual),
                Hex(expected)
            ),
            Self::DriverVersionMismatch { expected, actual } => write!(
                f,
                "the running Wintun driver is version {}.{}, expected {}.{}",
                actual.0, actual.1, expected.0, expected.1
            ),
            Self::AdapterExists { name } => {
                write!(f, "a network interface named {name:?} already exists")
            }
        }
    }
}

impl Error for WintunError {}

impl From<WintunError> for io::Error {
    fn from(e: WintunError) -> Self {
        Self::new(e.kind(), e)
    }
}

/// Lower-case hex formatting of a digest.
struct Hex<'a>(&'a [u8; 32]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHA-256 of `abc` (FIPS 180-2 test vector).
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /// A file under the temp directory, removed on drop.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(tag: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "nsplane-tun-wintun-{}-{tag}.dll",
                std::process::id()
            )))
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn downcast(e: &io::Error) -> Option<&WintunError> {
        e.get_ref().and_then(|e| e.downcast_ref::<WintunError>())
    }

    #[test]
    fn from_hex_accepts_64_hex_digits_in_either_case() {
        let lower = WintunPin::from_hex(ABC).unwrap();
        let upper = WintunPin::from_hex(&ABC.to_uppercase()).unwrap();
        assert_eq!(lower, upper);
        assert_eq!(lower.sha256()[..2], [0xba, 0x78]);
        assert_eq!(lower.sha256()[31], 0xad);
        assert_eq!(lower, WintunPin::new(*lower.sha256()));
    }

    #[test]
    fn from_hex_rejects_other_input() {
        let short = &ABC[..62];
        let long = format!("{ABC}00");
        let non_hex = format!("{}zz", &ABC[..62]);
        let signed = format!("+{}", &ABC[..63]);
        let non_ascii = format!("{}é", &ABC[..62]);
        for input in ["", short, &long, &non_hex, &signed, &non_ascii] {
            let e = WintunPin::from_hex(input).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{input}");
        }
    }

    #[test]
    fn pin_builders_set_path_and_driver_version() {
        let pin = WintunPin::from_hex(ABC).unwrap();
        assert_eq!(pin.expected_driver_version(), None);
        assert_eq!(
            pin.resolved_path().unwrap(),
            std::env::current_exe()
                .unwrap()
                .with_file_name("wintun.dll")
        );
        let pin = pin.path("dir/wintun.dll").driver_version(0, 14);
        assert_eq!(pin.expected_driver_version(), Some((0, 14)));
        let path = pin.resolved_path().unwrap();
        assert!(path.is_absolute());
        assert!(path.ends_with("dir/wintun.dll"));
    }

    #[test]
    fn verify_accepts_the_pinned_digest() {
        let file = TempFile::new("match");
        std::fs::write(&file.0, b"abc").unwrap();
        let pin = WintunPin::from_hex(ABC).unwrap();
        verify(&file.0, pin.sha256()).unwrap();
    }

    #[test]
    fn verify_reports_expected_and_actual_on_mismatch() {
        let file = TempFile::new("mismatch");
        std::fs::write(&file.0, b"xyz").unwrap();
        let pin = WintunPin::from_hex(ABC).unwrap();
        let e = verify(&file.0, pin.sha256()).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        let Some(WintunError::HashMismatch {
            path,
            expected,
            actual,
        }) = downcast(&e)
        else {
            panic!("not a hash mismatch: {e}");
        };
        assert_eq!(path, &file.0);
        assert_eq!(expected, pin.sha256());
        let xyz: [u8; 32] = Sha256::digest(b"xyz").into();
        assert_eq!(actual, &xyz);
        assert!(e.to_string().contains(ABC), "{e}");
    }

    #[test]
    fn verify_refuses_an_oversize_file() {
        let file = TempFile::new("oversize");
        File::create(&file.0)
            .unwrap()
            .set_len(MAX_DLL_LEN + 1)
            .unwrap();
        let e = verify(&file.0, &[0; 32]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(downcast(&e).is_none());
    }

    #[test]
    fn verify_names_the_path_and_remedy_for_a_missing_file() {
        let file = TempFile::new("missing");
        let e = verify(&file.0, &[0; 32]).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let message = e.to_string();
        assert!(message.contains(&file.0.display().to_string()), "{message}");
        assert!(message.contains("wintun.net"), "{message}");
        assert!(message.contains("elevated"), "{message}");
    }

    #[test]
    fn remedy_names_the_architecture_directory() {
        let path = Path::new("C:\\ns\\wintun.dll");
        for (arch, dir) in [
            ("x86_64", "bin\\amd64\\"),
            ("aarch64", "bin\\arm64\\"),
            ("x86", "bin\\x86\\"),
        ] {
            let remedy = remedy(path, arch);
            assert!(remedy.contains(dir), "{remedy}");
            assert!(remedy.contains("C:\\ns\\wintun.dll"), "{remedy}");
        }
    }

    #[test]
    fn plan_truth_table() {
        assert_eq!(plan(false, false), Plan::Create);
        assert_eq!(plan(false, true), Plan::Create);
        assert_eq!(plan(true, false), Plan::Open);
        assert_eq!(plan(true, true), Plan::Refuse);
    }

    #[test]
    fn mtu_below_the_ipv4_minimum_is_invalid() {
        assert_eq!(
            validate_mtu(575).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(validate_mtu(576).unwrap(), 576);
        assert_eq!(validate_mtu(u16::MAX).unwrap(), u16::MAX);
    }

    #[test]
    fn errors_display_and_map_to_io_kinds() {
        let version = WintunError::DriverVersionMismatch {
            expected: (0, 14),
            actual: (0, 13),
        };
        assert_eq!(version.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            version.to_string(),
            "the running Wintun driver is version 0.13, expected 0.14"
        );
        let exists = WintunError::AdapterExists {
            name: "ns0".to_owned(),
        };
        assert_eq!(exists.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            exists.to_string(),
            "a network interface named \"ns0\" already exists"
        );
        let hash = WintunError::HashMismatch {
            path: PathBuf::from("wintun.dll"),
            expected: [0; 32],
            actual: [0xff; 32],
        };
        assert_eq!(hash.kind(), io::ErrorKind::InvalidData);
        assert!(hash.to_string().contains(&"ff".repeat(32)));
    }

    #[test]
    fn downcast_round_trips_through_io_error() {
        let original = WintunError::AdapterExists {
            name: "ns0".to_owned(),
        };
        let e = io::Error::from(original.clone());
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(downcast(&e), Some(&original));
    }
}
