// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! The cross-platform `wg` configuration protocol (UAPI), independent of its transport (a
//! Unix socket or a Windows named pipe).

use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use hex::encode as encode_hex;

use super::Error;
use super::peer::AllowedIP;
use super::peer_table::{PeerTable, PeerTableError, PeerUpdate};
use crate::serialization::KeyBytes;
use crate::x25519;

// The UAPI reports errors as Linux errno values on every platform.
const EIO: i32 = 5;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;
const EPROTO: i32 = 71;
const EADDRINUSE: i32 = 98;

/// The device operations the UAPI needs.
pub(crate) trait UapiDevice {
    /// Our public key, once a private key is set.
    fn public_key(&self) -> Option<&x25519::PublicKey>;
    /// The UDP port, 0 if none is bound yet.
    fn listen_port(&self) -> u16;
    /// The firewall mark of outgoing packets.
    fn fwmark(&self) -> Option<u32>;
    /// The peers.
    fn peers(&self) -> &PeerTable;
    /// Replaces the private key.
    fn set_key(&mut self, private_key: &x25519::StaticSecret);
    /// Binds the UDP sockets to `port` (0 picks one).
    fn open_listen_socket(&mut self, port: u16) -> Result<(), Error>;
    /// Sets the firewall mark of outgoing packets.
    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error>;
    /// Removes all peers.
    fn clear_peers(&mut self);
    /// Applies one peer section.
    fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError>;
}

/// The two UAPI requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request {
    /// `get=1`: report the configuration.
    Get,
    /// `set=1`: change the configuration.
    Set,
}

/// Reads one request from `reader`, lets `handle` execute it, and writes the response to
/// `writer`.
///
/// `handle` runs [`get`] or [`set`] against the device, so the caller can take whatever lock
/// the request needs. Returns `false` when the connection is closed.
pub(crate) fn serve<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    handle: impl FnOnce(Request, &mut R, &mut W) -> i32,
) -> bool {
    let mut cmd = String::new();
    match reader.read_line(&mut cmd) {
        Ok(0) | Err(_) => return false,
        Ok(_) => {}
    }
    let status = match cmd.trim_end_matches('\n') {
        // Only two commands are legal according to the protocol, get=1 and set=1.
        "get=1" => handle(Request::Get, reader, writer),
        "set=1" => handle(Request::Set, reader, writer),
        _ => EIO,
    };
    // The protocol requires to return an error code as the response, or zero on success
    writeln!(writer, "errno={status}\n").is_ok() && writer.flush().is_ok()
}

/// Unix time of a handshake that happened `elapsed` before `now`.
fn last_handshake_unix(elapsed: Duration, now: SystemTime) -> (u64, u32) {
    let at = now
        .checked_sub(elapsed)
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .unwrap_or_default();
    (at.as_secs(), at.subsec_nanos())
}

/// Writes the `get` response.
pub(crate) fn get(writer: &mut impl Write, d: &impl UapiDevice) -> i32 {
    match write_config(writer, d) {
        Ok(()) => 0,
        Err(_) => EIO,
    }
}

fn write_config(writer: &mut impl Write, d: &impl UapiDevice) -> std::io::Result<()> {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(key) = d.public_key() {
        writeln!(writer, "own_public_key={}", encode_hex(key.as_bytes()))?;
    }

    if d.listen_port() != 0 {
        writeln!(writer, "listen_port={}", d.listen_port())?;
    }

    if let Some(fwmark) = d.fwmark() {
        writeln!(writer, "fwmark={fwmark}")?;
    }

    let peers = d.peers();
    for (k, peer) in peers.iter() {
        let allowed_ips = peers.allowed_ips(peer);
        let p = peer.lock();
        writeln!(writer, "public_key={}", encode_hex(k.as_bytes()))?;

        if let Some(key) = p.preshared_key() {
            writeln!(writer, "preshared_key={}", encode_hex(key))?;
        }

        if let Some(keepalive) = p.persistent_keepalive() {
            writeln!(writer, "persistent_keepalive_interval={keepalive}")?;
        }

        let endpoint = p.endpoint().addr;
        if let Some(addr) = endpoint {
            writeln!(writer, "endpoint={addr}")?;
        }

        for (ip, cidr) in allowed_ips {
            writeln!(writer, "allowed_ip={ip}/{cidr}")?;
        }

        if let Some(elapsed) = p.time_since_last_handshake() {
            // The UAPI reports the wall-clock time of the handshake, not its age.
            let (secs, nsecs) = last_handshake_unix(elapsed, SystemTime::now());
            writeln!(writer, "last_handshake_time_sec={secs}")?;
            writeln!(writer, "last_handshake_time_nsec={nsecs}")?;
        }

        let (_, tx_bytes, rx_bytes, ..) = p.tunnel.stats();

        writeln!(writer, "rx_bytes={rx_bytes}")?;
        writeln!(writer, "tx_bytes={tx_bytes}")?;
    }
    Ok(())
}

/// Reads and applies a `set` request.
pub(crate) fn set(reader: &mut impl BufRead, device: &mut impl UapiDevice) -> i32 {
    let mut cmd = String::new();

    while reader.read_line(&mut cmd).is_ok() {
        let line = cmd.trim_end_matches('\n');
        if line.is_empty() {
            return 0; // Done
        }
        let Some((key, val)) = line.split_once('=') else {
            return EPROTO;
        };

        match key {
            "private_key" => match val.parse::<KeyBytes>() {
                Ok(key_bytes) => {
                    device.set_key(&x25519::StaticSecret::from(key_bytes.0));
                }
                Err(_) => return EINVAL,
            },
            "listen_port" => match val.parse::<u16>() {
                Ok(port) => {
                    if device.open_listen_socket(port).is_err() {
                        return EADDRINUSE;
                    }
                }
                Err(_) => return EINVAL,
            },
            "fwmark" => match val.parse::<u32>() {
                Ok(mark) => {
                    if device.set_fwmark(mark).is_err() {
                        return EADDRINUSE;
                    }
                }
                Err(_) => return EINVAL,
            },
            "replace_peers" => match val.parse::<bool>() {
                Ok(true) => device.clear_peers(),
                Ok(false) => {}
                Err(_) => return EINVAL,
            },
            "public_key" => match val.parse::<KeyBytes>() {
                // Indicates a new peer section
                Ok(key_bytes) => {
                    return set_peers(reader, device, x25519::PublicKey::from(key_bytes.0));
                }
                Err(_) => return EINVAL,
            },
            _ => return EINVAL,
        }
        cmd.clear();
    }

    0
}

/// Reads and applies the peer sections of a `set` request, starting with `pub_key`.
fn set_peers(
    reader: &mut impl BufRead,
    d: &mut impl UapiDevice,
    pub_key: x25519::PublicKey,
) -> i32 {
    let mut cmd = String::new();
    // Every `public_key` line starts a fresh section: settings never leak into the next peer.
    let mut update = PeerUpdate::new(pub_key);

    while reader.read_line(&mut cmd).is_ok() {
        let line = cmd.trim_end_matches('\n');
        if line.is_empty() {
            return apply_peer_update(d, update);
        }
        let Some((key, val)) = line.split_once('=') else {
            return EPROTO;
        };
        match key {
            "remove" => match val.parse::<bool>() {
                Ok(remove) => update.remove = remove,
                Err(_) => return EINVAL,
            },
            "preshared_key" => match val.parse::<KeyBytes>() {
                Ok(key_bytes) => update.preshared_key = Some(key_bytes.0),
                Err(_) => return EINVAL,
            },
            "endpoint" => match val.parse::<SocketAddr>() {
                Ok(addr) => update.endpoint = Some(addr),
                Err(_) => return EINVAL,
            },
            "persistent_keepalive_interval" => match val.parse::<u16>() {
                Ok(interval) => update.persistent_keepalive = Some(interval),
                Err(_) => return EINVAL,
            },
            "replace_allowed_ips" => match val.parse::<bool>() {
                Ok(replace) => update.replace_allowed_ips = replace,
                Err(_) => return EINVAL,
            },
            "allowed_ip" => match val.parse::<AllowedIP>() {
                Ok(ip) => update.allowed_ips.push(ip),
                Err(_) => return EINVAL,
            },
            "public_key" => {
                // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                let Ok(key_bytes) = val.parse::<KeyBytes>() else {
                    return EINVAL;
                };
                let next = PeerUpdate::new(key_bytes.0.into());
                let status = apply_peer_update(d, std::mem::replace(&mut update, next));
                if status != 0 {
                    return status;
                }
            }
            "protocol_version" => match val.parse::<u32>() {
                Ok(1) => {} // Only version 1 is legal
                _ => return EINVAL,
            },
            _ => return EINVAL,
        }
        cmd.clear();
    }
    0
}

fn apply_peer_update(d: &mut impl UapiDevice, update: PeerUpdate) -> i32 {
    match d.update_peer(update) {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(message = "Failed to update peer", error = ?e);
            ENOSPC
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use std::io::BufReader;

    /// A device without sockets or TUN interface.
    #[derive(Default)]
    struct FakeDevice {
        key: Option<(x25519::StaticSecret, x25519::PublicKey)>,
        port: u16,
        peers: PeerTable,
    }

    impl UapiDevice for FakeDevice {
        fn public_key(&self) -> Option<&x25519::PublicKey> {
            self.key.as_ref().map(|(_, public)| public)
        }
        fn listen_port(&self) -> u16 {
            self.port
        }
        fn fwmark(&self) -> Option<u32> {
            None
        }
        fn peers(&self) -> &PeerTable {
            &self.peers
        }
        fn set_key(&mut self, private_key: &x25519::StaticSecret) {
            self.key = Some((private_key.clone(), x25519::PublicKey::from(private_key)));
        }
        fn open_listen_socket(&mut self, port: u16) -> Result<(), Error> {
            self.port = port;
            Ok(())
        }
        fn set_fwmark(&mut self, _mark: u32) -> Result<(), Error> {
            Err(Error::InvalidTunnelName)
        }
        fn clear_peers(&mut self) {
            self.peers.clear();
        }
        fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError> {
            let (private_key, _) = self.key.as_ref().ok_or(PeerTableError::IndicesExhausted)?;
            self.peers.apply(update, private_key, None)
        }
    }

    fn hex_key() -> (String, x25519::PublicKey) {
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        (
            encode_hex(secret.to_bytes()),
            x25519::PublicKey::from(&secret),
        )
    }

    fn request(device: &mut FakeDevice, body: &str) -> String {
        let mut reader = BufReader::new(body.as_bytes());
        let mut out = Vec::new();
        assert!(serve(
            &mut reader,
            &mut out,
            |request, r, w| match request {
                Request::Get => get(w, device),
                Request::Set => set(r, device),
            }
        ));
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn set_then_get_round_trips() {
        let mut device = FakeDevice::default();
        let (private, public) = hex_key();
        let (_, peer) = hex_key();
        let peer_hex = encode_hex(peer.as_bytes());
        let reply = request(
            &mut device,
            &format!(
                "set=1\nprivate_key={private}\nlisten_port=51820\npublic_key={peer_hex}\n\
                 endpoint=192.0.2.1:51820\nallowed_ip=10.0.0.0/24\n\
                 persistent_keepalive_interval=25\n\n"
            ),
        );
        assert_eq!(reply, "errno=0\n\n");

        let reply = request(&mut device, "get=1\n\n");
        assert!(reply.contains(&format!(
            "own_public_key={}\n",
            encode_hex(public.as_bytes())
        )));
        assert!(reply.contains("listen_port=51820\n"));
        assert!(reply.contains(&format!("public_key={peer_hex}\n")));
        assert!(reply.contains("endpoint=192.0.2.1:51820\n"));
        assert!(reply.contains("allowed_ip=10.0.0.0/24\n"));
        assert!(reply.contains("persistent_keepalive_interval=25\n"));
        assert!(reply.ends_with("errno=0\n\n"));
    }

    #[test]
    fn settings_do_not_leak_into_the_next_peer_section() {
        let mut device = FakeDevice::default();
        let (private, _) = hex_key();
        let (_, a) = hex_key();
        let (_, b) = hex_key();
        let (a_hex, b_hex) = (encode_hex(a.as_bytes()), encode_hex(b.as_bytes()));
        request(
            &mut device,
            &format!("set=1\nprivate_key={private}\npublic_key={b_hex}\n\n"),
        );
        // `remove=true` belongs to a only; b must survive and get no keepalive.
        let reply = request(
            &mut device,
            &format!(
                "set=1\npublic_key={a_hex}\npersistent_keepalive_interval=25\nremove=true\n\
                 public_key={b_hex}\nallowed_ip=10.0.1.0/24\n\n"
            ),
        );
        assert_eq!(reply, "errno=0\n\n");
        let b_peer = device.peers.get(&b).expect("b survives");
        assert_eq!(b_peer.lock().persistent_keepalive(), None);
        assert!(device.peers.get(&a).is_none());
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let mut device = FakeDevice::default();
        assert_eq!(request(&mut device, "set=1\nbogus\n\n"), "errno=71\n\n");
        assert_eq!(
            request(&mut device, "set=1\nprivate_key=xyz\n\n"),
            "errno=22\n\n"
        );
        assert_eq!(request(&mut device, "frob=1\n\n"), "errno=5\n\n");
    }

    #[test]
    fn last_handshake_is_reported_as_unix_time() {
        let now = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_100, 500);
        let (secs, nsecs) = last_handshake_unix(Duration::new(100, 0), now);
        assert_eq!((secs, nsecs), (1_700_000_000, 500));
    }
}
