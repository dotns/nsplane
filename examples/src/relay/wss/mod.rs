//! The WebSocket-over-TLS (WSS) carrier of the relay.
//!
//! One binary WebSocket message carries exactly one datagram of the shared port: a
//! WireGuard message or a framed control message, the same bytes as on UDP. Text messages,
//! messages longer than [`MAX_DATAGRAM`] and payloads that are neither are dropped and
//! counted; pings are answered.
//!
//! [`server`] accepts connections next to the relay's UDP socket: each one is a
//! [`Source::Ws`](super::router::Source::Ws) of the same [`Router`](super::router::Router),
//! so UDP and WSS clients relay to each other and reach the relay's own engine.
//! [`client`] is the node's [`WssTransport`](client::WssTransport).
//!
//! TLS is rustls with the aws-lc-rs provider. The relay generates a self-signed
//! certificate at start ([`ServerCert::generate`]); clients pin it, trusting nothing else
//! ([`client_tls`]).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
use std::path::Path as FsPath;
use std::sync::Arc;

use anyhow::{Context as _, anyhow, bail};
use nsplane::PacketBuf;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, SanType};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub mod client;
pub mod server;

/// The longest datagram a WebSocket message may carry.
pub const MAX_DATAGRAM: usize = 65_535;

/// The longest WebSocket message read at all; a longer one closes the connection.
const MAX_MESSAGE: usize = 4 * MAX_DATAGRAM;

/// The default certificate name of the relay.
pub const DEFAULT_NAME: &str = "relay.example";

/// The WebSocket limits of both sides.
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE))
}

/// The aws-lc-rs crypto provider.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Copies `data` into `buf` as a received datagram; `None` if it does not fit.
pub(crate) fn fill(buf: &mut PacketBuf, data: &[u8]) -> Option<usize> {
    if data.len() > buf.capacity() {
        return None;
    }
    buf.set_len(data.len());
    buf.as_packet_mut().copy_from_slice(data);
    Some(data.len())
}

/// The relay's self-signed TLS certificate and its key.
pub struct ServerCert {
    /// The certificate in PEM, for clients to pin.
    pub pem: String,
    der: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl fmt::Debug for ServerCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCert")
            .field("pem", &self.pem)
            .finish_non_exhaustive()
    }
}

impl ServerCert {
    /// A fresh certificate for the DNS name `name` and the IP addresses `ips` (an
    /// unspecified address stands for both loopback addresses).
    pub fn generate(name: &str, ips: &[IpAddr]) -> anyhow::Result<Self> {
        let mut params = CertificateParams::new(vec![name.to_owned()])
            .with_context(|| format!("invalid certificate name `{name}`"))?;
        for &ip in ips {
            let ips = if ip.is_unspecified() {
                vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ]
            } else {
                vec![ip]
            };
            for ip in ips {
                let san = SanType::IpAddress(ip);
                if !params.subject_alt_names.contains(&san) {
                    params.subject_alt_names.push(san);
                }
            }
        }
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().context("cannot generate the certificate key")?;
        let cert = params
            .self_signed(&key)
            .context("cannot sign the certificate")?;
        Ok(Self {
            pem: cert.pem(),
            der: cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
        })
    }

    /// The server TLS configuration presenting this certificate.
    pub fn server_tls(&self) -> anyhow::Result<Arc<ServerConfig>> {
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .context("no TLS protocol version")?
            .with_no_client_auth()
            .with_single_cert(vec![self.der.clone()], self.key.clone_key().into())
            .context("invalid certificate")?;
        Ok(Arc::new(config))
    }
}

/// A client TLS configuration that trusts only the certificates in `pem`.
pub fn client_tls(pem: &[u8]) -> anyhow::Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        roots
            .add(cert.context("invalid PEM certificate")?)
            .context("unusable certificate")?;
    }
    if roots.is_empty() {
        bail!("no certificate in the PEM");
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .context("no TLS protocol version")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// [`client_tls`] of a PEM file.
pub fn client_tls_file(path: &FsPath) -> anyhow::Result<Arc<ClientConfig>> {
    let pem = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    client_tls(&pem).with_context(|| format!("in {}", path.display()))
}

/// A `wss://<host>[:<port>][/<path>]` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WssUrl {
    /// The URL as given.
    pub url: String,
    /// The host: a DNS name or an IP address (without brackets).
    pub host: String,
    /// The port, 443 by default.
    pub port: u16,
}

impl WssUrl {
    /// Parses `url`.
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("wss://")
            .ok_or_else(|| anyhow!("`{url}` is not a wss:// URL"))?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, after) = v6
                .split_once(']')
                .ok_or_else(|| anyhow!("`{url}` has an unclosed `[`"))?;
            (host, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            bail!("`{url}` has no host");
        }
        let port = port.map_or(Ok(443), |port| {
            port.parse()
                .with_context(|| format!("invalid port in `{url}`"))
        })?;
        Ok(Self {
            url: url.to_owned(),
            host: host.to_owned(),
            port,
        })
    }

    /// The TLS server name (SNI and the name the certificate must carry).
    pub fn server_name(&self) -> anyhow::Result<ServerName<'static>> {
        ServerName::try_from(self.host.clone())
            .with_context(|| format!("invalid server name `{}`", self.host))
    }

    /// The host's first address.
    pub fn resolve(&self) -> anyhow::Result<SocketAddr> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .with_context(|| format!("cannot resolve `{}`", self.host))?
            .next()
            .ok_or_else(|| anyhow!("`{}` resolves to no address", self.host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse() {
        let url = WssUrl::parse("wss://relay.example:8443/ws").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("relay.example", 8443));
        let url = WssUrl::parse("wss://127.0.0.1/").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("127.0.0.1", 443));
        assert_eq!(url.resolve().unwrap(), "127.0.0.1:443".parse().unwrap());
        let url = WssUrl::parse("wss://[::1]:9/").unwrap();
        assert_eq!((url.host.as_str(), url.port), ("::1", 9));
        assert!(url.server_name().is_ok());
        assert!(WssUrl::parse("ws://relay.example/").is_err());
        assert!(WssUrl::parse("wss://:1/").is_err());
        assert!(WssUrl::parse("wss://relay.example:x/").is_err());
    }

    #[test]
    fn the_certificate_pins() {
        let cert = ServerCert::generate(DEFAULT_NAME, &["0.0.0.0".parse().unwrap()]).unwrap();
        assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert.server_tls().is_ok());
        assert!(client_tls(cert.pem.as_bytes()).is_ok());
        assert!(client_tls(b"not a certificate").is_err());
    }
}
