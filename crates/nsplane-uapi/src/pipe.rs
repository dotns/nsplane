//! The Windows named pipe the `wg` tool connects to.

use std::ffi::{OsStr, OsString};
use std::io;
use std::mem;

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// The prefix of the UAPI pipe names, as wireguard-windows uses.
const PIPE_PREFIX: &str = r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\";

/// The standard UAPI pipe name of interface `iface`:
/// `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>`.
pub fn pipe_path(iface: &str) -> String {
    format!("{PIPE_PREFIX}{iface}")
}

/// A listening UAPI named pipe.
///
/// One pipe instance waits for a client at a time; when a client connects, the next
/// instance is created before the connection is served, so clients can connect one after
/// another and stay connected concurrently.
#[derive(Debug)]
pub struct UapiListener {
    server: NamedPipeServer,
    path: OsString,
}

impl UapiListener {
    /// Binds the standard pipe of interface `iface` (see [`pipe_path`]).
    ///
    /// The `ProtectedPrefix\Administrators` namespace only lets elevated processes (members
    /// of Administrators) create the pipe, so an unprivileged process cannot squat on the
    /// name before the daemon starts; binding fails when the process is not elevated.
    ///
    /// The pipe gets the default security descriptor: full control for `LocalSystem`, the
    /// Administrators group and the creator, read access for everyone else. A
    /// non-elevated process can therefore open the pipe for reading: it cannot send
    /// requests, but it can occupy the waiting instance and delay other clients until it
    /// disconnects. wireguard-windows narrows the descriptor to `LocalSystem` and
    /// Administrators; that needs `unsafe` Win32 calls and is not done here. Remote clients
    /// are rejected.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind(iface: &str) -> io::Result<Self> {
        Self::bind_path(pipe_path(iface))
    }

    /// Binds a pipe named `path` (`\\.\pipe\<name>`), with the same security as
    /// [`UapiListener::bind`] but without the protected namespace unless `path` is in it.
    /// Fails when a pipe of that name already exists.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind_path(path: impl Into<OsString>) -> io::Result<Self> {
        let path = path.into();
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)?;
        Ok(Self { server, path })
    }

    /// The name of the pipe.
    pub fn path(&self) -> &OsStr {
        &self.path
    }

    /// Waits for the next client and returns the read and write halves of its connection.
    ///
    /// The next pipe instance is created before the connection is returned. Cancel safe:
    /// a dropped call leaves the waiting instance in place.
    pub(crate) async fn accept(
        &mut self,
    ) -> io::Result<(ReadHalf<NamedPipeServer>, WriteHalf<NamedPipeServer>)> {
        let connected = self.server.connect().await;
        // A failed instance is replaced as well, so the next call waits on a fresh one.
        let next = ServerOptions::new().create(&self.path)?;
        let server = mem::replace(&mut self.server, next);
        connected.map(|()| tokio::io::split(server))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test harness"
    )]

    use std::time::Duration;

    use nsplane::x25519::StaticSecret;
    use nsplane::{ChannelSink, ChannelSource, ChannelTransport, EngineBuilder, TransportId};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

    use super::{UapiListener, pipe_path};
    use crate::Uapi;

    /// Sends `request` and reads one response, up to and including the empty line after
    /// `errno`.
    async fn exchange(client: &mut BufReader<NamedPipeClient>, request: &str) -> String {
        client
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(client.read_line(&mut line).await.unwrap(), 0);
            let done = line == "\n" && out.contains("errno=");
            out.push_str(&line);
            if done {
                return out;
            }
        }
    }

    #[test]
    fn pipe_path_is_the_standard_one() {
        assert_eq!(
            pipe_path("wg0"),
            r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\wg0"
        );
    }

    #[tokio::test]
    #[ignore = "wine does not enforce FILE_FLAG_FIRST_PIPE_INSTANCE"]
    async fn a_second_listener_on_the_same_name_fails() {
        let path = format!(r"\\.\pipe\nsplane-uapi-test-first-{}", std::process::id());
        let _listener = UapiListener::bind_path(&path).unwrap();
        assert!(UapiListener::bind_path(&path).is_err());
    }

    #[tokio::test]
    async fn serves_requests_over_a_named_pipe() {
        let (source, _local, _mtu) = ChannelSource::new(16, 1420);
        let (sink, _delivered) = ChannelSink::new(16);
        let (transport, _remote) = ChannelTransport::pair(
            16,
            (TransportId::new(1), "192.0.2.1:51820".parse().unwrap()),
            (TransportId::new(2), "192.0.2.2:51820".parse().unwrap()),
        );
        let engine = EngineBuilder::new(source, sink)
            .transport(transport)
            .build()
            .unwrap();
        let handle = engine.handle();
        let uapi = Uapi::new(handle.clone());

        let path = format!(r"\\.\pipe\nsplane-uapi-test-{}", std::process::id());
        let listener = UapiListener::bind_path(&path).unwrap();
        assert_eq!(listener.path(), path.as_str());
        let server = tokio::spawn(async move { uapi.serve(listener).await });

        let secret = StaticSecret::from([1; 32]);
        let private = hex::encode(secret.to_bytes());
        let mut first = BufReader::new(ClientOptions::new().open(&path).unwrap());
        assert!(
            exchange(&mut first, "get=1\n\n")
                .await
                .ends_with("errno=0\n\n")
        );
        let set = format!("set=1\nprivate_key={private}\n\n");
        assert_eq!(exchange(&mut first, &set).await, "errno=0\n\n");

        // A second client while the first is still connected, then one after it closed.
        let mut second = BufReader::new(ClientOptions::new().open(&path).unwrap());
        let reply = exchange(&mut second, "get=1\n\n").await;
        assert!(
            reply.starts_with(&format!("private_key={private}\n")),
            "{reply}"
        );
        assert!(reply.ends_with("errno=0\n\n"), "{reply}");
        drop((first, second));
        let mut third = BufReader::new(ClientOptions::new().open(&path).unwrap());
        let reply = exchange(&mut third, "get=1\n\n").await;
        assert!(
            reply.starts_with(&format!("private_key={private}\n")),
            "{reply}"
        );

        // The server stops with the engine.
        handle.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(engine);
    }
}
