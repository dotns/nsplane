//! The Unix socket the `wg` tool connects to.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixSocket, UnixStream};

use crate::uapi::Uapi;

/// The directory of the UAPI sockets.
const SOCK_DIR: &str = "/var/run/wireguard";

/// The mode of a UAPI socket file: its owner only.
const SOCK_MODE: u32 = 0o600;

/// The backlog of a UAPI socket; the kernel caps it at its own limit.
const BACKLOG: u32 = 1024;

/// The standard UAPI socket path of interface `iface`: `/var/run/wireguard/<iface>.sock`.
pub fn socket_path(iface: &str) -> PathBuf {
    Path::new(SOCK_DIR).join(format!("{iface}.sock"))
}

/// A listening UAPI socket; the socket file is removed when it is dropped.
#[derive(Debug)]
pub struct UapiListener {
    listener: UnixListener,
    path: PathBuf,
}

impl UapiListener {
    /// Binds the standard socket of interface `iface` (see [`socket_path`]).
    ///
    /// Creates `/var/run/wireguard` if needed and, when the process runs under `sudo`, hands
    /// the directory to the invoking user (`SUDO_UID` / `SUDO_GID`), so the socket can still
    /// be removed after privileges are dropped. The socket itself stays with the user that
    /// bound it, with mode `0600`: bound by root, it takes root to connect (`sudo wg`), as
    /// with wireguard-go. The existing path is removed without
    /// checking its type or whether a listener is active; see [`Self::bind_path`].
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind(iface: &str) -> io::Result<Self> {
        create_sock_dir();
        Self::bind_path(socket_path(iface))
    }

    /// Binds a socket at `path`; the directory must exist. Attempts to remove any
    /// existing file or symlink at the path without checking its type or staleness.
    /// Removal errors are ignored; the subsequent bind determines success.
    ///
    /// The socket file gets mode `0600` whatever the process umask is, as wireguard-go
    /// creates it: `get=1` answers with the private key, so only the owner (and root) may
    /// connect. The mode is set before the socket listens, and a socket that does not
    /// listen refuses connections, so no client gets in under the mode the umask gave.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind_path(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let _ = fs::remove_file(&path); // Remove an existing path without a type or staleness check.
        let socket = UnixSocket::new_stream()?;
        socket.bind(&path)?;
        // From here on the socket file is removed when this fails.
        let bound = Self::listen(socket, &path);
        if bound.is_err() {
            let _ = fs::remove_file(&path);
        }
        Ok(Self {
            listener: bound?,
            path,
        })
    }

    /// Makes the file of the bound `socket` at `path` owner-only, then listens on it.
    fn listen(socket: UnixSocket, path: &Path) -> io::Result<UnixListener> {
        fs::set_permissions(path, fs::Permissions::from_mode(SOCK_MODE))?;
        socket.listen(BACKLOG)
    }

    /// The path of the socket file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Waits for the next client and returns the read and write halves of its connection.
    pub(crate) async fn accept(&self) -> io::Result<(OwnedReadHalf, OwnedWriteHalf)> {
        let (stream, _) = self.listener.accept().await?;
        Ok(stream.into_split())
    }
}

impl Drop for UapiListener {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn create_sock_dir() {
    let _ = fs::create_dir(SOCK_DIR); // Create the directory if it does not exist

    let id = |name| std::env::var(name).ok()?.parse::<u32>().ok();
    if let (Some(uid), Some(gid)) = (id("SUDO_UID"), id("SUDO_GID")) {
        // The directory is under the root user, but we want to be able to
        // delete the files there when we exit, so we need to change the owner
        let _ = std::os::unix::fs::chown(SOCK_DIR, Some(uid), Some(gid));
    }
}

impl Uapi {
    /// Serves requests on one connected `stream`, request after request, until the client
    /// closes it or a request fails; then the stream is closed.
    ///
    /// [`Uapi::serve`] runs this for every accepted connection. Call it directly for a
    /// connection that did not come from a [`UapiListener`], such as a socket inherited
    /// from a parent process (the CLI's `--uapi-fd`). It does not watch the engine: once
    /// the engine stops, the next request is answered with an error and the stream closes.
    pub async fn serve_stream(&self, stream: UnixStream) {
        let (reader, writer) = stream.into_split();
        self.serve_connection(reader, writer).await;
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use nsplane::{ChannelSink, ChannelSource, EngineBuilder};
    use tracing::span;

    use super::*;
    use crate::udp_transport;

    /// A new directory for the sockets of test `name`.
    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nsplane-uapi-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_socket_is_owner_only() {
        let dir = dir("mode");
        let path = dir.join("wg-test.sock");
        let listener = UapiListener::bind_path(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        // It still accepts its owner.
        let client = UnixStream::connect(&path).await.unwrap();
        listener.accept().await.unwrap();
        drop((client, listener));
        assert!(!path.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    /// Counts the warnings of this crate.
    struct CountWarnings(Arc<AtomicUsize>);

    impl tracing::Subscriber for CountWarnings {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
                && metadata.target().starts_with("nsplane_uapi")
        }

        fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _: &span::Id, _: &span::Record<'_>) {}

        fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}

        fn event(&self, _: &tracing::Event<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn enter(&self, _: &span::Id) {}

        fn exit(&self, _: &span::Id) {}
    }

    #[tokio::test]
    async fn failed_accepts_are_retried_after_a_pause() {
        let (source, _local, _mtu) = ChannelSource::new(16, 1420);
        let (sink, _delivered) = ChannelSink::new(16);
        let engine = EngineBuilder::new(source, sink)
            .transport(udp_transport(0).unwrap())
            .build()
            .unwrap();
        let uapi = Uapi::new(engine.handle());

        // Accepting on a connected socket fails at once (EINVAL), every time, as a
        // listening one does when the process is out of file descriptors (EMFILE).
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Readable, so that tokio attempts the accept.
        peer.write_all(b"x").unwrap();
        let socket = std::os::unix::net::UnixListener::from(OwnedFd::from(socket));
        socket.set_nonblocking(true).unwrap();
        let listener = UapiListener {
            listener: UnixListener::from_std(socket).unwrap(),
            path: PathBuf::new(),
        };

        let warnings = Arc::new(AtomicUsize::new(0));
        let _guard = tracing::subscriber::set_default(CountWarnings(Arc::clone(&warnings)));
        let serving = tokio::spawn(async move { uapi.serve(listener).await });
        tokio::time::sleep(Duration::from_millis(350)).await;
        let logged = warnings.load(Ordering::Relaxed);
        assert!(
            (1..=10).contains(&logged),
            "{logged} failed accepts in 350 ms"
        );

        // The pause does not delay the reaction to the engine stopping.
        engine.handle().shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
