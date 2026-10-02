//! The Unix socket the `wg` tool connects to.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use crate::uapi::Uapi;

/// The directory of the UAPI sockets.
const SOCK_DIR: &str = "/var/run/wireguard";

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
    /// be removed after privileges are dropped. A stale socket is replaced.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind(iface: &str) -> io::Result<Self> {
        create_sock_dir();
        Self::bind_path(socket_path(iface))
    }

    /// Binds a socket at `path`, replacing a stale socket; the directory must exist.
    ///
    /// # Panics
    ///
    /// Panics when called outside a tokio runtime with I/O enabled.
    pub fn bind_path(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let _ = fs::remove_file(&path); // Attempt to remove the socket if already exists
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
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
