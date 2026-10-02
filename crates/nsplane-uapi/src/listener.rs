//! The Unix socket the `wg` tool connects to.

use std::fs;
use std::future::{Future, poll_fn};
use std::io;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::task::Poll;

use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinSet;

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
    /// Accepts connections on `listener` and serves each on its own task, request after
    /// request, until the engine shuts down.
    ///
    /// On return, and when this future is dropped, the connection tasks are aborted and
    /// the socket file is removed.
    pub async fn serve(&self, listener: UapiListener) -> io::Result<()> {
        let mut events = self.handle().subscribe().await.map_err(io::Error::other)?;
        let mut stopped = pin!(async move {
            // The event channel closes when the engine stops.
            while !matches!(events.recv().await, Err(RecvError::Closed)) {}
        });
        let mut connections = JoinSet::new();
        loop {
            let accepted = poll_fn(|cx| {
                if stopped.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                listener.listener.poll_accept(cx).map(Some)
            })
            .await;
            match accepted {
                None => return Ok(()),
                Some(Ok((stream, _))) => {
                    while connections.try_join_next().is_some() {}
                    let uapi = self.clone();
                    connections.spawn(async move { uapi.serve_connection(stream).await });
                }
                Some(Err(e)) => {
                    tracing::warn!(message = "Failed to accept a UAPI connection", error = ?e);
                }
            }
        }
    }

    /// Serves requests on `stream` until the client closes it or a request fails.
    async fn serve_connection(&self, stream: UnixStream) {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        loop {
            match self.handle_request(&mut reader, &mut writer).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    tracing::debug!(message = "UAPI connection failed", error = ?e);
                    return;
                }
            }
        }
    }
}
