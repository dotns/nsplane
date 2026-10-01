// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::dev_lock::LockReadGuard;
use super::drop_privileges::get_saved_ids;
use super::peer_table::{PeerTable, PeerTableError, PeerUpdate};
use super::{Device, Error, uapi};
use crate::device::Action;
use crate::x25519;
use libc::{EIO, SIGINT, SIGTERM};
use std::fs::{create_dir, remove_file};
use std::io::{BufReader, BufWriter};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::Ordering;

const SOCK_DIR: &str = "/var/run/wireguard";

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        // The directory is under the root user, but we want to be able to
        // delete the files there when we exit, so we need to change the owner
        let _ = std::os::unix::fs::chown(SOCK_DIR, Some(saved_uid), Some(saved_gid));
    }
}

impl Device {
    /// Register the api handler for this Device. The api handler receives stream connections on a Unix socket
    /// with a known path: /`var/run/wireguard/{tun_name}.sock`.
    pub fn register_api_handler(&mut self) -> Result<(), Error> {
        let path = format!("{}/{}.sock", SOCK_DIR, self.iface.name()?);

        create_sock_dir();

        let _ = remove_file(&path); // Attempt to remove the socket if already exists

        let api_listener = UnixListener::bind(&path).map_err(Error::ApiSocket)?; // Bind a new socket to the path

        self.cleanup_paths.push(path.clone());

        self.queue.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api unix socket
                let Ok((api_conn, _)) = api_listener.accept() else {
                    return Action::Continue;
                };
                serve_api(&api_conn, d);
                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        self.register_monitor(path)?;
        self.register_api_signal_handlers()
    }

    /// Serves the UAPI over an inherited, already connected stream socket.
    pub fn register_api_fd(&mut self, fd: i32) -> Result<(), Error> {
        #[allow(unsafe_code, reason = "adopting an inherited file descriptor")]
        // SAFETY: the caller hands over ownership of `fd` (`WG_UAPI_FD`), an open stream socket
        // that nothing else in the process uses.
        let io_file = unsafe { UnixStream::from_raw_fd(fd) };

        self.queue.new_event(
            io_file.as_raw_fd(),
            Box::new(move |d, _| {
                // This is the closure that listens on the api file descriptor
                if !serve_api(&io_file, d) {
                    // The remote side is likely closed; we should trigger an exit.
                    d.trigger_exit();
                    return Action::Exit;
                }

                Action::Continue // Indicates the worker thread should continue as normal
            }),
        )?;

        Ok(())
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;

        Ok(())
    }

    fn register_api_signal_handlers(&self) -> Result<(), Error> {
        self.queue
            .new_signal_event(SIGINT, Box::new(move |_, _| Action::Exit))?;

        self.queue
            .new_signal_event(SIGTERM, Box::new(move |_, _| Action::Exit))?;

        Ok(())
    }
}

impl uapi::UapiDevice for Device {
    fn public_key(&self) -> Option<&x25519::PublicKey> {
        self.key_pair.as_ref().map(|(_, public)| public)
    }

    fn listen_port(&self) -> u16 {
        self.listen_port
    }

    fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    fn peers(&self) -> &PeerTable {
        &self.peers
    }

    fn set_key(&mut self, private_key: &x25519::StaticSecret) {
        Self::set_key(self, private_key);
    }

    fn open_listen_socket(&mut self, port: u16) -> Result<(), Error> {
        Self::open_listen_socket(self, port)
    }

    fn set_fwmark(&mut self, mark: u32) -> Result<(), Error> {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        return Self::set_fwmark(self, mark);
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        {
            let _ = mark;
            Err(Error::SetSockOpt(
                "fwmark is not supported on this platform".to_owned(),
            ))
        }
    }

    fn clear_peers(&mut self) {
        Self::clear_peers(self);
    }

    fn update_peer(&mut self, update: PeerUpdate) -> Result<(), PeerTableError> {
        Self::update_peer(self, update)
    }
}

/// Serves one UAPI request on `stream`; returns `false` when the connection is closed.
fn serve_api(stream: &UnixStream, d: &mut LockReadGuard<'_, Device>) -> bool {
    let mut reader = BufReader::new(stream);
    let mut writer = BufWriter::new(stream);
    uapi::serve(&mut reader, &mut writer, |request, r, w| match request {
        uapi::Request::Get => uapi::get(w, &**d),
        // Writers need every event loop thread to yield its read lock first.
        uapi::Request::Set => d
            .try_writable(Device::trigger_yield, |device| {
                device.cancel_yield();
                uapi::set(r, device)
            })
            .unwrap_or(EIO),
    })
}
