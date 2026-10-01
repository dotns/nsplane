// SPDX-License-Identifier: BSD-3-Clause

//! The UAPI named pipe, `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<interface>`, the
//! path `wg.exe` and wireguard-go use on Windows.
#![allow(unsafe_code, reason = "named pipe and security descriptor Win32 calls")]

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, RawHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

/// Full access for SYSTEM and Administrators only, high integrity, like wireguard-go.
const SDDL: &str = "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)";
const BUFFER_SIZE: u32 = 4096;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// The pipe path of the interface `name`.
pub(super) fn path(name: &str) -> String {
    format!(r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{name}")
}

/// Creates pipe instances and waits for clients.
pub(super) struct PipeServer {
    path: Vec<u16>,
    security_descriptor: PSECURITY_DESCRIPTOR,
}

impl std::fmt::Debug for PipeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeServer").finish_non_exhaustive()
    }
}

// SAFETY: the security descriptor is immutable after creation and only read by the Win32 calls
// that create pipe instances.
unsafe impl Send for PipeServer {}

impl PipeServer {
    pub(super) fn new(path: &str) -> io::Result<Self> {
        let sddl = wide(SDDL);
        let mut security_descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string; the descriptor is written to a
        // valid out-pointer and freed with `LocalFree` in `Drop`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut security_descriptor,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            path: wide(path),
            security_descriptor,
        })
    }

    /// Creates a pipe instance and blocks until a client connects to it.
    pub(super) fn accept(&self) -> io::Result<File> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.security_descriptor,
            bInheritHandle: 0,
        };
        // SAFETY: `path` is NUL-terminated UTF-16 and `attributes` points to a valid security
        // descriptor; both outlive the call.
        let handle = unsafe {
            CreateNamedPipeW(
                self.path.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                &raw const attributes,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `CreateNamedPipeW` returned a new handle that nothing else owns.
        let pipe = unsafe { File::from_raw_handle(handle as RawHandle) };

        // SAFETY: `handle` is a valid pipe handle (owned by `pipe`); no overlapped I/O.
        let connected = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) } != 0
            // SAFETY: reads the calling thread's last error code.
            || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED;
        if !connected {
            return Err(io::Error::last_os_error());
        }
        Ok(pipe)
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is freed once.
        unsafe { LocalFree(self.security_descriptor) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader, Write as _};

    #[test]
    fn serves_a_client() {
        let path = path(&format!("nstun-test-{}", std::process::id()));
        let server = PipeServer::new(&path).unwrap();
        let client_path = path;
        let client = std::thread::spawn(move || {
            // The server creates the instance first; retry until it exists.
            let mut pipe = loop {
                if let Ok(pipe) = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&client_path)
                {
                    break pipe;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            };
            pipe.write_all(b"get=1\n\n").unwrap();
            let mut reply = String::new();
            BufReader::new(&pipe).read_line(&mut reply).unwrap();
            reply
        });

        let conn = server.accept().unwrap();
        let mut request = String::new();
        BufReader::new(&conn).read_line(&mut request).unwrap();
        assert_eq!(request, "get=1\n");
        (&conn).write_all(b"errno=0\n\n").unwrap();
        assert_eq!(client.join().unwrap(), "errno=0\n");
    }
}
