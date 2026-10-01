// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::Error;
use libc::{gid_t, uid_t};
use nix::unistd::{Gid, Uid, User, setgid, setuid};

/// Name of the user that started the process, before any `sudo`.
fn login_name() -> Result<String, Error> {
    #[cfg(target_os = "macos")]
    {
        std::env::var("USER").map_err(|e| {
            Error::DropPrivileges(format!(
                "Could not get environment variable for user; err: {e:?}"
            ))
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[allow(unsafe_code, reason = "getlogin has no safe wrapper")]
        // SAFETY: `getlogin` takes no arguments; the result is checked for NULL before use.
        let uname = unsafe { libc::getlogin() };
        if uname.is_null() {
            return Err(Error::DropPrivileges("NULL from getlogin".to_owned()));
        }
        #[allow(unsafe_code, reason = "getlogin has no safe wrapper")]
        // SAFETY: `getlogin` returned a non-NULL, NUL-terminated string in static storage.
        let uname = unsafe { std::ffi::CStr::from_ptr(uname) };
        Ok(uname.to_string_lossy().into_owned())
    }
}

/// Returns the user and group IDs of the user that started the process.
pub fn get_saved_ids() -> Result<(uid_t, gid_t), Error> {
    // Get the user name of the sudoer
    match User::from_name(&login_name()?) {
        Ok(Some(user)) => Ok((uid_t::from(user.uid), gid_t::from(user.gid))),
        Err(e) => Err(Error::DropPrivileges(format!(
            "Failed parse user; err: {e:?}"
        ))),
        Ok(None) => Err(Error::DropPrivileges("Failed to find user".to_owned())),
    }
}

/// Permanently switches to the IDs from [`get_saved_ids`].
pub fn drop_privileges() -> Result<(), Error> {
    let (saved_uid, saved_gid) = get_saved_ids()?;

    // Set real and effective group ID
    setgid(Gid::from_raw(saved_gid)).map_err(|e| Error::DropPrivileges(e.to_string()))?;
    // Set real and effective user ID
    setuid(Uid::from_raw(saved_uid)).map_err(|e| Error::DropPrivileges(e.to_string()))?;

    // Validated we can't get sudo back again
    if setgid(Gid::from_raw(0)).is_ok() || setuid(Uid::from_raw(0)).is_ok() {
        Err(Error::DropPrivileges(
            "Failed to permanently drop privileges".to_owned(),
        ))
    } else {
        Ok(())
    }
}
