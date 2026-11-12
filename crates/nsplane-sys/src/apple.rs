//! Process credential calls of Apple platforms.

use std::io;

/// Replaces the supplementary GIDs of the process with `gids` (`setgroups`). Apple
/// platforms only; elsewhere `nix::unistd::setgroups` is the safe call.
///
/// The kernel keeps the effective GID as the first entry of the list, so `gids[0]` becomes
/// the effective GID of the process as well: a caller that goes on to `setgid` passes that
/// GID first.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] for an empty list, which the kernel would answer by
/// making GID 0 the only entry and the effective GID, and for more than `NGROUPS_MAX` (16)
/// GIDs (`EINVAL`); [`io::ErrorKind::PermissionDenied`] (`EPERM`) unless the process is
/// root. A failed call changes nothing.
pub fn set_supplementary_groups(gids: &[u32]) -> io::Result<()> {
    if gids.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let count = libc::c_int::try_from(gids.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    #[allow(unsafe_code, reason = "setgroups(2)")]
    // SAFETY: `gids` is readable for `count` values of `gid_t`, which is `u32` on these
    // targets (the pointer type checks that), and outlives the call; the kernel copies the
    // list and keeps no pointer.
    let result = unsafe { libc::setgroups(count, gids.as_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GIDs `getgroups` reports for the process.
    fn groups() -> Vec<u32> {
        let mut gids = [0u32; 64];
        let size = libc::c_int::try_from(gids.len()).unwrap();
        #[allow(unsafe_code, reason = "getgroups(2)")]
        // SAFETY: `gids` is writable for `size` values of `gid_t` and outlives the call.
        let count = unsafe { libc::getgroups(size, gids.as_mut_ptr()) };
        gids[..usize::try_from(count).unwrap()].to_vec()
    }

    fn is_root() -> bool {
        #[allow(unsafe_code, reason = "geteuid(2)")]
        // SAFETY: the call takes no argument and cannot fail.
        let euid = unsafe { libc::geteuid() };
        euid == 0
    }

    /// Only root changes the list: for anyone else the call fails and the list stays.
    #[test]
    fn unprivileged_process_is_refused() {
        if is_root() {
            return;
        }
        let before = groups();
        let err = set_supplementary_groups(&[before[0]]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(groups(), before);
    }

    /// An empty list and one longer than the kernel takes are refused for every caller.
    #[test]
    fn empty_and_oversized_lists_are_refused() {
        let before = groups();
        for gids in [&[][..], &[before[0]; 17]] {
            let err = set_supplementary_groups(gids).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert_eq!(groups(), before);
    }

    /// Changes the credentials of the test process, so it runs on its own and as root:
    /// `sudo <test executable> --ignored --exact apple::tests::root_replaces_the_list`.
    #[test]
    #[ignore = "needs root and changes the credentials of the test process"]
    fn root_replaces_the_list() {
        assert!(is_root(), "run as root");
        assert!(groups().len() > 1, "root starts with several GIDs");
        let nobody = u32::MAX - 1;
        set_supplementary_groups(&[nobody]).unwrap();
        assert_eq!(groups(), [nobody]);

        for gids in [&[][..], &[nobody; 17]] {
            let err = set_supplementary_groups(gids).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert_eq!(groups(), [nobody]);
    }
}
