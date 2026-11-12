# nsplane-cli

A development and test daemon for Linux and macOS: one engine on a TUN device, configured
with the standard `wg` tool. Products embed the library instead; this binary is not a public
API.

## Behavior

`nsplane-cli <interface>` builds a multi-threaded tokio runtime (`--threads` workers),
creates the TUN device (or adopts one with `--tun-fd`), builds an engine on it, binds a UDP
transport on an ephemeral port, serves the UAPI on `/var/run/wireguard/<name>.sock` (and on
an inherited stream with `--uapi-fd`), drops privileges to `SUDO_UID` / `SUDO_GID` unless
`--disable-drop-privileges`, and runs in the foreground until SIGINT or SIGTERM. It logs to
stderr and does not daemonize, so `wg-quick` with `WG_QUICK_USERSPACE_IMPLEMENTATION` is not
supported.

- The UAPI socket has mode `0600` and belongs to the user the daemon started as. Started
  with `sudo`, that is root, also after the privilege drop: use `sudo wg`. Started
  unprivileged (`setcap cap_net_admin+epi`), the same user runs `wg`.
- The privilege drop sets the supplementary GIDs to the target GID (`setgroups`), then the
  GID and the UID, and fails startup if root can be regained. On macOS the first step is
  missing: the daemon keeps the supplementary GIDs it started with, those of root under
  `sudo` (`wheel`, `admin` and the like), so after the drop it still passes permission checks
  made on those GIDs, for example a file readable or writable by `admin`; its UID and GID are
  the invoking user's. `nix` 0.31 provides neither `setgroups` nor `initgroups` on Apple
  targets, no other dependency has a safe wrapper, and the crate allows no further `unsafe`
  block. Where that matters, do not run the daemon as root on macOS.
- `wg set <name> listen-port <port>` rebinds the UDP socket.
- `--crypto-workers <N>` enables the crypto worker pool for `N` >= 2.
- `--no-offload` opens the TUN device and binds the UDP socket without segmentation
  offload; a socket rebound over the UAPI keeps the setting.
- An adopted TUN fd starts with MTU 1420 and then follows the interface MTU.
- The daemon takes ownership of the `--tun-fd` and `--uapi-fd` descriptors first thing after
  parsing its arguments, before the logger and the runtime exist, so a number can only name
  a descriptor the invoker passed. It sets `FD_CLOEXEC` on them and closes them on exit. A
  number below 3 (the standard streams), a number that is not an open descriptor, the same
  number for both options, or a `--uapi-fd` that is not a Unix socket fails startup.
- Turning a descriptor number into an owned descriptor is the one `unsafe` block of the
  binary (`adopt_fd`); its soundness rests on the invoker passing descriptors that are open
  and meant for the daemon.

## Configuration and defaults

| Argument | Env var | Default |
|---|---|---|
| `<interface_name>` | | required (`utun` or `utunN` on macOS) |
| `-t`, `--threads` | `WG_THREADS` | 4 (at least 1) |
| `-v`, `--verbosity` | `WG_LOG_LEVEL` | `error` (`info`, `debug`, `trace`) |
| `--disable-drop-privileges` | `WG_SUDO` | off |
| `--tun-fd <FD>` | `WG_TUN_FD` | create the interface |
| `--uapi-fd <FD>` | `WG_UAPI_FD` | none |
| `--crypto-workers <N>` | `WG_CRYPTO_WORKERS` | 0 |
| `--no-offload` | `WG_NO_OFFLOAD` | offload on |

## See also

- [README: development CLI](../../README.md#development-cli-linux-and-macos)
- [nsplane-uapi](nsplane-uapi.md)
