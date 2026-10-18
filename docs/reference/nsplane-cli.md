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

- `wg set <name> listen-port <port>` rebinds the UDP socket.
- `--crypto-workers <N>` enables the crypto worker pool for `N` >= 2.
- `--no-offload` opens the TUN device and binds the UDP socket without segmentation
  offload; a socket rebound over the UAPI keeps the setting.
- An adopted TUN fd starts with MTU 1420 and then follows the interface MTU; the daemon owns
  and closes inherited fds, and a closed or invalid fd fails startup.

## Configuration and defaults

| Argument | Env var | Default |
|---|---|---|
| `<interface_name>` | | required (`utun` or `utunN` on macOS) |
| `-t`, `--threads` | `WG_THREADS` | 4 |
| `-v`, `--verbosity` | `WG_LOG_LEVEL` | `error` (`info`, `debug`, `trace`) |
| `--disable-drop-privileges` | `WG_SUDO` | off |
| `--tun-fd <FD>` | `WG_TUN_FD` | create the interface |
| `--uapi-fd <FD>` | `WG_UAPI_FD` | none |
| `--crypto-workers <N>` | `WG_CRYPTO_WORKERS` | 0 |
| `--no-offload` | `WG_NO_OFFLOAD` | offload on |

## See also

- [README: development CLI](../../README.md#development-cli-linux-and-macos)
- [nsplane-uapi](nsplane-uapi.md)
