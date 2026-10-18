# nsplane-uapi

The `wg` cross-platform configuration protocol (UAPI) over an nsplane engine, so `wg show`
and `wg set` read and change a running engine. Builds on `nsplane`.

## Public API

| Item | Role |
|---|---|
| `Uapi` (`new`, `with_listen_port`, `with_external_transport`, `bind_transport`, `handle_request`, `serve`, `serve_stream`) | answers `get=1` and `set=1` over an `EngineHandle` |
| `UapiListener` (`bind`, `bind_path`, `path`) | the endpoint the `wg` tool talks to: a Unix socket, or a named pipe on Windows |
| `udp_transport`, `TRANSPORT_ID` | the UDP transport the UAPI owns and its id |
| `socket_path` / `pipe_path` | the standard endpoint of an interface |

## Behavior

### Requests

`Uapi` answers `get=1` and `set=1` by reading and changing the engine through its
`EngineHandle`. `listen_port` and `fwmark` bind a new `UdpTransport` with id `TRANSPORT_ID`
and install it with `EngineHandle::replace_transport` (or `add_transport` when the engine
does not run it yet); other transports of the engine are left alone.

The UAPI rebinds only a UDP transport it owns: one it bound itself (`Uapi::new` with
`bind_transport`, or `listen_port=`) or one the engine was built with (`with_listen_port`,
over `udp_transport`). When the transport under `TRANSPORT_ID` is something else, such as a
link or WebSocket carrier, `with_external_transport` builds a UAPI that never replaces it:
a `listen_port=` or `fwmark=` equal to the reported value is a no-op, any other value fails
with `EADDRINUSE` (98) and is logged. `get=1` still reports the listen port.

### Local identities

The UAPI configures the default local identity (`LocalIdentityId::DEFAULT`) and its peers
only: `private_key` is that identity's key, every peer section addresses a peer of it,
`get=1` lists its peers, and `replace_peers=true` removes them alone. Other local identities
and their peers are managed through the `EngineHandle`; the UAPI neither shows nor touches
them.

### Endpoints

`Uapi::handle_request` serves one request over any async reader and writer. `UapiListener`
binds `/var/run/wireguard/<iface>.sock` on Unix and the named pipe
`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<iface>` with the default security
descriptor on Windows. `Uapi::serve` accepts connections on it; on Unix `serve_stream` serves
one already-connected stream.

## Platform notes

The Windows named-pipe path and security descriptor match wireguard-windows; they are
covered by the Windows unit tests under wine, not by a test on a Windows host.

## See also

- [nsplane-cli](nsplane-cli.md): the development daemon that serves this UAPI.
- [nsplane](nsplane.md): `EngineHandle` and the transports.
