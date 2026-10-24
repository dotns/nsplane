# nsplane-dns

Generic DNS serving: owned message types, a wire codec, the async `Resolver` trait, resolvers
to compose (local records, fake addresses, forwarding) and a server over UDP and TCP. It
answers clients with what the embedder decides; resolution policy (which names are local,
which are faked, where the rest goes) stays with the embedder, which can express it as a rule
table for `PolicyResolver`. It is not a full DNS
implementation: no zones, no DNSSEC, no recursion, no cache, no zone transfers or updates.
The codec builds on the `simple-dns` fork (ADR
[2026-10-24-simple-dns-fork](../decisions/2026-10-24-simple-dns-fork.md)), which stays an
implementation detail: no `simple-dns` type appears in the public API. The optional `netstack`
feature builds on `nsplane-netstack`.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| messages and codec (`message`) | `Query::decode` (`id`, `name`, `record_type`, `class`, `recursion_desired`, `udp_payload_size`, `raw`), `encode_response`, `encode_error`, `max_udp_response_size`, `normalize_name` | `Record` (`new`, `a`, `aaaa`, `cname`, `ptr`, `txt`, `record_type`), `RecordData`, `RecordType`, `ResponseCode` (`value`), `Answer`, `DecodeError` (`id`, `response_code`), `EncodeOptions`, `DEFAULT_UDP_PAYLOAD_SIZE`, `MIN_UDP_RESPONSE_SIZE`, `CLASS_IN` |
| resolvers: composition (`resolver`) | trait `Resolver` (also for `Arc<R>` and `&R`), `Fallback` (`new`) | |
| resolvers: static records (`records`) | `StaticRecords` (`new`, `insert`, `FromIterator<Record>`, `lookup`, `with_fallback`, `len`, `is_empty`) | |
| resolvers: fake addresses (`fake`) | `FakePool` (`new`, `with_fallback`, `lookup`, `lookup_name`, `capacity`, `len`, `is_empty`, `stats`) | `FakePoolConfig`, `FakePoolConfigError`, `FakePoolStats`, `NoData`, `DEFAULT_FAKE_CAPACITY`, `DEFAULT_FAKE_TTL` |
| resolvers: forwarding (`forward`) | `Forwarder` (`new`, `config`, `stats`) | `ForwarderConfig` (`new`), `ForwarderError`, `ForwarderStats` |
| resolvers: policy routing (`policy`) | `PolicyResolver` (`new`, `replace`, `replace_table`, `table`, `matching`, `stats`) | `PolicyTable` (`new`, `with_ttl`, `rules`, `ttl`, `matching`), `Rule` (`new`, `with_types`, `with_clients`, `with_on_nxdomain`), `NameMatch`, `Action`, `NxDomainFallback`, `ResolverSet` (`new`, `with`, `insert`, `contains`, `len`, `is_empty`), `PolicyStats`, `PolicyError`, `DEFAULT_POLICY_TTL`, `MAX_CNAME_CHAIN` |
| hosts text (`hosts`) | `Hosts` (`parse`, `static_records`, `wildcard_rules`, `rules`, `errors`, `is_empty`) | `HostsError`, `HostsErrorKind` |
| server (`server`) | `Server` (`new`, `handle`, `serve_udp`, `serve_tcp`, `serve_stream`, `config`, `resolver`, `stats`) | `ServerConfig` (`with_max_in_flight`, `with_udp_payload_size`, `with_resolve_timeout`, `with_tcp_idle_timeout`), `ServerStats`, `Transport` |
| feature `netstack` (`netstack`) | `Server::serve_udp_flow`, `Server::serve_tcp_connection` | |

## Behavior

### Codec

`Query::decode` accepts a query (`QR` = 0) with opcode `QUERY` and exactly one question. The
question name is normalized (ASCII-lowercase, no trailing dot) for matching; `raw` keeps the
received bytes for forwarding. Records in the other sections are ignored except the EDNS OPT
record, whose UDP payload size `udp_payload_size` reports. A message that does not decode
yields a `DecodeError`: `response_code` is `FORMERR` for a malformed message or zero or
several questions, `NOTIMP` for another opcode, and `None` (drop silently) for input shorter
than the header or a response. `encode_error(id, code)` answers the former without a
question.

`encode_response` echoes the ID, `RD` and the question as the client sent it (its case
included), sets `QR` and `RA`, and sets `AA` for local answers (`Answer::Records`,
`Answer::Code`). `Answer::Records` with an empty list is `NODATA`. When the query carried an
OPT record, the response carries one advertising `EncodeOptions::udp_payload_size`
(`DEFAULT_UDP_PAYLOAD_SIZE`, 1232, by default); a query without one gets none. `Answer::Raw`
is passed through with only the ID replaced. Records that do not encode (a name that is not a
host name, a TXT string over 255 bytes) give `SERVFAIL`.

### Truncation

`max_udp_response_size` is 512 bytes without EDNS, else the client's payload size clamped to
512 and `EncodeOptions::udp_payload_size`. A response longer than the `max_size` passed to
`encode_response` (records or raw) is replaced by the truncated form built from the query:
header with `TC` = 1, the question and the OPT record, no answers, which fits any limit of at
least 512 bytes. The client then retries over TCP, where the limit is 65535.

### Resolver

`Resolver::resolve(&query, client)` returns an `Answer`; the trait uses native async
functions in traits. A server calls it concurrently, so implementations await slow work
instead of blocking. `client` is the transport peer. `Fallback<A, B>` asks `A` and, only when
`A` answers `NXDOMAIN`, asks `B`; `NODATA` and other codes from `A` are final. Fallbacks nest
to chain several resolvers without trait objects. `StaticRecords::with_fallback` builds a
`Fallback`; `FakePool::with_fallback` is different (see below).

### StaticRecords

An immutable table once shared, filled with `insert` or `collect()`. Names match
case-insensitively, with or without a trailing dot. For a known name of class IN: its
`CNAME` records for any query type when it has one, else its records of the query type (all
for `ANY`), else `NODATA`. Unknown names and other classes answer `NXDOMAIN`, so
`with_fallback` hands them to the next resolver.

### FakePool

Answers class IN A and AAAA queries with addresses allocated per name from an IPv4 and/or an
IPv6 prefix. A name gets one binding holding a host index; its IPv4 and IPv6 addresses share
that index, so the A and AAAA answers of a name stay stable together. Indexes are handed out
sequentially, skipping the network address (and, for IPv4 prefixes shorter than /31, the
broadcast address). The answer is one record with TTL `FakePoolConfig::ttl`; a family without
a prefix answers `NODATA`.

Every answer refreshes the binding's last use. When no fresh index is left (capacity or prefix
exhausted), the least recently used binding unused for at least `ttl` is evicted and its
addresses go to the new name (`FakePoolStats::reused`). A binding is never evicted earlier: while
every binding is within its TTL the pool answers `SERVFAIL` (`FakePoolStats::exhausted`).

`lookup(addr)` maps an address of either family back to its name and `lookup_name(name)`
returns a name's addresses; neither allocates nor refreshes. Queries of other types or classes
go to the pool's fallback: `NoData` (answers `NODATA`) by default, any resolver with
`with_fallback`, which replaces that fallback instead of chaining on `NXDOMAIN`.

### Forwarder

Forwards each query to upstream servers and answers with their response (`Answer::Raw`).
Each attempt sends the client's query under a fresh transaction ID from a new ephemeral UDP
socket connected to the upstream. Only a response with that ID and the query's question (name
compared case-insensitively, type and class) is accepted; other datagrams are ignored until
the attempt times out. A truncated response (`TC` = 1) is retried over TCP to the same
upstream. Attempts rotate through `ForwarderConfig::upstreams` in order, starting with the
first for every query; when all attempts fail (timeout, ICMP refusal, I/O error) the answer is
`SERVFAIL`. Any accepted response is final, whatever its response code.

The transaction ID mixes a counter with the socket's port and is not cryptographically random;
resistance against spoofed responses comes mostly from the random source port of every
attempt. There is no cache and no policy: every query the forwarder gets is forwarded. To
answer some names locally, put it behind other resolvers, for example
`StaticRecords::with_fallback(forwarder)`.

### PolicyResolver

Routes each query by a `PolicyTable` to one of the resolvers of a `ResolverSet`, registered
under string ids and of any types (shared ones as `Arc<R>`), or to a local answer. A `Rule`
has a name match, optional conditions and an action; names are normalized on install.

| `NameMatch` | Matches |
|---|---|
| `Exact(name)` | that name |
| `Suffix(name)` | that name and every name below it, on label boundaries |
| `Wildcard("*.name")` | every name below `name`, not `name` itself (hosts-style); the `*` is the whole leftmost label |
| `Default` | every name |

Conditions: `types` (query types) and `clients` (client prefixes; IPv4-mapped IPv6 clients
match as IPv4); empty means any. The rule for a query is the first by precedence, then by
declaration order, whose conditions hold: exact rules; then suffix and wildcard rules by the
length of the name they are anchored at, longer first, a suffix rule before a wildcard rule
at equal length; then default rules. A query no rule applies to is answered `REFUSED`
(`PolicyStats::unmatched`). A lookup costs a few hash lookups per label of the query name,
whatever the number of rules; `matching(name, type, client)` returns the index of the rule a
query would use.

| `Action` | Answer |
|---|---|
| `Resolve(id)` | the registered resolver's answer |
| `Records(data)` | the entries of the query type (all for `ANY`) under the query name, `NODATA` without any; a wildcard hosts entry under a suffix or wildcard rule |
| `Block(code)` | the code without records, typically `NXDOMAIN` or `REFUSED` |
| `Sinkhole` | A `0.0.0.0`, AAAA `::` (both for `ANY`), `NODATA` for other types |
| `NoData` | `NOERROR` without records |
| `Cname(target)` | a CNAME from the query name to `target`, then the answer for `target` |

Local records carry the table TTL (`PolicyTable::with_ttl`). With `on_nxdomain`, a
`Resolve` rule whose resolver answers `NXDOMAIN` (`Answer::Code`, or `Answer::Raw` with that
code) hands the query once to the default rule (`NxDomainFallback::Default`, the first
default rule whose conditions hold, other than the rule itself) or to another resolver
(`NxDomainFallback::Resolve`).

A `Cname` target is resolved through the same table with the query's type, class, ID, `RD`
and EDNS payload size and the same client; a query of type CNAME gets the CNAME alone. The
answer is the chain of CNAME records followed by the target's answer: its records, or an
upstream response with the client's question restored and the chain in front of its
answers, or the target's response code with the chain. The chain stops with the records
collected so far when a target repeats a name of the chain, at `MAX_CNAME_CHAIN` (8)
records, or when no rule applies to a target.

`PolicyTable::new` rejects empty or invalid names, wildcards not of the form `*.name`,
invalid CNAME targets (also CNAME / PTR data in `Records`) and prefix lengths over the
address width. Installing (`new`, `replace` with a new resolver set, `replace_table` with the
current one) rejects resolver ids not in the set; on error the current installation stays.
The resolver set and table are swapped atomically: every query, CNAME chain included, runs
against the installation current when it started, and queries in flight finish with it;
the `Server` keeps running. `PolicyStats` counts applications per rule (restarting with each
installation) and per action, `NXDOMAIN` fallbacks and unmatched lookups.

### Hosts

`Hosts::parse` reads hosts-format text: `address name...` per line, whitespace-separated,
`#` comments, IPv4 and IPv6 addresses (no zone index), several names per line and several
lines per name (addresses in order, duplicates once). A name `*.name` is a wildcard. Parsing
does not fail as a whole: a line with an invalid address is skipped, an invalid name is
skipped with the rest of its line kept, and each problem is a `HostsError` with its line
number in `errors()`. `static_records(ttl)` builds `StaticRecords` from the plain names,
`wildcard_rules()` a `Wildcard` rule with `Action::Records` per wildcard, `rules()` such a
rule for every name (plain names as `Exact`). Reading the text from a file is the embedder's.

### Server

`Server::handle` is the transport-neutral core: one message in, at most one response out. A
message that does not decode is answered by `encode_error` when its header is readable, else
dropped. A query is resolved under `ServerConfig::resolve_timeout`; when it expires the answer
is `SERVFAIL` (`ServerStats::timeouts`). The response is encoded with the limit of the
`Transport`: `max_udp_response_size` over UDP, 65535 over TCP. `handle` does not bound
concurrency itself.

The serve functions bound the queries resolved at once, over all transports of a server and
its clones, to `ServerConfig::max_in_flight`:

- UDP (`serve_udp`, `serve_udp_flow`): each datagram is handled in its own task holding a
  permit. Without a free permit the datagram is dropped and counted in
  `ServerStats::dropped_overload`; the client retries. `serve_udp` skips receive errors
  caused by one peer (ICMP-reported reset or unreachable port) and returns on any other.
- TCP (`serve_tcp`, `serve_stream`, `serve_tcp_connection`): connections are served each in
  its own task with two-byte length framing (RFC 1035 section 4.2.2, RFC 7766). Queries on a
  connection are processed one at a time in arrival order, pipelined ones included; each
  waits for a permit instead of being dropped. The connection is closed on end of stream, a
  zero-length or cut-off frame, a message that gets no response, or when
  `ServerConfig::tcp_idle_timeout` passes without a query or without the client reading the
  response.

### netstack feature

`Server::serve_udp_flow` answers the datagrams of one `nsplane-netstack` `UdpFlow` through its
reply handle until the flow ends, with the UDP overload rule above. `Server::serve_tcp_connection`
serves one `TcpConnection` with `serve_stream`, the client being the connection's peer. The
stack reports flows and connections to every port; the embedder routes the ones for its DNS
address and port to these functions.

## Configuration and defaults

| Setting | Default |
|---|---|
| `ServerConfig::max_in_flight` | 256 |
| `ServerConfig::udp_payload_size` | `DEFAULT_UDP_PAYLOAD_SIZE` (1232) |
| `ServerConfig::resolve_timeout` | 5 s |
| `ServerConfig::tcp_idle_timeout` | 10 s |
| `FakePoolConfig::ipv4` / `ipv6` | none (at least one required) |
| `FakePoolConfig::capacity` | `DEFAULT_FAKE_CAPACITY` (65536), bounded by the prefix sizes |
| `FakePoolConfig::ttl` | `DEFAULT_FAKE_TTL` (60 s) |
| `ForwarderConfig::timeout` | 2 s per attempt (the UDP exchange; the TCP retry has its own) |
| `ForwarderConfig::attempts` | 2 |
| `PolicyTable::with_ttl` | `DEFAULT_POLICY_TTL` (60 s) |

## Errors and drop reasons

- `FakePoolConfigError`: `NoPrefix`, `InvalidPrefixLength`, `HostBitsSet` (prefix address
  with host bits set), `Empty` (zero capacity or no usable address).
- `ForwarderError`: `NoUpstreams`, `NoAttempts`.
- `PolicyError` (with the rule index): `InvalidName`, `InvalidTarget`, `InvalidPrefix`,
  `UnknownResolver`.
- `HostsError` (with the line number): `HostsErrorKind::InvalidAddress`, `NoName`,
  `InvalidName`.
- Server: every message that does not decode counts in `ServerStats::decode_errors`; it is
  answered `FORMERR` or `NOTIMP`, or dropped when it is shorter than the header or a
  response. UDP datagrams over the in-flight bound are dropped
  (`ServerStats::dropped_overload`).

## Limits and bounds

- One question per message; opcodes other than `QUERY` (notify, update) are answered with
  `NOTIMP`.
- Response codes are limited to `ResponseCode` (no extended codes).
- `RecordData` covers A, AAAA, CNAME, PTR and TXT.
- At most `max_in_flight` queries resolve at once per server; a `FakePool` holds at most
  `capacity` bindings.
- A CNAME chain of `PolicyResolver` holds at most `MAX_CNAME_CHAIN` (8) records. Name
  matching has no wildcards inside a label or in the middle of a name.

## See also

- [nsplane-netstack](nsplane-netstack.md): the user-space stack served by the `netstack`
  feature.
- [ADR: simple-dns fork](../decisions/2026-10-24-simple-dns-fork.md)
- [`dns_netstack`](../../examples/README.md#dns_netstack): a server on an address a transparent
  netstack terminates without owning it, with static, fake and forwarded answers.
