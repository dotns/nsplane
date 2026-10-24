# nsplane-dns

DNS serving building blocks: owned message types, a wire codec, the async `Resolver` trait
and resolvers to compose. It answers clients with what the embedder decides (local records,
addresses it hands out, forwarded responses); it is not a full DNS server: no zones, no
DNSSEC, no recursion, no zone transfers or updates. The codec builds on the `simple-dns`
fork (ADR [2026-10-24-simple-dns-fork](../decisions/2026-10-24-simple-dns-fork.md)), which
stays an implementation detail: no `simple-dns` type appears in the public API.

## Public API

| Part | Entry points | Supporting types |
|---|---|---|
| messages and codec (`message`) | `Query::decode` (`id`, `name`, `record_type`, `class`, `recursion_desired`, `udp_payload_size`, `raw`), `encode_response`, `encode_error`, `max_udp_response_size`, `normalize_name` | `Record` (`new`, `a`, `aaaa`, `cname`, `ptr`, `txt`), `RecordData`, `RecordType`, `ResponseCode` (`value`), `Answer`, `DecodeError` (`id`, `response_code`), `EncodeOptions`, `DEFAULT_UDP_PAYLOAD_SIZE`, `MIN_UDP_RESPONSE_SIZE`, `CLASS_IN` |
| resolvers (`resolver`) | trait `Resolver` (also for `Arc<R>` and `&R`), `Fallback` (`new`) | |
| static records (`records`) | `StaticRecords` (`new`, `insert`, `FromIterator<Record>`, `lookup`, `with_fallback`, `len`, `is_empty`) | |

## Behavior

### Codec

`Query::decode` accepts a query (`QR` = 0) with opcode `QUERY` and exactly one question. The
question name is normalized (ASCII-lowercase, no trailing dot) for matching; `raw` keeps the
received bytes for forwarding. A message that does not decode yields a `DecodeError`:
`response_code` is `FORMERR` for a malformed message or zero or several questions, `NOTIMP`
for another opcode, and `None` (drop silently) for input shorter than the header or a
response. `encode_error(id, code)` answers the former without a question.

`encode_response` echoes the ID, `RD` and the question as the client sent it (its case
included), sets `QR` and `RA`, and sets `AA` for local answers (`Answer::Records`,
`Answer::Code`). `Answer::Records` with an empty list is `NODATA`. When the query carried an
EDNS OPT record, the response carries one advertising `EncodeOptions::udp_payload_size`
(`DEFAULT_UDP_PAYLOAD_SIZE`, 1232, by default). `Answer::Raw` is passed through with only the
ID replaced. Records that do not encode (a name that is not a host name, a TXT string over 255
bytes) give `SERVFAIL`.

### Truncation

`max_udp_response_size` is 512 bytes without EDNS, else the client's payload size clamped to
512 and `EncodeOptions::udp_payload_size`. A response longer than the `max_size` passed to
`encode_response` (records or raw) is replaced by the truncated form built from the query:
header with `TC` = 1, the question and the OPT record, no answers, which fits any limit of at
least 512 bytes. Over TCP, pass 65535.

### Resolver

`Resolver::resolve(&query, client)` returns an `Answer`; the trait uses native async
functions in traits. A server calls it concurrently, so implementations await slow work
instead of blocking. `client` is the transport peer. `Fallback<A, B>` asks `A` and, only when
`A` answers `NXDOMAIN`, asks `B`; `NODATA` and other codes from `A` are final. Fallbacks nest
to chain several resolvers without trait objects.

### StaticRecords

An immutable table once shared, filled with `insert` or `collect()`. Names match
case-insensitively, with or without a trailing dot. For a known name of class IN: its
`CNAME` records for any query type when it has one, else its records of the query type (all
for `ANY`), else `NODATA`. Unknown names and other classes answer `NXDOMAIN`, so
`with_fallback` hands them to the next resolver. A lookup is one hash lookup and a filter
over the name's records.

## Limits and bounds

- One question per message; opcodes other than `QUERY` (notify, update) are answered with
  `NOTIMP`.
- A question whose type the codec does not know (for example TLSA, type 52) does not parse
  and is answered with `FORMERR`.
- Response codes are limited to `ResponseCode` (no extended codes).
- `RecordData` covers A, AAAA, CNAME, PTR and TXT.

## See also

- [ADR: simple-dns fork](../decisions/2026-10-24-simple-dns-fork.md)
