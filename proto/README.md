# Exoware protocol limits

This document defines the portable size contract for `log.ingest.v1.Put`.
The message schema is [`log/v1/ingest.proto`](./log/v1/ingest.proto).

## Portable Put limits

The published baseline is:

| Dimension | Limit |
| --- | ---: |
| Entries in one `PutRequest` | 2,000,000 |
| Individual value | 32 MiB |
| Individual key | 254 bytes |

The request must contain at least one entry.

These limits are a language-independent contract. A conforming backend must
not reject a valid request for these dimensions when every published limit is
satisfied.
Server defaults use the published limits. A backend may explicitly accept
larger requests. Requests above the published baseline are nonportable and may
be accepted or rejected by a particular deployment.

RPC request bodies and decompressed messages are limited to 256 MiB. This is
the transport byte limit for all methods. Put has no additional application
byte limit. `MAX_REQUEST_MESSAGE_BYTES` exposes the message limit in both SDKs.
JSON and compression can change the body size relative to the binary protobuf
size reported by `StoreWriteBatch::encoded_len()`.

The value limit applies to each individual value. Chunking a `PutRequest` does
not divide a value across requests. Splitting cannot make a value above a
backend's configured value limit fit that limit.

## Size errors

After request decoding, a request that exceeds the entry limit returns
`INVALID_ARGUMENT`. The error includes a `BadRequest` detail with the
field `kvs` and an `ErrorInfo` detail with:

| Field | Value |
| --- | --- |
| `domain` | `log.ingest` |
| `reason` | `PUT_TOO_LARGE` |
| metadata | `entries`, `max_entries` |

A transport rejects an oversized HTTP body or decompressed message with
`RESOURCE_EXHAUSTED` before application validation. Backend byte limits use the
same generic code. Key and value limits remain application validation errors.
Decoder failures can return `INVALID_ARGUMENT` without `PUT_TOO_LARGE` details.
The status alone does not establish a global retry rule.

## SDK behavior

The Rust SDK exposes the limits under `exoware_sdk::limits`. Its
`StoreWriteBatch` reports the exact encoded request length through
`encoded_len()` and can split ownership into batches with
`split(max_rows, max_encoded_bytes)`. Both limits must be positive. An empty
batch produces no chunks. An entry that cannot fit alone returns an error.
Splitting preserves staged entries without copying or re-prefixing payloads.

Each resulting batch remains atomic as one `Put`, but several chunks are
several writes. Exoware data is immutable. Retry policy, concurrency, and
publication barriers belong to the application. The TypeScript SDK exports
the published constants and does not provide a batch-splitting helper.
