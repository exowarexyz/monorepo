# Exoware protocol limits

This document defines the portable size contract for `log.ingest.v1.Put`.
The message schema is [`log/v1/ingest.proto`](./log/v1/ingest.proto).
Put accepts a stream of `PutRequest` messages and returns one `PutResponse`.
All messages in the call belong to one atomic write. Closing the request stream
finishes the upload. The successful response acknowledges publication.

## Portable Put limits

The published baseline is:

| Dimension | Limit |
| --- | ---: |
| Entries across one Put call | 2,000,000 |
| Individual value | 32 MiB |
| Individual key | 254 bytes |

The stream and each message must contain at least one entry.

These limits are a language-independent contract. A conforming backend must
not reject a valid request for these dimensions when every published limit is
satisfied.
Server defaults use the published limits. A backend may explicitly accept
larger requests. Requests above the published baseline are nonportable and may
be accepted or rejected by a particular deployment.

Put limits each encoded and decompressed message to 64 MiB. Aggregate protobuf
bytes across the messages are limited to 256 MiB. Its wire bound adds five bytes
per permitted entry for streaming envelope framing. JSON and compression can
change the wire size. Other RPC request bodies and messages retain their 256 MiB
limit. Both SDKs expose `MAX_PUT_CHUNK_BYTES` and `MAX_REQUEST_MESSAGE_BYTES`.

The value limit applies to each individual value. Streaming chunks do not divide
a value across messages. Splitting cannot make a value above a
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
`StoreWriteBatch` reports the aggregate protobuf payload length through
`encoded_len()` and can split ownership into batches with
`split(max_rows, max_encoded_bytes)`. Both limits must be positive. An empty
batch produces no chunks. An entry that cannot fit alone returns an error.
Splitting preserves staged entries without copying or re-prefixing payloads.

The SDKs automatically send messages near the 1 MiB target. A larger entry gets
its own message. These transport chunks remain one atomic Put. Explicit batch
splitting produces separate writes. Exoware data is immutable. Retry policy, concurrency, and
publication barriers belong to the application.

The TypeScript SDK exports the same constants. Its `StoreWriteBatch` provides
`encodedLen(encoding)`, `validate(options)`, and `split(options)` for JSON and
binary protobuf. Pass `store.putOptions` to validation and splitting to use the
client's encoding and configured limits. Store writes validate before sending
and remain one atomic Put. Splitting is explicit.
TypeScript ingestion uses the Node transport. Browser ingestion is unsupported.
Automatic Put retries are disabled because a failed call may already have
committed and its consumed stream cannot safely be replayed.
