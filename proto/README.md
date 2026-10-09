# Exoware protocol compatibility and limits

This document defines the supported request formats and portable size contract
for `log.ingest.v1.Put`.
The message schema is [`log/v1/ingest.proto`](./log/v1/ingest.proto).

## Put client compatibility

The shared Put endpoint supports the Connect unary protocol with binary protobuf.
The Rust SDK and TypeScript SDK use this format. Custom or generated clients must
also select Connect unary and protobuf. Generating a client from the same schema
does not make a gRPC or gRPC-Web transport compatible with Put.

| Request format | Put support |
| --- | --- |
| Connect unary protobuf, uncompressed | Accepted |
| Connect unary protobuf, zstd meeting the restrictions below | Accepted |
| Connect unary JSON | Rejected |
| Connect unary protobuf with gzip or another unsupported content encoding | Rejected |
| gRPC or gRPC-Web, including protobuf requests | Rejected |
| Connect streaming envelopes | Rejected |

Send an HTTP `POST` to `/log.ingest.v1.Service/Put` with
`Content-Type: application/proto`. For an uncompressed body, omit
`Content-Encoding` or use `Content-Encoding: identity`. For zstd, use
`Content-Encoding: zstd`. Multiple content encodings and the streaming compression
headers `Connect-Content-Encoding` and `Grpc-Encoding` are rejected.

These restrictions apply to Put. Other services continue to support JSON and
gzip requests through the ordinary ConnectRPC dispatcher.

### Zstd restrictions

A compressed Put body must satisfy all of the following:

- Contain exactly one complete standard zstd frame, with no trailing bytes,
  concatenated frames, or skippable frames.
- Declare the decompressed content size in the zstd frame header. The decoded
  byte count must match that declaration. This is separate from HTTP
  `Content-Length` and is required even when that HTTP header is omitted.
- Use a window no larger than 128 MiB and require no compression dictionary.
- Stay within the request body and decompressed message limits described below.

The Rust SDK's zstd request compression produces this format. Custom compressors
must include the content size even if their default streaming mode omits it.

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
Compression can change the body size relative to the binary protobuf size
reported by `StoreWriteBatch::encoded_len()`.

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

## Admission retries

Temporary initial-admission exhaustion returns `RESOURCE_EXHAUSTED` with an
`ErrorInfo` whose domain is `log.ingest` and reason is
`INGEST_ADMISSION_EXHAUSTED`, plus a positive `RetryInfo.retry_delay`. This
rejection guarantees that the request was not submitted to the backend.
Requests that cannot fit the configured admission budget even when it is empty
do not receive this retry hint. Memory reservation failures after admission do
not receive it either.

The Rust and TypeScript SDKs retry Put only when that complete rejection detail
is present and valid. They retain the same atomic batch, respect the advertised
minimum delay, and apply their configured attempt and backoff limits. If the hint
exceeds the client's maximum backoff, they return the error. A configured call
deadline covers attempts and backoff together.

Generic errors, timeouts, and lost responses are not proof that a write was
rejected before submission. The SDKs do not automatically retry those Put
failures. Replaying a committed batch can create another sequence-log entry even
when the key/value data is identical. A transport failure that prevents delivery
of the admission details also remains non-retryable under this policy.

## SDK behavior

The Rust SDK exposes the limits under `exoware_sdk::limits`. Its
`StoreWriteBatch` reports the exact encoded request length through
`encoded_len()` and can split ownership into batches with
`split(max_rows, max_encoded_bytes)`. Both limits must be positive. An empty
batch produces no chunks. An entry that cannot fit alone returns an error.
Splitting preserves staged entries without copying or re-prefixing payloads.

Each resulting batch remains atomic as one `Put`, but several chunks are
several writes. Exoware data is immutable. Applications own retries beyond the
admission policy above, concurrency, and publication barriers across chunks.

The TypeScript SDK exports the same constants. Its `StoreWriteBatch` provides
`encodedLen()`, `validate(options)`, and `split(options)` for protobuf.
All TypeScript Put requests use protobuf. `ClientOptions.useBinaryFormat` controls
only non-ingest services. Pass `store.putOptions` to validation and splitting to
use the client's configured limits. Store writes validate before sending and
remain one atomic Put. Splitting is explicit.
