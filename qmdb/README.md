# exoware-qmdb

Publish Commonware QMDB data to Exoware and serve queries with proofs that clients
can verify against a trusted root.

- [Rust](./rs/README.md): authenticated uploads, Store-backed readers, ConnectRPC
  services, and verifying clients for ordered, unordered, immutable, and keyless
  databases.
- [TypeScript](./ts/README.md): ConnectRPC clients and WASM proof verification,
  including a standalone verifier for application transports.

Both packages support Merkle Mountain Range (MMR) and Merkle Mountain Belt (MMB)
trees. Operation proofs authenticate entries in the log, while current-state
proofs also authenticate which operations remain active at a chosen batch
boundary. To verify either kind, applications supply trusted roots and matching
database configuration.
