# exoware-qmdb

Publish Commonware QMDB data to Exoware and serve queries with proofs that clients
can verify against a trusted root.

- [Rust](./rs/README.md): authenticated uploads, Store-backed readers, ConnectRPC
  services, and verifying clients for ordered, unordered, immutable, and keyless
  databases.
- [TypeScript](./ts/README.md): ConnectRPC clients and WASM proof verification,
  including a standalone verifier for application transports.

Operation proofs authenticate entries in the log. Current-state proofs also
authenticate activity at a chosen database boundary. Both packages support
Merkle Mountain Range (MMR) and Merkle Mountain Belt (MMB) trees. Applications
supply the trusted roots and matching database configuration.
