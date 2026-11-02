# simplex

Store and retrieve Commonware Simplex blocks and certificates through Exoware
Store. Headers and full blocks are indexed by digest, certificates by epoch and
view, and finalizations also by block height.

- [Rust](./rs/README.md): typed reads and writes for Commonware blocks and
  certificates, with a Store-backed resolver for Commonware Marshal.
- [TypeScript](./ts/README.md): byte-oriented uploads, reads and subscriptions,
  with a browser WASM verifier for Commonware certificates.

To authenticate retrieved artifacts, applications supply trusted Simplex
configuration and define how a certified payload authenticates their header and
body formats.
