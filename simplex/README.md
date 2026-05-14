# simplex

Store-backed upload helpers for Commonware Simplex blocks and certificates.

- [rs](./rs/README.md): typed Rust client for Commonware `Block`, notarization, and finalization values.
- [ts](./ts/README.md): browser/client-side helpers for raw and verified Simplex artifact bytes.

The clients use the Commonware Library revision pinned in the workspace
`Cargo.toml` and share the same Store key layout across Rust, TypeScript, and
the sandbox.
