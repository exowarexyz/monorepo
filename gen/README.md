# Generated code layout

Protobuf **schemas** live under [`proto/`](../proto/). Language bindings are generated in two places:

| Language | Location | Checked in | Produced by |
|----------|----------|------------|-------------|
| **Rust** | [`gen/rust/README.md`](./rust/README.md) — stubs live in Cargo `OUT_DIR` under `target/` | No | `sdk-rs/build.rs` + `cargo build -p exoware-sdk-rs` |
| **TypeScript** | [`sdk-ts/src/gen/ts/`](../sdk-ts/src/gen/ts/) — mirrors `proto/…` | No | `buf generate` in `sdk-ts` (`npm run generate`) |

There is **no** second copy of Rust files under `gen/rust/`; that folder only documents where codegen goes. TypeScript uses a `gen/ts/` path segment under the SDK package so `tsc` can keep `rootDir: ./src` without pulling files outside `sdk-ts/`.
