# exoware-sdk-ts

[![npm](https://img.shields.io/npm/v/exoware-sdk-ts.svg)](https://www.npmjs.com/package/exoware-sdk-ts)

TypeScript SDK for the Exoware **store** API, aligned with [`exoware-sdk-rs`](../sdk-rs/README.md) and [`exoware-simulator`](../simulator/README.md).

## Status

`exoware-sdk-ts` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Generated TypeScript (`gen/ts`)

Protobuf-ES output goes under **`src/gen/ts/`** (mirrors the repo [`proto/`](../proto/) tree, e.g. `proto/store/v1/query.proto` → `src/gen/ts/store/v1/query_pb.ts`). That tree is **gitignored** (large embedded descriptors). Run generate before build or test:

```bash
cd sdk-ts && npm install && npm run generate   # or: npm run build (prebuild runs generate)
```

See the monorepo [`gen/README.md`](../gen/README.md) for how this relates to Rust codegen.

`buf.gen.yaml` is tracked; `src/gen/` is not.

Integration tests spawn the Rust simulator via `jest.globalSetup.ts` (`cargo build --package exoware-simulator`).
