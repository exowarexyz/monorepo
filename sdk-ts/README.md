# exoware-sdk-ts

[![npm](https://img.shields.io/npm/v/exoware-sdk-ts.svg)](https://www.npmjs.com/package/exoware-sdk-ts)

Interact with the Exoware API in TypeScript.

## Status

`exoware-sdk-ts` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Generated TypeScript (`gen/ts`)

Protobuf-ES output lives under **`src/gen/ts/`** (mirrors the repo [`proto/`](../proto/) tree, e.g. `proto/store/v1/query.proto` → `src/gen/ts/store/v1/query_pb.ts`). To regenerate after proto changes, run `../gen.sh` from the repo root.

Integration tests spawn the Rust simulator via `jest.globalSetup.ts` (`cargo build --package exoware-simulator`).
