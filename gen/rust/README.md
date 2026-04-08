# Rust generated code

`sdk-rs` does **not** emit sources into this directory. `sdk-rs/build.rs` runs `buf` + `connectrpc_build` and writes generated Rust into Cargo **`OUT_DIR`** (under `target/…/build/exoware-sdk-rs-*/out/`), which `sdk-rs/src/proto/mod.rs` pulls in via `include!`.

This directory exists so the repo has a **`gen/rust`** path next to [`gen/README.md`](../README.md) and the TypeScript tree [`sdk-ts/src/gen/ts/`](../../sdk-ts/src/gen/ts/).
