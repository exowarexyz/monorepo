#!/usr/bin/env bash
# Regenerate committed proto bindings for all SDKs.
# Prerequisites: buf CLI, connectrpc-build (Cargo build dep).
# Set BUF_TOKEN to authenticate remote Buf plugins and avoid low anonymous BSR limits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$ROOT/sdk-rs/src/gen/"*.rs
rm -rf "$ROOT/qmdb/src/gen/"*.rs
rm -rf "$ROOT/sql/src/gen/"*.rs
rm -rf "$ROOT/sdk-ts/src/gen/ts/"

echo "==> Rust (sdk-rs)"
PROTO_GEN=1 cargo build -p exoware-sdk 2>&1

echo "==> Rust (qmdb)"
PROTO_GEN=1 cargo build -p exoware-qmdb 2>&1

echo "==> Rust (sql)"
PROTO_GEN=1 cargo build -p exoware-sql 2>&1

echo "==> TypeScript (sdk-ts)"
(cd "$ROOT/sdk-ts" && buf generate --template buf.gen.yaml)

echo "Done."
