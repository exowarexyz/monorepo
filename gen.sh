#!/usr/bin/env bash
# Regenerate committed proto bindings for all SDKs.
# Prerequisites: buf CLI, connectrpc-build (Cargo build dep).
# Set BUF_TOKEN to authenticate remote Buf plugins and avoid low anonymous BSR limits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$ROOT/sdk/rs/src/gen/"*.rs
rm -rf "$ROOT/qmdb/rs/src/gen/"*.rs
rm -rf "$ROOT/sql/rs/src/gen/"*.rs
rm -rf "$ROOT/sdk/ts/src/gen/ts/"
rm -rf "$ROOT/qmdb/ts/src/generated/proto/"
rm -rf "$ROOT/sql/ts/src/generated/proto/"

echo "==> Rust (sdk/rs)"
PROTO_GEN=1 cargo build -p exoware-sdk 2>&1

echo "==> Rust (qmdb/rs)"
PROTO_GEN=1 cargo build -p exoware-qmdb 2>&1

echo "==> Rust (sql/rs)"
PROTO_GEN=1 cargo build -p exoware-sql 2>&1

echo "==> TypeScript (sdk/ts)"
(cd "$ROOT/sdk/ts" && buf generate --template buf.gen.yaml)

echo "==> TypeScript (qmdb/ts)"
(cd "$ROOT/qmdb/ts" && buf generate --template buf.gen.yaml)

echo "==> TypeScript (sql/ts)"
(cd "$ROOT/sql/ts" && buf generate --template buf.gen.yaml)

echo "Done."
