#!/usr/bin/env bash
# Regenerate committed proto bindings for all SDKs.
# Prerequisites: buf CLI, connectrpc-build (Cargo build dep).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "==> Rust (sdk-rs)"
PROTO_GEN=1 cargo build -p exoware-sdk-rs 2>&1

echo "==> TypeScript (sdk-ts)"
(cd "$ROOT/sdk-ts" && buf generate --template buf.gen.yaml)

echo "Done."
