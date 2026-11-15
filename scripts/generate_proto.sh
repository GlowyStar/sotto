#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
uv run python -m grpc_tools.protoc -Iproto \
    --python_out=src/sotto/proto --pyi_out=src/sotto/proto proto/sotto.proto
