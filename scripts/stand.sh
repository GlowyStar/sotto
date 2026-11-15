#!/usr/bin/env bash
set -euo pipefail

project="${1:?usage: scripts/stand.sh <compose project name>}"
cd "$(dirname "$0")/.."

export RELAY_PORT="${RELAY_PORT:-8765}"
compose=(docker compose -p "$project")

finish() {
    status=$?
    [ "$status" -eq 0 ] || "${compose[@]}" logs --no-color || true
    "${compose[@]}" down -v
    exit "$status"
}
trap finish EXIT

"${compose[@]}" up --build -d --wait --wait-timeout 60
RELAY_URL="ws://127.0.0.1:${RELAY_PORT}" uv run pytest -m stand

uid="$("${compose[@]}" exec -T relay id -u)"
[ "${uid:-0}" != 0 ] || { echo "the relay runs as root" >&2; exit 1; }

"${compose[@]}" stop
container="$("${compose[@]}" ps -aq relay)"
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$container")"
[ "$exit_code" = 0 ] || { echo "the relay exited with $exit_code after stop" >&2; exit 1; }
