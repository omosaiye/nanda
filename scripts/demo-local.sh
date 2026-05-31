#!/usr/bin/env sh
set -eu

BASE_URL="${NANDA_BASE_URL:-http://localhost:8080}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

cd "$REPO_DIR"

echo "Registering agent.example"
curl -fsS -X POST "$BASE_URL/v1/agents/register" \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: demo-register" \
  --data-binary @docs/examples/register-agent.json

printf '\nResolving agent.example\n'
curl -fsS -X POST "$BASE_URL/v1/resolve" \
  -H "Content-Type: application/json" \
  -H "X-Request-ID: demo-resolve" \
  --data-binary @docs/examples/resolve-agent.json
printf '\n'
