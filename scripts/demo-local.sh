#!/usr/bin/env sh
set -eu

BASE_URL="${NANDA_BASE_URL:-http://localhost:8080}"
API_TOKEN="${NANDA_API_TOKEN:-}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(dirname "$SCRIPT_DIR")

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

cd "$REPO_DIR"

section() {
  printf '\n== %s ==\n' "$1"
}

pretty_print() {
  if command -v jq >/dev/null 2>&1; then
    jq .
  else
    cat
    printf '\n'
  fi
}

curl_get() {
  url="$1"
  request_id="$2"
  if [ -n "$API_TOKEN" ]; then
    response=$(curl -fsS "$url" \
      -H "Authorization: Bearer $API_TOKEN" \
      -H "X-Request-ID: $request_id")
  else
    response=$(curl -fsS "$url" \
      -H "X-Request-ID: $request_id")
  fi
  printf '%s\n' "$response" | pretty_print
}

curl_post_json() {
  url="$1"
  request_id="$2"
  body_file="$3"
  if [ -n "$API_TOKEN" ]; then
    response=$(curl -fsS -X POST "$url" \
      -H "Authorization: Bearer $API_TOKEN" \
      -H "Content-Type: application/json" \
      -H "X-Request-ID: $request_id" \
      --data-binary @"$body_file")
  else
    response=$(curl -fsS -X POST "$url" \
      -H "Content-Type: application/json" \
      -H "X-Request-ID: $request_id" \
      --data-binary @"$body_file")
  fi
  printf '%s\n' "$response" | pretty_print
}

section "Health"
curl_get "$BASE_URL/healthz" "demo-health"

section "Readiness"
curl_get "$BASE_URL/readyz" "demo-ready"

section "Register agent.example"
curl_post_json "$BASE_URL/v1/agents/register" "demo-register" "docs/examples/register-agent.json"

section "Resolve agent.example"
curl_post_json "$BASE_URL/v1/resolve" "demo-resolve" "docs/examples/resolve-agent.json"

section "Admin agent inspection"
curl_get "$BASE_URL/v1/admin/agents/agent.example" "demo-admin-agent"

section "Admin audit list"
curl_get "$BASE_URL/v1/admin/audit?limit=10&offset=0" "demo-admin-audit"

section "Admin revocation status"
curl_get "$BASE_URL/v1/admin/revocation/issuer.example/credential-1" "demo-admin-revocation"
