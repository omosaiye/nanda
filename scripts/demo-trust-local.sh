#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NANDA_BASE_URL:-http://localhost:8080}"
RESOLVE_BODY="${NANDA_TRUST_DEMO_RESOLVE_BODY:-docs/examples/resolve-agent-required-capability.json}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat >&2 <<'MSG'
Usage: scripts/demo-trust-local.sh

The running server must have been started with NANDA_TRUST_ISSUERS_JSON or
NANDA_TRUST_ISSUERS_FILE so it can trust the capability credential issuer.

This script does not generate or sign capability credentials. It only sends a
capability-required resolve request to a running local server, and it does not
configure server trust. Register an agent whose AgentFacts contains a valid v0
Ed25519 capability credential from one of the server-configured issuers first.
MSG
  exit 0
fi

curl -sS -X POST "${BASE_URL}/v1/resolve" \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-trust-resolve' \
  --data-binary @"${RESOLVE_BODY}"
