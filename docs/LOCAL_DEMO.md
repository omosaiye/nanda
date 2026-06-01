# NANDA Local Demo

This demo runs the v0 server against local PostgreSQL and uses the checked-in JSON examples.

## Start PostgreSQL

```sh
docker compose up -d postgres
```

The compose file exposes PostgreSQL on localhost port `5432` with:

```sh
postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable
```

## Migration Behavior

In `NANDA_MODE=local`, `cmd/nanda-server` runs the SQL files in `migrations/` at startup by default. Migrations are written to be safe for repeated local runs, so restarting the server reapplies the current schema definitions without a separate migration command.

In `NANDA_MODE=production`, startup does not run migrations unless `NANDA_AUTO_MIGRATE=true` is set. The intended production flow is to apply `migrations/*.sql` with your deployment or database migration tooling, then start the server without automatic migration enabled.

## Run the Server

```sh
NANDA_MODE=local \
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' \
NANDA_TRUST_ISSUERS_JSON='{"did:example:issuer":"<base64-ed25519-public-key>"}' \
go run ./cmd/nanda-server
```

Or use the Makefile default DSN:

```sh
make run-local
```

The server listens on `:8080` by default.

## Environment Variables

- `NANDA_MODE`: runtime mode. Supported values are `local` and `production`. Defaults to `local`.
- `NANDA_POSTGRES_DSN`: PostgreSQL DSN. Required to start the server.
- `NANDA_ADDR`: HTTP listen address. Defaults to `:8080`.
- `NANDA_FACTS_DIR`: local AgentFacts storage directory. Defaults to `./var/facts`.
- `NANDA_PRIVATE_KEY_BASE64`: base64 Ed25519 private key. Optional for local demos.
- `NANDA_PUBLIC_KEY_BASE64`: base64 Ed25519 public key matching the private key. Optional.
- `NANDA_TRUST_ISSUERS_JSON`: JSON object mapping issuer name to base64 Ed25519 public key. Optional.
- `NANDA_TRUST_ISSUERS_FILE`: path to a JSON file with the same shape as `NANDA_TRUST_ISSUERS_JSON`. Optional.
- `NANDA_API_TOKEN`: bearer token for protected API routes. Optional in local mode. Required in production mode.
- `NANDA_AUTO_MIGRATE`: in local mode, migrations run unless this is `false`. In production mode, migrations run only when this is exactly `true`.

If no signing key is configured, the server generates an ephemeral local Ed25519 key at startup. Records from a previous ephemeral run will not verify after restarting with a different key.

Set only one of `NANDA_TRUST_ISSUERS_JSON` and `NANDA_TRUST_ISSUERS_FILE`; configuring both is a startup error. The trust issuer map looks like:

```json
{
  "did:example:issuer": "<base64-ed25519-public-key>"
}
```

This is local Ed25519 issuer trust. The server does not resolve DIDs, perform full W3C VC canonicalization, or consume VC Status Lists.

Production mode requires `NANDA_POSTGRES_DSN`, `NANDA_PRIVATE_KEY_BASE64`, and `NANDA_API_TOKEN`. Ephemeral signing keys are forbidden in production mode.

When `NANDA_API_TOKEN` is configured, `POST /v1/agents/register`, `POST /v1/resolve`, and `/v1/admin/*` require:

```sh
Authorization: Bearer <token>
```

`GET /healthz` and `GET /readyz` remain public. In local mode without `NANDA_API_TOKEN`, registration, resolution, and admin inspection remain unauthenticated for demos.

## Register an Agent

```sh
curl -sS -X POST http://localhost:8080/v1/agents/register \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-register' \
  --data-binary @docs/examples/register-agent.json
```

## Resolve an Agent

```sh
curl -sS -X POST http://localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-resolve' \
  --data-binary @docs/examples/resolve-agent.json
```

Resolver responses include additive `cache` metadata with `ttlSeconds`, `expiresAt`, and `sourceSequence`. The cache TTL is capped by both the remaining L1 `AgentAddr120` TTL and the selected endpoint TTL. The L1 index rejects stale sequence overwrites, and same-sequence updates are idempotent only when the record bytes are identical.

## Resolve with Required Capability

When `requiredCapability` is present, the resolver requires a valid signed capability credential from a configured issuer. If the issuer allowlist is empty or does not include the credential issuer, the request fails closed with `403 trust_denied`.

The trusted issuer configuration must be present when the server starts, for example by setting `NANDA_TRUST_ISSUERS_JSON` or `NANDA_TRUST_ISSUERS_FILE` on the `go run ./cmd/nanda-server` command. Setting those variables only when invoking the helper script does not configure trust on an already-running server.

```sh
curl -sS -X POST http://localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-resolve-capability' \
  --data-binary @docs/examples/resolve-agent-required-capability.json
```

The helper script is intentionally limited because the repo does not yet include a credential-signing demo:

```sh
./scripts/demo-trust-local.sh
```

`scripts/demo-trust-local.sh` only sends the capability-required resolve request to the running server. It does not configure server trust.

## Admin Inspection

Set `TOKEN_HEADER` only when the server was started with `NANDA_API_TOKEN`:

```sh
TOKEN_HEADER=(-H 'Authorization: Bearer replace-me')
```

Get the current L1 record for an agent:

```sh
curl -sS http://localhost:8080/v1/admin/agents/agent.example \
  "${TOKEN_HEADER[@]}" \
  -H 'X-Request-ID: demo-admin-agent'
```

List audit events with pagination:

```sh
curl -sS 'http://localhost:8080/v1/admin/audit?limit=100&offset=0' \
  "${TOKEN_HEADER[@]}" \
  -H 'X-Request-ID: demo-admin-audit'
```

List denied resolve audit events for one agent:

```sh
curl -sS 'http://localhost:8080/v1/admin/audit/agent.example?limit=50&offset=0&eventType=resolve.denied&decision=denied' \
  "${TOKEN_HEADER[@]}" \
  -H 'X-Request-ID: demo-admin-audit-agent'
```

Set a credential as revoked:

```sh
curl -sS -X POST http://localhost:8080/v1/admin/revocation \
  "${TOKEN_HEADER[@]}" \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-admin-revoke' \
  --data '{
    "issuer": "did:example:issuer",
    "credentialId": "credential-1",
    "status": "revoked",
    "reason": "operator action"
  }'
```

Get revocation status for a credential:

```sh
curl -sS http://localhost:8080/v1/admin/revocation/did:example:issuer/credential-1 \
  "${TOKEN_HEADER[@]}" \
  -H 'X-Request-ID: demo-admin-revocation'
```

When registered AgentFacts contain a signed capability credential with the same issuer and credential ID, capability-required resolution fails closed after that credential is marked revoked. The resolver returns `403 trust_denied` for requests that include `requiredCapability`.

## Demo Script

With PostgreSQL and the server running:

```sh
./scripts/demo-local.sh
```

## Tests

Run unit tests:

```sh
go test ./...
```

Or:

```sh
make test
```

Run CI-style verification:

```sh
./scripts/verify.sh
```

Or:

```sh
make verify
```

Run integration tests against local PostgreSQL:

```sh
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test ./...
```

Or use the Makefile default DSN:

```sh
make test-integration
```

## Production-Like Local Run

Generate and set a stable base64 Ed25519 private key before running production mode. Then start with explicit auth and migration behavior:

```sh
NANDA_MODE=production \
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' \
NANDA_PRIVATE_KEY_BASE64='<base64-ed25519-private-key>' \
NANDA_API_TOKEN='replace-me' \
NANDA_AUTO_MIGRATE=true \
go run ./cmd/nanda-server
```
