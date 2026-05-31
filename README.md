# NANDA

NANDA is a local prototype of a DNS-like registry and resolver for AI agents. It gives an agent a compact L1 address record, stores richer L2 metadata separately, and resolves the current endpoint with verification checks before returning it. The L1 record is `AgentAddr120`, a signed 120-byte anchor that binds the agent ID hash, AgentFacts pointer hash, credential-set hash, TTL, flags, and sequence. The L2 `AgentFacts` document is stored on the local filesystem, while Postgres stores the L1 index, facts pointer mapping, audit events, and revocation records. The registration API writes AgentFacts, creates and signs the L1 record, indexes it, and emits an audit event. The resolver API verifies the signed L1 record, checks the L1-to-L2 binding, validates AgentFacts, applies trust and revocation checks when a capability is required, and emits an audit event. v0.1 is intentionally local-first and does not include distributed identity, private resolution paths, production authorization, or deployment automation.

## v0.1 Scope

The v0.1 local prototype supports:

- `AgentAddr120` L1 index records in Postgres.
- Local filesystem `AgentFacts` storage.
- Postgres facts pointer mapping from L1 pointer hash to stored AgentFacts pointer.
- Registration API at `POST /v1/agents/register`.
- Resolver API at `POST /v1/resolve`.
- Trust verifier v0 for local Ed25519 capability credentials.
- Revocation v0 through the revocation store and verifier hook.
- Hash-chained audit events with append-only Postgres table protection.
- Admin inspection API for agents, audit events, and revocation status.

## Prerequisites

- Go
- Docker
- Docker Compose for local Postgres

The local Postgres DSN used by the Makefile is:

```sh
postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable
```

## Quickstart

```sh
docker compose up -d postgres
make verify
make run-local
```

In another terminal:

```sh
scripts/demo-local.sh
```

The demo script checks health and readiness, registers `docs/examples/register-agent.json`, resolves `docs/examples/resolve-agent.json`, calls admin inspection endpoints, and exits non-zero on failure.

## Manual Curl Examples

Health:

```sh
curl -sS http://localhost:8080/healthz
```

Readiness:

```sh
curl -sS http://localhost:8080/readyz
```

Register:

```sh
curl -sS -X POST http://localhost:8080/v1/agents/register \
  -H 'Content-Type: application/json' \
  --data-binary @docs/examples/register-agent.json
```

Resolve:

```sh
curl -sS -X POST http://localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  --data-binary @docs/examples/resolve-agent.json
```

Admin get agent:

```sh
curl -sS http://localhost:8080/v1/admin/agents/agent.example
```

Admin list audit:

```sh
curl -sS 'http://localhost:8080/v1/admin/audit?limit=10&offset=0'
```

Admin get revocation status:

```sh
curl -sS http://localhost:8080/v1/admin/revocation/issuer.example/credential-1
```

If `NANDA_API_TOKEN` is set, add `-H 'Authorization: Bearer <token>'` to registration, resolution, and admin requests. Health and readiness are public.

## Production-Like Mode

`NANDA_MODE=production` enables stricter startup validation:

- `NANDA_API_TOKEN` is required.
- `NANDA_PRIVATE_KEY_BASE64` is required and ephemeral signing keys are forbidden.
- `NANDA_POSTGRES_DSN` is required.
- Automatic migrations are disabled unless `NANDA_AUTO_MIGRATE=true`.

This mode is a guardrail for local production-like testing, not a complete production deployment model.

## Revocation Status

Revocation support currently exists at the store and trust-verifier level. The admin API can inspect revocation status with `GET /v1/admin/revocation/{issuer}/{credentialId}` when records exist, and returns active/not found when no record exists. There is no HTTP endpoint in v0.1 to mutate revocation status; adding an admin revocation mutation endpoint is a future hardening task.

## Out of Scope

- DID resolution.
- Full W3C VC canonicalization.
- VC Status Lists.
- ZK proofs.
- IPFS, Tor, or OHTTP privacy paths.
- Kubernetes, Redis, NATS, or Envoy.
- UI.
- Production authorization beyond the bearer-token guardrail.

More detail is available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/API.md](docs/API.md), [docs/TESTING.md](docs/TESTING.md), and [docs/RELEASE_NOTES_v0.1.md](docs/RELEASE_NOTES_v0.1.md).
