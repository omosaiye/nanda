# NANDA

[![CI](https://github.com/solai/nanda/actions/workflows/ci.yml/badge.svg)](https://github.com/solai/nanda/actions/workflows/ci.yml)

NANDA is a local prototype of a DNS-like registry and resolver for AI agents. It gives an agent a compact L1 address record, stores richer L2 metadata separately, and resolves the current endpoint with verification checks before returning it. The L1 record is `AgentAddr120`, a signed 120-byte anchor that binds the agent ID hash, AgentFacts pointer hash, credential-set hash, TTL, flags, and sequence. The L2 `AgentFacts` document is stored on the local filesystem, while Postgres stores the L1 index, facts pointer mapping, audit events, and revocation records. The registration API writes AgentFacts, creates and signs the L1 record, indexes it, and emits an audit event. The resolver API verifies the signed L1 record, checks the L1-to-L2 binding, validates AgentFacts, applies trust and revocation checks when a capability is required, and emits an audit event. v0.2 is intentionally local-first and does not include distributed identity, private resolution paths, production authorization, or deployment automation.

## v0.2 Status

v0.2 is a local release checkpoint after CI/release hygiene, local issuer trust configuration, admin revocation mutation, lightweight local observability practices, and audit/test hardening. It does not change the `AgentAddr120` layout or add distributed identity, VC Status Lists, full W3C VC canonicalization, or an external observability stack.

## v0.1 Scope

The v0.1 local prototype supports:

- `AgentAddr120` L1 index records in Postgres.
- Local filesystem `AgentFacts` storage.
- Postgres facts pointer mapping from L1 pointer hash to stored AgentFacts pointer.
- Registration API at `POST /v1/agents/register`.
- Resolver API at `POST /v1/resolve`.
- Trust verifier v0 for local Ed25519 capability credentials.
- Local trusted issuer configuration through `NANDA_TRUST_ISSUERS_JSON` or `NANDA_TRUST_ISSUERS_FILE`.
- Revocation v0 through the revocation store, verifier hook, and admin mutation endpoint.
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

The demo script checks health and readiness, registers and resolves the `agent.example` and `agent.beta` examples, calls admin inspection endpoints, prints `/metrics`, and exits non-zero on failure.

## Technical Challenge Notes

The Level 1 flow is: index lookup -> signed `AgentAddr120` -> `AgentFacts` pointer -> `AgentFacts` metadata -> verified endpoint.

The local demo registers and resolves two NANDA-native agents: `agent.example` and `agent.beta`. Tamper detection is handled through the Ed25519-signed `AgentAddr120`, `AgentFacts` pointer hash binding, `AgentFacts` schema validation, credential-set hash, and trust/revocation checks when a required capability is requested.

AI assistance was used iteratively for scaffolding, test review, and hardening; changes were reviewed, tested, and committed milestone by milestone. This repository remains a local prototype and does not claim production readiness.

## Development Workflow

- Branch from `main`.
- Run `make verify` before opening a pull request.
- Open a pull request to `main`.
- CI must pass before merge.

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

Resolve with a required capability:

```sh
curl -sS -X POST http://localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  --data-binary @docs/examples/resolve-agent-required-capability.json
```

Admin get agent:

```sh
curl -sS http://localhost:8080/v1/admin/agents/agent.example
```

Admin list audit:

```sh
curl -sS 'http://localhost:8080/v1/admin/audit?limit=10&offset=0'
```

Admin set revocation status:

```sh
curl -sS -X POST http://localhost:8080/v1/admin/revocation \
  -H 'Content-Type: application/json' \
  --data '{"issuer":"did:example:issuer","credentialId":"credential-1","status":"revoked","reason":"operator action"}'
```

Admin get revocation status:

```sh
curl -sS http://localhost:8080/v1/admin/revocation/did:example:issuer/credential-1
```

If `NANDA_API_TOKEN` is set, add `-H 'Authorization: Bearer <token>'` to registration, resolution, and admin requests. Health and readiness are public.

## Production-Like Mode

`NANDA_MODE=production` enables stricter startup validation:

- `NANDA_API_TOKEN` is required.
- `NANDA_PRIVATE_KEY_BASE64` is required and ephemeral signing keys are forbidden.
- `NANDA_POSTGRES_DSN` is required.
- Automatic migrations are disabled unless `NANDA_AUTO_MIGRATE=true`.

This mode is a guardrail for local production-like testing, not a complete production deployment model.

## Local Issuer Trust

Capability-required resolution verifies v0 Ed25519 capability credentials against a local issuer allowlist. Configure exactly one of:

```sh
export NANDA_TRUST_ISSUERS_JSON='{"did:example:issuer":"<base64-ed25519-public-key>"}'
export NANDA_TRUST_ISSUERS_FILE='docs/examples/trust-issuers.example.json'
```

If both variables are set, startup config validation fails. If neither contains the credential issuer, resolution requests with `requiredCapability` fail closed with `403 trust_denied`. Resolution without `requiredCapability` remains unverified-v0 and does not require issuer trust.

This is local Ed25519 issuer trust only. It does not implement DID resolution, full W3C VC canonicalization, or VC Status Lists.

## Revocation Status

Revocation support exists at the store and trust-verifier level. The admin API can mutate local v0 revocation status with `POST /v1/admin/revocation` and inspect status with `GET /v1/admin/revocation/{issuer}/{credentialId}`. Capability-required resolution fails closed when a matching credential is revoked.

## Out of Scope

- DID resolution.
- Full W3C VC canonicalization.
- VC Status Lists.
- ZK proofs.
- IPFS, Tor, or OHTTP privacy paths.
- Kubernetes, Redis, NATS, or Envoy.
- UI.
- Production authorization beyond the bearer-token guardrail.

More detail is available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/API.md](docs/API.md), [docs/TESTING.md](docs/TESTING.md), [docs/RELEASE_NOTES_v0.1.md](docs/RELEASE_NOTES_v0.1.md), and [docs/RELEASE_NOTES_v0.2.md](docs/RELEASE_NOTES_v0.2.md).
