# NANDA v0.2 Release Notes

v0.2 is a local-prototype release checkpoint after Milestones 15 through 18. It keeps the v0.1 protocol and server behavior intact while documenting the CI, trust, revocation, observability, and audit/test hardening work added since `v0.1-local-prototype`.

Release tag: `v0.2-local-prototype`

## What Changed Since v0.1

- Added GitHub Actions CI for formatting, unit tests, and PostgreSQL-backed integration tests.
- Added local release hygiene documentation and repeatable verification commands.
- Added local issuer trust configuration through `NANDA_TRUST_ISSUERS_JSON` and `NANDA_TRUST_ISSUERS_FILE`.
- Added capability-required resolve examples for locally allowlisted Ed25519 issuers.
- Added an admin revocation mutation endpoint at `POST /v1/admin/revocation`.
- Added revocation update audit events with event type `credential.revocation.updated`.
- Kept lightweight local observability centered on health/readiness endpoints, request IDs, structured server logs, admin audit inspection, and release checklist validation for local metrics when present.
- Stabilized audit hash-chain verification around canonical event JSON.
- Hardened uncached and PostgreSQL-backed test runs by documenting `-count=1` and serial integration execution.

## Upgrade Notes From v0.1

- No AgentAddr120 layout migration is required. `AgentAddr120` remains exactly 120 bytes.
- Existing local AgentFacts documents and L1 records remain compatible with the v0.1 shape.
- Capability-required resolution now depends on local issuer trust configuration. Set exactly one of `NANDA_TRUST_ISSUERS_JSON` or `NANDA_TRUST_ISSUERS_FILE` when testing trusted capability credentials.
- If both trust issuer environment variables are set, startup fails closed with a configuration error.
- Revocation state is stored in the local PostgreSQL `credential_revocations` table. Apply migrations before using the admin revocation mutation endpoint against an existing database.
- Capability-required resolution fails closed when a matching credential is marked revoked.
- Release validation should use uncached tests for the checkpoint commands below.

## Known Limitations

- No DID resolution.
- No VC Status Lists.
- No full W3C VC canonicalization.
- No external observability stack.
- No Redis, NATS, Envoy, OHTTP, IPFS, Tor, Trillian, or Kubernetes.
- No production authorization model beyond the bearer-token guardrail.
- No real credential signing demo is included yet.

## Release Validation Commands

These are the commands used for v0.2 release validation:

```sh
go fmt ./...
go test -count=1 ./...
./scripts/verify.sh
```

When local PostgreSQL is available:

```sh
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test -p 1 -count=1 -v ./...
```

The release checklist also includes a clean-clone smoke test, `./scripts/demo-local.sh`, and a local `/metrics` curl check after the demo.
