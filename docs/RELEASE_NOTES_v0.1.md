# NANDA v0.1 Release Notes

v0.1 freezes the local prototype around protocol primitives, local persistence, HTTP registration and resolution, auditability, and operator inspection.

## Completed Summary

- Implemented fixed-size `AgentAddr120` L1 records with signing and verification.
- Added AgentFacts validation and local filesystem storage.
- Added Postgres-backed L1 index, facts pointer mapping, audit store, and revocation store.
- Added registration and resolver services plus HTTP APIs.
- Added v0 trust verifier and revocation checker interfaces.
- Added hash-chained audit events and append-only Postgres protection.
- Added admin inspection APIs for agents, audit, and revocation status.
- Added local Docker Postgres, Makefile targets, demo script, and v0.1 documentation.

## What Works

- Start local Postgres with Docker Compose.
- Run formatting and tests through `make verify`.
- Start the local server with `make run-local`.
- Register `docs/examples/register-agent.json`.
- Resolve `docs/examples/resolve-agent.json`.
- Inspect L1 metadata, audit events, and revocation status through admin GET endpoints.

## How To Demo

Terminal 1:

```sh
docker compose up -d postgres
make verify
make run-local
```

Terminal 2:

```sh
scripts/demo-local.sh
```

## Known Limitations

- Local prototype only.
- No DID resolution.
- No full W3C VC canonicalization.
- No VC Status Lists.
- No ZK proofs.
- No private resolution path through IPFS, Tor, or OHTTP.
- No Kubernetes, Redis, NATS, Envoy, Trillian, or UI.
- No production authorization model beyond the bearer-token guardrail.
- No HTTP revocation mutation endpoint.
- No production issuer trust configuration wired into the server.

## Recommended Next Milestones

- Add explicit issuer trust configuration for local capability demos.
- Add an admin revocation mutation endpoint with audit events.
- Add OpenTelemetry traces and Prometheus metrics.
- Add stronger admin auth/RBAC.
- Add isolated integration test databases for parallel package tests.
- Add deployment hardening once the prototype scope expands.
