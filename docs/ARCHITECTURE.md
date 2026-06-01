# NANDA v0.1 Architecture

NANDA v0.1 is a local prototype with a compact signed L1 record, local L2 AgentFacts storage, Postgres-backed indexes, and HTTP APIs for registration, resolution, and inspection.

## Components

- `cmd/nanda-server`: loads runtime config including local trusted issuers, opens Postgres, optionally applies migrations, wires stores and services, and exposes HTTP routes.
- `internal/agentaddr`: defines the 120-byte `AgentAddr120` payload and signed record format, agent ID normalization, hashes, encode/decode, and Ed25519 verification.
- `internal/agentfacts`: defines and validates `AgentFacts`, endpoints, and v0 capability credential data.
- `internal/facts`: stores AgentFacts on the filesystem and stores facts pointer mappings in Postgres.
- `internal/index`: stores signed L1 records in Postgres, keyed by agent ID hash, with sequence freshness checks.
- `internal/registration`: validates registration requests, stores AgentFacts, records pointer mappings, signs L1 records, updates the index, and appends audit events.
- `internal/resolver`: loads and verifies L1 records, resolves pointer mappings, validates AgentFacts, checks credential-set binding, applies trust verification when requested, selects an endpoint, returns cache metadata, and appends audit events.
- `internal/trust`: verifies local Ed25519 capability credentials against an issuer allowlist and optional revocation checker. It is not full W3C VC interoperability.
- `internal/revocation`: stores and reads v0 credential revocation status and exposes `IsRevoked` for trust checks.
- `internal/audit`: appends canonical hash-chained audit events, queries them, and verifies the chain.
- `internal/admin`: reads agent index metadata, audit events, and revocation status for operator inspection.
- `internal/api`: maps services to HTTP handlers, JSON errors, bearer-token guardrail auth, and request IDs.
- `internal/observability`: keeps local in-process counters and latency summaries, renders `/metrics`, wraps audit appends for event metrics, and records structured HTTP request logs.

## Data Flow

Registration accepts an agent ID, TTL, sequence, flags, and embedded AgentFacts JSON. It stores the AgentFacts document, stores the pointer mapping, signs a new `AgentAddr120`, writes the L1 index record, and appends `agent.registered`.

Resolution accepts an agent ID and optional required capability. It loads the L1 record, verifies the signature, checks the requested agent ID hash, rejects expired L1 records, resolves the facts pointer mapping, loads AgentFacts, validates L1-to-L2 hashes, validates schema and endpoint data, optionally verifies capability trust and revocation, selects an endpoint, and appends either allowed or denied audit events.

## Trust Boundaries

- HTTP input is untrusted and decoded with strict JSON field handling for registration and resolution.
- Postgres is trusted local storage for the L1 index, facts pointer mapping, audit events, and revocation records.
- Filesystem AgentFacts storage is local storage and is verified through L1 pointer and credential-set hashes during resolution.
- The server signing key is the root of local L1 authenticity. Local mode may generate an ephemeral key; production mode requires `NANDA_PRIVATE_KEY_BASE64`.
- The v0 trust verifier only trusts local configured issuer public keys from `NANDA_TRUST_ISSUERS_JSON` or `NANDA_TRUST_ISSUERS_FILE`. Capability-required resolution fails closed when no configured issuer matches the credential issuer.
- Issuer trust configuration is local Ed25519 key pinning. It is not DID resolution, full W3C VC trust, or VC Status List processing.
- Admin routes are protected only by the same optional bearer-token guardrail as registration and resolution.

## Observability v0

The server includes lightweight local observability only. HTTP middleware records structured logs for every route, including health and readiness probes, with `request_id`, method, route template, status, and duration in milliseconds. Logs do not include request bodies or authorization headers.

`GET /metrics` is public like `/healthz` and `/readyz`. It renders deterministic text metrics from an in-process registry and does not require Prometheus or any external collector. Metric labels use stable route templates such as `/v1/admin/agents/{agentId}` and `/v1/admin/revocation/{issuer}/{credentialId}` so agent IDs, issuers, credential IDs, and other path values are not exposed as labels.

Domain metrics cover HTTP requests, registration outcomes, resolve outcomes, trust denials, admin requests, revocation updates, and successful audit appends by event type and decision. This is not OpenTelemetry, distributed tracing, log aggregation, alerting, or a production observability stack.

## Key Invariants

- `AgentAddr120` remains exactly 120 bytes.
- `AgentAddr120` binds agent ID hash, facts pointer hash, credential set hash, TTL, flags, and sequence.
- Resolver rejects bad signatures, agent hash mismatch, facts pointer mismatch, missing pointer records, credential set mismatch, expired L1 records, invalid AgentFacts, endpoint absence, and trust denial.
- Index writes reject stale sequence overwrites, and same-sequence writes are idempotent only when the signed bytes are identical.
- Audit events are hash chained.
- The Postgres `audit_events` table is append-only guarded against update and delete by trigger.

## Known Limitations

- No DID resolution.
- No full W3C VC canonicalization.
- No VC Status Lists.
- No ZK proofs.
- No IPFS, Tor, OHTTP, Trillian, Envoy, Redis, NATS, Kubernetes, or UI.
- No production RBAC or operator authorization model beyond a bearer token.
- No issuer lifecycle management, key rotation workflow, or DID-backed trust chain.
- Filesystem AgentFacts storage is intended for the local prototype.
