# NANDA Hardening Backlog

Known hardening tasks for NANDA v0:

1. Improve resolver HTTP error mapping.
   - Verification failures should not all become generic 500s forever.
   - Consider `409`, `422`, or `502` depending on failure type.
2. Add monotonic sequence enforcement so stale `AgentAddr120` records cannot overwrite newer records.
3. Add stronger structured audit events for registration and resolution once audit v0 proves out.
4. Add trace IDs to audit payloads once tracing exists.
5. Add isolated integration test databases to avoid shared-DSN package test interference.
6. Add stricter local startup checks for filesystem permissions and schema drift.
7. Add API examples for capability-protected resolution once issuer trust config exists.
8. Later: replace placeholder `credentialSet128` with real credential-set commitment.
9. Add OpenTelemetry traces for registration, resolution, trust checks, and audit writes.
10. Add Prometheus metrics for request counts, denial counts, audit append failures, and resolver latency.
11. Add production operator authentication beyond the simple API token guardrail.
12. Add W3C VC interoperability when v0 scope expands.
13. Add DID resolution when v0 scope expands.
14. Add stronger deployment hardening for production packaging and operations.

Completed:

- Added reusable JSON error helpers for API handlers.
- Added request IDs to local API responses and handler error logs.
- Added local Makefile targets for test, integration test, local run, Docker, formatting, and verification.
- Added explicit `NANDA_MODE` runtime behavior with production validation.
- Added simple bearer-token API auth guardrail for registration and resolution.
- Added production migration gating with `NANDA_AUTO_MIGRATE`.
- Added PostgreSQL append-only trigger protection for `audit_events`.
