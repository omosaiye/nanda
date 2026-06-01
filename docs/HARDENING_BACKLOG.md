# NANDA Hardening Backlog

Known hardening tasks for NANDA v0:

1. Improve resolver HTTP error mapping.
   - Verification failures should not all become generic 500s forever.
   - Consider `409`, `422`, or `502` depending on failure type.
2. Add stronger structured audit events for registration and resolution once audit v0 proves out.
3. Add trace IDs to audit payloads once tracing exists.
4. Add isolated integration test databases to avoid shared-DSN package test interference.
5. Add stricter local startup checks for filesystem permissions and schema drift.
6. Later: replace placeholder `credentialSet128` with real credential-set commitment.
7. Add OpenTelemetry traces for registration, resolution, trust checks, and audit writes.
8. Add Prometheus metrics for request counts, denial counts, audit append failures, and resolver latency.
9. Add stronger authentication and RBAC beyond the simple API token guardrail.
10. Add W3C VC interoperability and canonicalization when v0 scope expands.
11. Add DID resolution when v0 scope expands.
12. Add VC Status Lists when v0 scope expands.
13. Add issuer lifecycle management and key rotation.
14. Add private resolution path support when v0 scope expands.
15. Add stronger deployment hardening for production packaging and operations.
16. Add richer audit search and export for operator workflows.
17. Add an admin revocation mutation endpoint with audit events.
18. Add branch protection requiring CI before merge.
19. Add CodeQL or equivalent security scanning.
20. Add dependency scanning policy and alert triage process.
21. Add stronger integration test isolation if shared database state becomes flaky in CI.

Completed:

- Added reusable JSON error helpers for API handlers.
- Added request IDs to local API responses and handler error logs.
- Added local Makefile targets for test, integration test, local run, Docker, formatting, and verification.
- Added explicit `NANDA_MODE` runtime behavior with production validation.
- Added simple bearer-token API auth guardrail for registration and resolution.
- Added production migration gating with `NANDA_AUTO_MIGRATE`.
- Added PostgreSQL append-only trigger protection for `audit_events`.
- Added admin inspection API for agents, audit events, and revocation status.
- Added admin audit pagination and filtering by event type and decision.
- Added monotonic sequence enforcement so stale `AgentAddr120` records cannot overwrite newer records.
- Added resolver cache metadata based on L1 freshness and selected endpoint TTL.
- Added expired L1 record rejection during resolution.
- Added GitHub Actions CI for formatting, unit tests, and PostgreSQL-backed integration tests.
- Added release checklist documentation for local prototype releases.
- Added local issuer trust configuration with capability-protected resolve examples.
