# NANDA Hardening Backlog

Known hardening tasks for NANDA v0:

1. Improve resolver HTTP error mapping.
   - Verification failures should not all become generic 500s forever.
   - Consider `409`, `422`, or `502` depending on failure type.
2. Add production-grade config profiles separate from local/demo config.
3. Add monotonic sequence enforcement so stale `AgentAddr120` records cannot overwrite newer records.
4. Add stronger structured audit events for registration and resolution once audit v0 proves out.
5. Add trace IDs to audit payloads once tracing exists.
6. Add isolated integration test databases to avoid shared-DSN package test interference.
7. Add stricter local startup checks for filesystem permissions and schema drift.
8. Add API examples for capability-protected resolution once issuer trust config exists.
9. Later: replace placeholder `credentialSet128` with real credential-set commitment.
10. Add OpenTelemetry traces for registration, resolution, trust checks, and audit writes.
11. Add Prometheus metrics for request counts, denial counts, audit append failures, and resolver latency.
12. Add stronger append-only protections for PostgreSQL audit storage.
13. Add production operator authentication and API authentication.

Completed:

- Added reusable JSON error helpers for API handlers.
- Added request IDs to local API responses and handler error logs.
- Added local Makefile targets for test, integration test, local run, Docker, formatting, and verification.
