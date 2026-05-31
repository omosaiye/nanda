# NANDA Hardening Backlog

Known hardening tasks for NANDA v0:

1. Improve resolver HTTP error mapping.
   - Verification failures should not all become generic 500s forever.
   - Consider `409`, `422`, or `502` depending on failure type.
2. Add reusable JSON response/error helpers for API handlers.
3. Add production-grade config profiles separate from local/demo config.
4. Add monotonic sequence enforcement so stale `AgentAddr120` records cannot overwrite newer records.
5. Add stronger structured audit events for registration and resolution once audit v0 proves out.
6. Add request IDs / trace IDs to API logs and audit payloads.
7. Add isolated integration test databases to avoid shared-DSN package test interference.
8. Add stricter local startup checks for filesystem permissions and schema drift.
9. Add API examples for capability-protected resolution once issuer trust config exists.
10. Later: replace placeholder `credentialSet128` with real credential-set commitment.
11. Add OpenTelemetry traces for registration, resolution, trust checks, and audit writes.
12. Add Prometheus metrics for request counts, denial counts, audit append failures, and resolver latency.
