# NANDA Hardening Backlog

Known hardening tasks for NANDA v0:

1. Improve resolver HTTP error mapping.
   - Verification failures should not all become generic 500s forever.
   - Consider `409`, `422`, or `502` depending on failure type.
2. Add reusable JSON response/error helpers for API handlers.
3. Wire registration and resolver handlers into `cmd/nanda-server` through explicit local/demo config.
4. Add monotonic sequence enforcement so stale `AgentAddr120` records cannot overwrite newer records.
5. Add stronger structured audit events for registration and resolution once the audit subsystem starts.
6. Add request IDs / trace IDs to API logs.
7. Add integration test covering registration followed by resolution end-to-end.
8. Add Makefile targets for integration tests, including Postgres DSN.
9. Add API examples under `docs/examples`.
10. Later: replace placeholder `credentialSet128` with real credential-set commitment.
