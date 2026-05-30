# NANDA Agent Instructions

You are helping build NANDA v0: a DNS-like registry and resolver for AI agents.

Primary goal:
Build the system incrementally and test each milestone before moving on.

Architecture rules:
- L1 is a compact signed AgentAddr120 anchor.
- L2 is AgentFacts metadata.
- L3 is dynamic endpoint selection.
- AgentAddr120 must always be exactly 120 bytes.
- Do not implement full W3C VC interoperability, OHTTP, Envoy, IPFS, Tor, or Trillian in v0.
- Use interfaces so those components can be added later.
- Security-sensitive failures must fail closed.
- Every registration, resolution, denial, revocation, and trust decision must produce an audit event once the audit subsystem exists.

Implementation rules:
- Use Go for the v0 server and core protocol packages.
- Keep packages small and testable.
- Do not hide behavior in large utility files.
- Prefer explicit errors over silent fallbacks.
- Add tests with every feature.
- Run `go test ./...` before declaring a task done.
- Do not skip tests unless explicitly instructed.
- Do not build future-scope features unless specifically asked.

Repository structure target:
- cmd/nanda-server
- internal/agentaddr
- internal/api
- internal/audit
- internal/config
- internal/facts
- internal/index
- internal/observability
- internal/policy
- internal/resolver
- internal/revocation
- internal/trust
- migrations
- testdata
- tests

Current milestone:
Milestone 1 only: protocol primitives and server skeleton.
