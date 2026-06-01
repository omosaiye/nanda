# NANDA v0.1 API

Errors use this shape:

```json
{
  "error": {
    "code": "error_code",
    "message": "human-readable message"
  }
}
```

Health and readiness are public. Registration, resolution, and admin routes require `Authorization: Bearer <token>` only when `NANDA_API_TOKEN` is configured.

## GET /healthz

Purpose: process liveness check.

Auth: none.

Response:

```json
{ "status": "ok" }
```

## GET /readyz

Purpose: local readiness check.

Auth: none.

Response:

```json
{ "status": "ready" }
```

## POST /v1/agents/register

Purpose: store AgentFacts, create a signed L1 record, write the index, and audit the registration.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Request:

```json
{
  "agentId": "agent.example",
  "ttlSeconds": 300,
  "flags": 0,
  "sequence": 1,
  "facts": {
    "schemaVersion": "nanda.agentfacts.v0",
    "id": "agent.example",
    "controller": "did:example:controller",
    "validFrom": "2026-01-01T00:00:00Z",
    "validUntil": "2030-01-01T00:00:00Z",
    "capabilities": ["chat"],
    "endpoints": [
      {
        "id": "primary",
        "type": "static",
        "url": "https://agent.example/api",
        "protocol": "https",
        "ttlSeconds": 60
      }
    ]
  }
}
```

Response:

```json
{
  "agentId": "agent.example",
  "factsPointer": "sha256:<hex>",
  "factsPtrHash128": "<hex>",
  "credentialSet128": "<hex>",
  "sequence": 1,
  "ttlSeconds": 300,
  "agentAddrRecordBase64": "<base64>"
}
```

Errors: `400 registration_validation_failed`, `400 invalid_registration_request`, `401 unauthorized`, `405 method_not_allowed`, `500 internal_error`.

## POST /v1/resolve

Purpose: resolve an agent to an endpoint after verifying the L1 record and AgentFacts bindings.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Request:

```json
{
  "agentId": "agent.example",
  "requiredCapability": "chat"
}
```

`requiredCapability` is optional. When present, trust verification is required and failures are fail-closed.

Capability trust uses the server's local Ed25519 issuer allowlist from `NANDA_TRUST_ISSUERS_JSON` or `NANDA_TRUST_ISSUERS_FILE`. If no configured issuer matches the credential issuer, the resolver returns `403 trust_denied`. This is not DID resolution, full W3C VC canonicalization, or VC Status List processing.

Response:

```json
{
  "agentId": "agent.example",
  "endpoint": {
    "id": "primary",
    "type": "static",
    "url": "https://agent.example/api",
    "protocol": "https",
    "ttlSeconds": 60
  },
  "trustDecision": "unverified-v0",
  "proofBundle": {
    "agentAddrSignatureVerified": true,
    "agentFactsPointerHashVerified": true,
    "agentFactsSchemaVerified": true,
    "credentialSetVerified": true,
    "credentialStatus": "not-implemented-v0",
    "capabilityCredentialVerified": false
  },
  "cache": {
    "ttlSeconds": 60,
    "expiresAt": "2026-05-31T12:00:00Z",
    "sourceSequence": 1
  }
}
```

Errors: `400 resolve_validation_failed`, `400 invalid_resolve_request`, `401 unauthorized`, `403 trust_denied`, `404 not_found`, `405 method_not_allowed`, `410 expired`, `500 internal_error`.

## GET /v1/admin/agents/{agentId}

Purpose: inspect the current L1 index record metadata for one agent.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Response:

```json
{
  "agentId": "agent.example",
  "agentHash": "<hex>",
  "sequence": 1,
  "ttlSeconds": 300,
  "factsPtrHash128": "<hex>",
  "credentialSet128": "<hex>",
  "recordBase64": "<base64>",
  "createdAt": "2026-05-31T12:00:00Z",
  "updatedAt": "2026-05-31T12:00:00Z",
  "expiresAt": "2026-05-31T12:05:00Z",
  "expired": false
}
```

Errors: `400 admin_validation_failed`, `401 unauthorized`, `404 not_found`, `405 method_not_allowed`, `500 internal_error`.

## GET /v1/admin/audit

Purpose: list audit events.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Query params:

- `limit`: positive integer, defaults to 100, maximum 500.
- `offset`: non-negative integer, defaults to 0.
- `eventType`: one of `agent.registered`, `resolve.allowed`, `resolve.denied`, `trust.denied`.
- `decision`: one of `allowed`, `denied`.

Response:

```json
{
  "items": [
    {
      "eventId": "<hex>",
      "eventType": "agent.registered",
      "agentId": "agent.example",
      "agentHash": "<hex>",
      "decision": "allowed",
      "eventJSON": {},
      "previousHash": "",
      "eventHash": "<hex>",
      "createdAt": "2026-05-31T12:00:00Z"
    }
  ],
  "limit": 100,
  "offset": 0,
  "count": 1
}
```

Errors: `400 admin_validation_failed`, `401 unauthorized`, `405 method_not_allowed`, `500 internal_error`.

## GET /v1/admin/audit/{agentId}

Purpose: list audit events for one agent.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Query params: same as `GET /v1/admin/audit`.

Response: same list shape as `GET /v1/admin/audit`.

Errors: `400 admin_validation_failed`, `401 unauthorized`, `405 method_not_allowed`, `500 internal_error`.

## GET /v1/admin/revocation/{issuer}/{credentialId}

Purpose: inspect v0 revocation status for one issuer and credential ID.

Auth: optional bearer token in local mode; required when `NANDA_API_TOKEN` is set.

Response when no explicit revocation record exists:

```json
{
  "issuer": "issuer.example",
  "credentialId": "credential-1",
  "status": "active",
  "found": false
}
```

Response when a record exists:

```json
{
  "issuer": "issuer.example",
  "credentialId": "credential-1",
  "status": "revoked",
  "reason": "operator action",
  "found": true,
  "updatedAt": "2026-05-31T12:00:00Z"
}
```

Errors: `400 admin_validation_failed`, `401 unauthorized`, `405 method_not_allowed`, `500 internal_error`.
