# NANDA Local Demo

This demo runs the v0 server against local PostgreSQL and uses the checked-in JSON examples.

## Start PostgreSQL

```sh
docker compose up -d postgres
```

The compose file exposes PostgreSQL on localhost port `5432` with:

```sh
postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable
```

## Migration Behavior

`cmd/nanda-server` runs the SQL files in `migrations/` at startup. Migrations are written to be safe for repeated local runs, so restarting the server reapplies the current schema definitions without a separate migration command.

## Run the Server

```sh
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go run ./cmd/nanda-server
```

Or use the Makefile default DSN:

```sh
make run-local
```

The server listens on `:8080` by default.

## Environment Variables

- `NANDA_POSTGRES_DSN`: PostgreSQL DSN. Required by the local server.
- `NANDA_ADDR`: HTTP listen address. Defaults to `:8080`.
- `NANDA_FACTS_DIR`: local AgentFacts storage directory. Defaults to `./var/facts`.
- `NANDA_PRIVATE_KEY_BASE64`: base64 Ed25519 private key. Optional for local demos.
- `NANDA_PUBLIC_KEY_BASE64`: base64 Ed25519 public key matching the private key. Optional.

If no signing key is configured, the server generates an ephemeral local Ed25519 key at startup. Records from a previous ephemeral run will not verify after restarting with a different key.

## Register an Agent

```sh
curl -sS -X POST http://localhost:8080/v1/agents/register \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-register' \
  --data-binary @docs/examples/register-agent.json
```

## Resolve an Agent

```sh
curl -sS -X POST http://localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: demo-resolve' \
  --data-binary @docs/examples/resolve-agent.json
```

## Demo Script

With PostgreSQL and the server running:

```sh
./scripts/demo-local.sh
```

## Tests

Run unit tests:

```sh
go test ./...
```

Or:

```sh
make test
```

Run integration tests against local PostgreSQL:

```sh
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test ./...
```

Or use the Makefile default DSN:

```sh
make test-integration
```
