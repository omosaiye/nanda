# Testing

## Unit Tests

Run all Go tests without a Postgres DSN:

```sh
go test ./...
```

Most packages use memory stores or isolated temporary filesystem state for unit coverage.

## Integration Tests

Postgres-backed tests run when `NANDA_POSTGRES_DSN` is set:

```sh
docker compose up -d postgres
NANDA_POSTGRES_DSN='postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable' go test ./...
```

The Makefile default is equivalent:

```sh
make test-integration
```

Integration tests may drop, recreate, truncate, or otherwise reset local test tables in the configured database. Use the local Docker Postgres instance for tests, not a shared or production database.

## Verification Script

`scripts/verify.sh` runs:

```sh
go fmt ./...
go test ./...
```

If `NANDA_POSTGRES_DSN` is set, it also runs a verbose integration pass:

```sh
go test -v ./...
```

`make verify` delegates to this script.

## Persistent Docker State

`docker compose down` stops the local database but keeps the named volume. Persistent state can affect manual demos because records, audit events, and revocation rows remain. For a fully clean local database, remove the compose volume after stopping Postgres:

```sh
docker compose down -v
```
