.PHONY: test test-integration run-local run fmt tidy

test:
	go test ./...

test-integration:
	NANDA_POSTGRES_DSN="$${NANDA_POSTGRES_DSN:?set NANDA_POSTGRES_DSN}" go test ./...

run-local:
	NANDA_POSTGRES_DSN="$${NANDA_POSTGRES_DSN:?set NANDA_POSTGRES_DSN}" go run ./cmd/nanda-server

run:
	go run ./cmd/nanda-server

fmt:
	go fmt ./...

tidy:
	go mod tidy
