LOCAL_POSTGRES_DSN ?= postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable

.PHONY: test test-integration run-local run docker-up docker-down fmt tidy verify

test:
	go test ./...

test-integration:
	NANDA_POSTGRES_DSN="$${NANDA_POSTGRES_DSN:-$(LOCAL_POSTGRES_DSN)}" go test ./...

run-local:
	NANDA_POSTGRES_DSN="$${NANDA_POSTGRES_DSN:-$(LOCAL_POSTGRES_DSN)}" go run ./cmd/nanda-server

run:
	go run ./cmd/nanda-server

docker-up:
	docker compose up -d postgres

docker-down:
	docker compose down

fmt:
	go fmt ./...

tidy:
	go mod tidy

verify: fmt test
