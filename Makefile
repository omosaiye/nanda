LOCAL_POSTGRES_DSN ?= postgres://nanda:nanda@localhost:5432/nanda?sslmode=disable

.PHONY: test test-integration run-local run docker-up docker-down fmt tidy verify verify-script

test:
	go test ./...

test-integration:
	NANDA_POSTGRES_DSN="$${NANDA_POSTGRES_DSN:-$(LOCAL_POSTGRES_DSN)}" go test -p 1 -count=1 -v ./...

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

verify: verify-script

verify-script:
	./scripts/verify.sh
