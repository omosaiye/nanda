.PHONY: test run fmt tidy

test:
	go test ./...

run:
	go run ./cmd/nanda-server

fmt:
	go fmt ./...

tidy:
	go mod tidy
