#!/bin/sh
set -eu

: "${GOCACHE:=${TMPDIR:-/tmp}/nanda-go-cache}"
export GOCACHE

go fmt ./...
go test -count=1 ./...

if [ -n "${NANDA_POSTGRES_DSN:-}" ]; then
	go test -p 1 -count=1 -v ./...
fi

./scripts/verify.sh
