#!/bin/sh
set -eu

: "${GOCACHE:=${TMPDIR:-/tmp}/nanda-go-cache}"
export GOCACHE

go fmt ./...
go test ./...

if [ -n "${NANDA_POSTGRES_DSN:-}" ]; then
	go test -v ./...
fi
