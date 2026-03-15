#!/bin/sh
set -e

export PATH=/usr/local/go/bin:$PATH
export GOPATH=/root/go
export GONOSUMDB="*"
export GOFLAGS="-mod=mod"

echo "Go : $(go version)"
cd /srv/mcp-suite

echo "→ go mod tidy..."
go mod tidy

echo "→ Compilation..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags '-w -s -X main.version=1.0.0 -X main.buildHash=chat2' \
    -o bin/license-server \
    ./cmd/license-server

echo "✓ $(ls -lh bin/license-server)"
