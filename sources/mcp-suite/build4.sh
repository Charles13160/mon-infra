#!/bin/sh
set -e
export PATH=/usr/local/go/bin:$PATH
export GOPATH=/root/go
export GONOSUMDB="*"
export GOFLAGS="-mod=mod"

cd /srv/mcp-suite
echo "→ go get des dépendances externes..."
go get github.com/go-chi/chi/v5@v5.1.0
go get github.com/golang-jwt/jwt/v5@v5.2.1
go get github.com/google/uuid@v1.6.0
go get github.com/jackc/pgx/v5@v5.5.5
go get github.com/spf13/viper@v1.19.0
go get go.uber.org/zap@v1.27.0
go get golang.org/x/crypto@v0.21.0

echo "→ Compilation..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -mod=mod \
    -trimpath \
    -ldflags '-w -s -X main.version=1.0.0 -X main.buildHash=chat2' \
    -o /srv/mcp-suite/bin/mcp-license-server \
    ./cmd/license-server

echo "✓ $(ls -lh bin/license-server)"
