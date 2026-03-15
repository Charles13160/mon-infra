#!/bin/sh
set -e

echo "→ Téléchargement Go 1.22 via curl..."
cd /tmp
curl -L -o go1.22.0.linux-amd64.tar.gz https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
rm go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh

echo "✓ $(go version)"

echo "→ Build license-server..."
cd /srv/mcp-suite
export GOPATH=/root/go
export GOMODCACHE=/root/go/pkg/mod

go mod tidy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags '-w -s -X main.version=1.0.0 -X main.buildHash=chat2' \
    -o bin/license-server \
    ./cmd/license-server

echo "✓ Binaire : $(ls -lh bin/license-server)"
