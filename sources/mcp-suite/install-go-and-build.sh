#!/bin/sh
set -e

echo "→ Installation Go 1.22..."
cd /tmp
wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
rm go1.22.0.linux-amd64.tar.gz

# PATH permanent
if ! grep -q "/usr/local/go/bin" /etc/profile.d/go.sh 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh
fi
export PATH=$PATH:/usr/local/go/bin

echo "✓ Go installé : $(go version)"

echo "→ Téléchargement des dépendances..."
cd /srv/mcp-suite
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin

go get github.com/go-chi/chi/v5@v5.1.0
go get github.com/golang-jwt/jwt/v5@v5.2.1
go get github.com/google/uuid@v1.6.0
go get github.com/jackc/pgx/v5@v5.5.5
go get github.com/spf13/viper@v1.19.0
go get go.uber.org/zap@v1.27.0
go get golang.org/x/crypto@v0.21.0

go mod tidy
echo "✓ Dépendances OK"

echo "→ Compilation license-server..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags '-w -s -X main.version=1.0.0 -X main.buildHash=chat2' \
    -o bin/license-server \
    ./cmd/license-server

echo "✓ Binaire compilé : $(ls -lh bin/license-server)"
