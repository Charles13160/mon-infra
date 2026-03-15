#!/bin/sh
set -e

# ── 1. Forcer Go 1.22 ──────────────────────────────────────
export PATH=/usr/local/go/bin:$PATH

echo "Go actif : $(go version)"

# Vérifier que c'est bien 1.22
GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
if [ "$GO_VER" != "1.22" ]; then
    echo "ERREUR: Go 1.22 attendu, trouvé $GO_VER"
    echo "Vérification du tar..."
    ls -lh /usr/local/go/bin/go
    /usr/local/go/bin/go version
    export PATH=/usr/local/go/bin:$PATH
fi

cd /srv/mcp-suite

# ── 2. Dire à Go que ce module est LOCAL (pas sur GitHub) ──
export GONOSUMCHECK="github.com/felfoldy/*"
export GOFLAGS="-mod=mod"
export GONOSUMDB="github.com/felfoldy/*"
export GOPRIVATE="github.com/felfoldy/*"
export GONOPROXY="github.com/felfoldy/*"

# ── 3. Télécharger uniquement les dépendances externes ─────
export GOPATH=/root/go
export GOMODCACHE=/root/go/pkg/mod

echo "→ go mod download (dépendances externes seulement)..."
go mod download \
    github.com/go-chi/chi/v5@v5.1.0 \
    github.com/golang-jwt/jwt/v5@v5.2.1 \
    github.com/google/uuid@v1.6.0 \
    github.com/jackc/pgx/v5@v5.5.5 \
    github.com/spf13/viper@v1.19.0 \
    go.uber.org/zap@v1.27.0 \
    golang.org/x/crypto@v0.21.0

echo "→ go mod tidy..."
go mod tidy

echo "→ Compilation..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build \
    -trimpath \
    -ldflags '-w -s -X main.version=1.0.0 -X main.buildHash=chat2' \
    -o bin/license-server \
    ./cmd/license-server

echo "✓ Binaire : $(ls -lh bin/license-server)"
