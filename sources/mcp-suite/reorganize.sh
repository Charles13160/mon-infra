#!/bin/sh
# Réorganisation des fichiers MCP Suite dans la bonne arborescence
set -e

BASE="/srv/mcp-suite"
cd "$BASE"

echo "→ Création de l'arborescence..."
mkdir -p cmd/license-server
mkdir -p internal/api/handlers
mkdir -p internal/api/middleware
mkdir -p internal/db
mkdir -p internal/jwt
mkdir -p internal/pki
mkdir -p internal/webhook
mkdir -p internal/model
mkdir -p internal/config
mkdir -p systemd
mkdir -p scripts
mkdir -p config
mkdir -p certs/ca
mkdir -p certs/jwt
mkdir -p logs
mkdir -p bin

echo "→ Déplacement des fichiers Go..."
[ -f main.go ]     && mv main.go     cmd/license-server/main.go
[ -f router.go ]   && mv router.go   internal/api/router.go
[ -f license.go ]  && mv license.go  internal/api/handlers/license.go
[ -f host.go ]     && mv host.go     internal/api/handlers/host.go
[ -f token.go ]    && mv token.go    internal/api/handlers/token.go
[ -f issuer.go ]   && mv issuer.go   internal/jwt/issuer.go
[ -f pki.go ]      && mv pki.go      internal/pki/pki.go
[ -f push.go ]     && mv push.go     internal/webhook/push.go

echo "→ Déplacement systemd et scripts..."
[ -f mcp-license-server.service ] && mv mcp-license-server.service systemd/
[ -f setup-postgres.sh ]          && mv setup-postgres.sh scripts/ && chmod +x scripts/setup-postgres.sh

echo "→ Permissions..."
chmod +x mcp

echo "✓ Réorganisation terminée"
ls -la
