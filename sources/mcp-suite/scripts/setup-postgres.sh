#!/usr/bin/env bash
# scripts/setup-postgres.sh
# Migration PostgreSQL Docker → PostgreSQL natif sur host2
# Prérequis : PostgreSQL 16 installé (apt install postgresql-16)

set -euo pipefail

PGUSER="license_server"
PGDB="license"
PGHOST="localhost"
MCP_DIR="/srv/mcp-suite"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
info() { echo -e "${BLUE}→${NC} $*"; }

echo ""
echo "═══ Setup PostgreSQL natif pour MCP License Server ═══"
echo ""

# ── 1. Vérifier PostgreSQL installé ─────────────────────────
if ! command -v psql &>/dev/null; then
    warn "PostgreSQL non installé. Installation..."
    apt-get update -qq
    apt-get install -y postgresql-16 postgresql-client-16
    ok "PostgreSQL 16 installé"
fi

PG_VERSION=$(psql --version | grep -oP '\d+\.\d+' | head -1)
ok "PostgreSQL $PG_VERSION détecté"

# ── 2. Démarrer PostgreSQL si nécessaire ────────────────────
if ! systemctl is-active postgresql &>/dev/null; then
    systemctl start postgresql
    systemctl enable postgresql
    ok "PostgreSQL démarré et activé"
fi

# ── 3. Créer utilisateur dédié avec droits minimaux ─────────
info "Création utilisateur $PGUSER..."

# Générer mot de passe aléatoire si pas déjà dans .env
if grep -q "CHANGE_ME" "$MCP_DIR/config/.env" 2>/dev/null; then
    PG_PASSWORD=$(openssl rand -hex 24)
    sed -i "s|license_server:CHANGE_ME@|license_server:${PG_PASSWORD}@|g" "$MCP_DIR/config/.env"
    ok "Mot de passe généré et sauvegardé dans .env"
else
    PG_PASSWORD=$(grep MCP_DATABASE_URL "$MCP_DIR/config/.env" | grep -oP '(?<=:)[^@]+(?=@)')
fi

sudo -u postgres psql <<SQL
-- Créer rôle avec mot de passe
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$PGUSER') THEN
        CREATE ROLE $PGUSER WITH LOGIN PASSWORD '$PG_PASSWORD';
    ELSE
        ALTER ROLE $PGUSER WITH PASSWORD '$PG_PASSWORD';
    END IF;
END
\$\$;

-- Créer base
SELECT 'CREATE DATABASE $PGDB OWNER $PGUSER'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$PGDB')\gexec

-- Droits stricts : pas de CREATE sur public
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE $PGDB TO $PGUSER;
SQL
ok "Utilisateur $PGUSER et base $PGDB créés"

# ── 4. Appliquer le schéma ───────────────────────────────────
info "Application du schéma..."
PGPASSWORD="$PG_PASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" \
    -f "$MCP_DIR/migrations/001_initial_schema.sql"
ok "Schéma appliqué"

# Droits post-migration (uniquement sur les tables créées)
sudo -u postgres psql -d "$PGDB" <<SQL
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO $PGUSER;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO $PGUSER;
-- Pas de DELETE, pas de DROP, pas de TRUNCATE
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM $PGUSER;
SQL
ok "Droits minimaux appliqués (pas de DELETE/DROP)"

# ── 5. Configuration pg_hba.conf — connexions locales uniquement ──
info "Sécurisation pg_hba.conf..."
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | xargs)

# Ajouter règle dédiée pour license_server (avant les règles génériques)
if ! grep -q "license_server" "$PG_HBA" 2>/dev/null; then
    # Insérer après la ligne de commentaire d'en-tête
    sudo bash -c "echo '# MCP License Server — connexion locale uniquement' >> $PG_HBA"
    sudo bash -c "echo 'host    license    license_server    127.0.0.1/32    scram-sha-256' >> $PG_HBA"
    sudo bash -c "echo 'host    license    license_server    10.10.0.0/24    scram-sha-256' >> $PG_HBA"
    sudo -u postgres psql -c "SELECT pg_reload_conf();"
    ok "pg_hba.conf mis à jour (localhost + WireGuard 10.10.0.0/24)"
fi

# ── 6. Migration depuis Docker (si applicable) ───────────────
echo ""
info "Migration depuis Docker (optionnel)"
echo "  Si vous avez des données dans mcp-postgres Docker:"
echo "  1. docker exec mcp-postgres pg_dump -U master license > /tmp/license_backup.sql"
echo "  2. PGPASSWORD='$PG_PASSWORD' psql -h localhost -U license_server -d license < /tmp/license_backup.sql"
echo "  3. sudo mcp start license-server"
echo ""

# ── 7. Test de connexion ─────────────────────────────────────
info "Test de connexion..."
if PGPASSWORD="$PG_PASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" -c "\dt" &>/dev/null; then
    ok "Connexion PostgreSQL natif OK"
    TABLE_COUNT=$(PGPASSWORD="$PG_PASSWORD" psql -h "$PGHOST" -U "$PGUSER" -d "$PGDB" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';")
    ok "$TABLE_COUNT tables présentes dans la base license"
else
    warn "Connexion impossible — vérifier $MCP_DIR/config/.env"
fi

echo ""
echo -e "${GREEN}✓ PostgreSQL natif configuré pour MCP License Server${NC}"
echo "  Base   : $PGDB"
echo "  User   : $PGUSER"
echo "  Host   : $PGHOST"
echo "  Config : $MCP_DIR/config/.env"
echo ""
