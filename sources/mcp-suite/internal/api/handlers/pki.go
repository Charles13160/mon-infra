package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	mcpjwt "github.com/felfoldy/mcp-suite/internal/jwt"
)

type PKIHandler struct {
	db      *pgxpool.Pool
	jwtMgr  *mcpjwt.Manager
	version string
	startAt time.Time
}

func NewPKIHandler(db *pgxpool.Pool, jwtMgr *mcpjwt.Manager, version string) *PKIHandler {
	return &PKIHandler{db: db, jwtMgr: jwtMgr, version: version, startAt: time.Now()}
}

func (h *PKIHandler) PublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"kid":            h.jwtMgr.ActiveKID(),
		"algorithm":      "RS256",
		"public_key_pem": string(h.jwtMgr.ActivePublicPEM()),
		"created_at":     time.Now(),
	})
}

func (h *PKIHandler) Health(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := h.db.Ping(r.Context()); err != nil {
		dbStatus = "error"
	}
	status := http.StatusOK
	if dbStatus != "ok" {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     dbStatus,
		"db":         dbStatus,
		"uptime_sec": int(time.Since(h.startAt).Seconds()),
		"version":    h.version,
	})
}
