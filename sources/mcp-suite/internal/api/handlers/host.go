package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/felfoldy/mcp-suite/internal/api/middleware"
	"github.com/felfoldy/mcp-suite/internal/model"
	"github.com/felfoldy/mcp-suite/internal/pki"
)

type HostHandler struct {
	db      *pgxpool.Pool
	ca      *pki.CA
	certTTL int // jours
	jwtPub  []byte
	log     *zap.Logger
}

func NewHostHandler(db *pgxpool.Pool, ca *pki.CA, certTTL int, jwtPub []byte, log *zap.Logger) *HostHandler {
	return &HostHandler{db: db, ca: ca, certTTL: certTTL, jwtPub: jwtPub, log: log}
}

// ─────────────────────────────────────────────
// POST /v1/hosts/register
// ─────────────────────────────────────────────

func (h *HostHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Récupérer la licence depuis le contexte (posé par LicenseKeyAuth)
	licenseKeyStr, _ := r.Context().Value(middleware.LicenseKeyCtx).(string)
	licenseKey, err := uuid.Parse(licenseKeyStr)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "invalid_license_key", "X-License-Key invalide")
		return
	}

	var req model.RegisterHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if req.HostID == "" || req.Fingerprint == "" {
		writeError(w, r, http.StatusBadRequest, "missing_fields", "host_id et fingerprint requis")
		return
	}

	// Vérifier la licence : active + quota hosts
	var lic model.License
	var activeHosts int
	err = h.db.QueryRow(r.Context(), `
		SELECT l.status, l.max_hosts, l.token_budget,
		       COUNT(h.id) FILTER (WHERE h.status='active') as active_hosts
		FROM licenses l
		LEFT JOIN hosts h ON h.license_key = l.license_key
		WHERE l.license_key = $1
		GROUP BY l.license_key`, licenseKey,
	).Scan(&lic.Status, &lic.MaxHosts, &lic.TokenBudget, &activeHosts)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "invalid_license", "Licence introuvable")
		return
	}
	if lic.Status != model.StatusActive {
		writeError(w, r, http.StatusForbidden, "license_inactive", "Licence non active")
		return
	}
	if activeHosts >= lic.MaxHosts {
		writeError(w, r, http.StatusForbidden, "quota_hosts_reached",
			"Quota de hosts atteint pour cette licence")
		return
	}

	// Anti-clonage : fingerprint déjà actif sur un autre host ?
	var fpExists bool
	h.db.QueryRow(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM hosts WHERE fingerprint=$1 AND status='active' AND host_id != $2)",
		req.Fingerprint, req.HostID,
	).Scan(&fpExists)
	if fpExists {
		h.log.Warn("tentative clonage Worker détectée",
			zap.String("fingerprint", req.Fingerprint),
			zap.String("host_id", req.HostID),
		)
		writeError(w, r, http.StatusConflict, "fingerprint_conflict",
			"Empreinte système déjà enregistrée sur un autre host actif")
		return
	}

	// Émettre certificat mTLS
	cert, err := h.ca.IssueWorkerCert(req.HostID, h.certTTL)
	if err != nil {
		h.log.Error("émission certificat Worker", zap.Error(err))
		writeError(w, r, http.StatusInternalServerError, "pki_error", "Erreur émission certificat")
		return
	}

	// Insérer le host (UPSERT : réenregistrement autorisé)
	_, err = h.db.Exec(r.Context(), `
		INSERT INTO hosts (host_id, license_key, fingerprint, cert_serial, cert_expiry, status)
		VALUES ($1, $2, $3, $4, $5, 'active')
		ON CONFLICT (host_id) DO UPDATE SET
			fingerprint = EXCLUDED.fingerprint,
			cert_serial = EXCLUDED.cert_serial,
			cert_expiry = EXCLUDED.cert_expiry,
			status = 'active',
			updated_at = NOW()`,
		req.HostID, licenseKey, req.Fingerprint,
		cert.SerialNumber, cert.ExpiresAt,
	)
	if err != nil {
		h.log.Error("insertion host", zap.Error(err))
		writeError(w, r, http.StatusInternalServerError, "db_error", "Erreur enregistrement host")
		return
	}

	// Stocker cert dans pki_certificates
	h.db.Exec(r.Context(), `
		INSERT INTO pki_certificates (host_id, license_key, serial_number, cert_pem, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		req.HostID, licenseKey, cert.SerialNumber, string(cert.CertPEM), cert.ExpiresAt,
	)

	h.log.Info("Worker enregistré",
		zap.String("host_id", req.HostID),
		zap.String("license_key", licenseKey.String()),
		zap.String("version", req.WorkerVersion),
	)

	writeJSON(w, http.StatusCreated, model.RegisterHostResponse{
		HostID:       req.HostID,
		CertPEM:      string(cert.CertPEM),
		CACertPEM:    string(h.ca.CACertPEM()),
		CertSerial:   cert.SerialNumber,
		CertExpiry:   cert.ExpiresAt,
		MasterPubKey: string(h.jwtPub),
	})
}

// ─────────────────────────────────────────────
// DELETE /v1/hosts/:host_id
// ─────────────────────────────────────────────

func (h *HostHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")
	if hostID == "" {
		writeError(w, r, http.StatusBadRequest, "missing_host_id", "host_id requis")
		return
	}

	ct, err := h.db.Exec(r.Context(),
		"UPDATE hosts SET status='revoked', updated_at=NOW() WHERE host_id=$1 AND status='active'",
		hostID,
	)
	if err != nil || ct.RowsAffected() == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "Host introuvable ou déjà révoqué")
		return
	}

	// Révoquer le certificat mTLS
	h.db.Exec(r.Context(),
		"UPDATE pki_certificates SET revoked_at=NOW() WHERE host_id=$1 AND revoked_at IS NULL",
		hostID,
	)

	h.log.Info("host révoqué", zap.String("host_id", hostID))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host_id":      hostID,
		"status":       "revoked",
		"cert_revoked": true,
	})
}

// ─────────────────────────────────────────────
// GET /v1/hosts/:host_id/cert  (renouvellement mTLS)
// ─────────────────────────────────────────────

func (h *HostHandler) RenewCert(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")

	// Vérifier host actif
	var licKey uuid.UUID
	err := h.db.QueryRow(r.Context(),
		"SELECT license_key FROM hosts WHERE host_id=$1 AND status='active'",
		hostID,
	).Scan(&licKey)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Host introuvable ou révoqué")
		return
	}

	cert, err := h.ca.IssueWorkerCert(hostID, h.certTTL)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "pki_error", "Erreur renouvellement certificat")
		return
	}

	// Invalider l'ancien cert, stocker le nouveau
	h.db.Exec(r.Context(),
		"UPDATE pki_certificates SET rotated_at=NOW() WHERE host_id=$1 AND revoked_at IS NULL",
		hostID,
	)
	h.db.Exec(r.Context(), `
		INSERT INTO pki_certificates (host_id, license_key, serial_number, cert_pem, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hostID, licKey, cert.SerialNumber, string(cert.CertPEM), cert.ExpiresAt,
	)
	h.db.Exec(r.Context(),
		"UPDATE hosts SET cert_serial=$1, cert_expiry=$2, updated_at=NOW() WHERE host_id=$3",
		cert.SerialNumber, cert.ExpiresAt, hostID,
	)

	now := time.Now()
	h.log.Info("certificat renouvelé",
		zap.String("host_id", hostID),
		zap.Time("expires_at", cert.ExpiresAt),
	)
	_ = now

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cert_pem":    string(cert.CertPEM),
		"cert_serial": cert.SerialNumber,
		"cert_expiry": cert.ExpiresAt,
	})
}

// ─────────────────────────────────────────────
// POST /v1/hosts/:host_id/heartbeat
// ─────────────────────────────────────────────

func (h *HostHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	hostID := chi.URLParam(r, "host_id")
	h.db.Exec(r.Context(),
		"UPDATE hosts SET last_seen_at=NOW() WHERE host_id=$1 AND status='active'",
		hostID,
	)
	w.WriteHeader(http.StatusNoContent)
}
