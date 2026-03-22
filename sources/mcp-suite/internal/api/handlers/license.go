package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/virtusia/mcp-suite/internal/model"
	mcpjwt "github.com/virtusia/mcp-suite/internal/jwt"
	"github.com/virtusia/mcp-suite/internal/webhook"
)

type LicenseHandler struct {
	db      *pgxpool.Pool
	jwt     *mcpjwt.Manager
	pusher  *webhook.Pusher
	log     *zap.Logger
}

func NewLicenseHandler(db *pgxpool.Pool, jwt *mcpjwt.Manager, pusher *webhook.Pusher, log *zap.Logger) *LicenseHandler {
	return &LicenseHandler{db: db, jwt: jwt, pusher: pusher, log: log}
}

// ─────────────────────────────────────────────
// POST /v1/licenses
// ─────────────────────────────────────────────

func (h *LicenseHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req model.CreateLicenseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	if req.CustomerID == uuid.Nil || req.Plan == "" || req.BillingCycle == "" {
		writeError(w, r, http.StatusBadRequest, "missing_fields", "customer_id, plan, billing_cycle requis")
		return
	}

	// Vérifier que le customer existe
	var exists bool
	err := h.db.QueryRow(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM customers WHERE id = $1)", req.CustomerID,
	).Scan(&exists)
	if err != nil || !exists {
		writeError(w, r, http.StatusNotFound, "customer_not_found", "Customer introuvable")
		return
	}

	// KID JWT pour cette licence
	kid := h.jwt.ActiveKID()

	// Calculer la fin de période
	var periodEnd *time.Time
	if req.BillingCycle == model.BillingMonthly {
		t := time.Now().AddDate(0, 1, 0)
		periodEnd = &t
	} else if req.BillingCycle == model.BillingAnnual {
		t := time.Now().AddDate(1, 0, 0)
		periodEnd = &t
	}

	// Convertir modules en []string pour pgx (cast enum)
	modulesStr := make([]string, len(req.Modules))
	for i, m := range req.Modules {
		modulesStr[i] = string(m)
	}

	// Insertion en DB — cast explicite des enums via SQL
	var licenseKey uuid.UUID
	err = h.db.QueryRow(r.Context(), `
		INSERT INTO licenses (
			customer_id, plan, modules, max_hosts, token_budget,
			billing_cycle, status, jwt_kid, expiry_at,
			current_period_start, current_period_end
		) VALUES (
			$1,
			$2::plan_type,
			$3::module_type[],
			$4, $5,
			$6::billing_cycle_type,
			'active'::license_status,
			$7, $8,
			NOW(), $9
		)
		RETURNING license_key`,
		req.CustomerID,
		string(req.Plan),
		modulesStr,
		req.MaxHosts,
		req.TokenBudget,
		string(req.BillingCycle),
		kid,
		req.ExpiryAt,
		periodEnd,
	).Scan(&licenseKey)
	if err != nil {
		h.log.Error("création licence", zap.Error(err))
		writeError(w, r, http.StatusInternalServerError, "db_error", "Erreur création licence: "+err.Error())
		return
	}

	// Billing event activation
	h.db.Exec(r.Context(), `
		INSERT INTO billing_events (license_key, customer_id, event_type, tokens_credited)
		VALUES ($1, $2, 'activation', $3)`,
		licenseKey, req.CustomerID, req.TokenBudget,
	)

	h.log.Info("licence créée",
		zap.String("license_key", licenseKey.String()),
		zap.String("plan", string(req.Plan)),
		zap.String("customer_id", req.CustomerID.String()),
	)

	writeJSON(w, http.StatusCreated, model.CreateLicenseResponse{
		LicenseKey: licenseKey.String(),
		JWTKid:     kid,
		Status:     "active",
		CreatedAt:  time.Now(),
	})
}

// ─────────────────────────────────────────────
// GET /v1/licenses/:key
// ─────────────────────────────────────────────

func (h *LicenseHandler) Get(w http.ResponseWriter, r *http.Request) {
	key, err := parseUUID(chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_key", "UUID invalide")
		return
	}

	summary, err := h.getSummary(r.Context(), key)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Licence introuvable")
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// ─────────────────────────────────────────────
// GET /v1/licenses/:key/status  (appelé par Master)
// ─────────────────────────────────────────────

func (h *LicenseHandler) Status(w http.ResponseWriter, r *http.Request) {
	key, err := parseUUID(chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_key", "UUID invalide")
		return
	}

	// FIX: cast enums en text pour compatibilité pgx v5
	var lic model.License
	var planStr, statusStr string
	var modulesStr []string
	err = h.db.QueryRow(r.Context(), `
		SELECT license_key, plan::text, modules::text[], status::text,
		       token_budget, tokens_used, max_hosts, expiry_at, jwt_kid
		FROM licenses WHERE license_key = $1`, key,
	).Scan(
		&lic.LicenseKey, &planStr, &modulesStr, &statusStr,
		&lic.TokenBudget, &lic.TokensUsed, &lic.MaxHosts,
		&lic.ExpiryAt, &lic.JWTKid,
	)
	if err != nil {
		writeJSON(w, http.StatusOK, model.ValidateResponse{
			Valid:  false,
			Reason: "not_found",
		})
		return
	}
	lic.Plan = model.PlanType(planStr)
	lic.Status = model.LicenseStatus(statusStr)
	lic.Modules = make([]model.ModuleType, len(modulesStr))
	for i, m := range modulesStr {
		lic.Modules[i] = model.ModuleType(m)
	}

	// Vérifier module optionnel
	moduleParam := r.URL.Query().Get("module")
	if moduleParam != "" {
		if !lic.HasModule(model.ModuleType(moduleParam)) {
			writeJSON(w, http.StatusOK, model.ValidateResponse{
				Valid:      false,
				LicenseKey: key.String(),
				Status:     lic.Status,
				Reason:     "module_not_licensed",
			})
			return
		}
	}

	// Validations
	reason := validateLicense(&lic)
	if reason != "" {
		writeJSON(w, http.StatusOK, model.ValidateResponse{
			Valid:      false,
			LicenseKey: key.String(),
			Status:     lic.Status,
			Reason:     reason,
		})
		return
	}

	writeJSON(w, http.StatusOK, model.ValidateResponse{
		Valid:           true,
		LicenseKey:      key.String(),
		Plan:            lic.Plan,
		Modules:         lic.Modules,
		Status:          lic.Status,
		TokensRemaining: lic.TokensRemaining(),
		MaxHosts:        lic.MaxHosts,
		ExpiryAt:        lic.ExpiryAt,
		JWTKid:          lic.JWTKid,
	})
}

// ─────────────────────────────────────────────
// POST /v1/licenses/:key/revoke
// ─────────────────────────────────────────────

func (h *LicenseHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	key, err := parseUUID(chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_key", "UUID invalide")
		return
	}

	var req model.RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Mise à jour synchrone en DB
	ct, err := h.db.Exec(r.Context(),
		"UPDATE licenses SET status='revoked', updated_at=NOW() WHERE license_key=$1 AND status='active'",
		key,
	)
	if err != nil || ct.RowsAffected() == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "Licence introuvable ou déjà révoquée")
		return
	}

	// Journal révocation
	_, err = h.db.Exec(r.Context(), `
		INSERT INTO revocations (license_key, reason, initiated_by, notes)
		VALUES ($1, $2, $3, $4)`,
		key, string(req.Reason), req.InitiatedBy, req.Notes,
	)
	if err != nil {
		h.log.Error("insertion révocation", zap.Error(err))
	}

	revokedAt := time.Now()
	h.log.Info("licence révoquée",
		zap.String("license_key", key.String()),
		zap.String("reason", string(req.Reason)),
		zap.String("by", req.InitiatedBy),
	)

	// Push webhook asynchrone vers les Masters
	go h.pushRevocation(key.String(), req)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"license_key": key.String(),
		"status":      "revoked",
		"revoked_at":  revokedAt,
		"webhook_push": map[string]interface{}{
			"status":                 "dispatched",
			"estimated_delivery_sec": 60,
		},
	})
}

// pushRevocation envoie le webhook de révocation à tous les Masters concernés
func (h *LicenseHandler) pushRevocation(licenseKey string, req model.RevokeRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	rows, err := h.db.Query(ctx, `
		SELECT DISTINCT c.webhook_url, c.webhook_secret
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		WHERE l.license_key = $1 AND c.webhook_url IS NOT NULL AND c.webhook_url != ''`,
		licenseKey,
	)
	if err != nil {
		h.log.Error("récupération webhooks", zap.Error(err))
		return
	}
	defer rows.Close()

	payload := webhook.RevocationPayload{
		Event:      "license.revoked",
		LicenseKey: licenseKey,
		Reason:     string(req.Reason),
		RevokedAt:  time.Now(),
	}

	for rows.Next() {
		var url, secret string
		if err := rows.Scan(&url, &secret); err != nil {
			continue
		}
		attempts, err := h.pusher.Push(ctx, url, secret, payload)
		if err != nil {
			h.log.Error("push révocation échoué",
				zap.String("url", url),
				zap.Int("attempts", attempts),
				zap.Error(err),
			)
			h.db.Exec(ctx,
				"UPDATE revocations SET webhook_attempts=$1 WHERE id=(SELECT id FROM revocations WHERE license_key=$2 ORDER BY revoked_at DESC LIMIT 1)",
				attempts, licenseKey,
			)
		} else {
			now := time.Now()
			h.db.Exec(ctx,
				"UPDATE revocations SET webhook_pushed_at=$1, webhook_attempts=$2 WHERE id=(SELECT id FROM revocations WHERE license_key=$3 ORDER BY revoked_at DESC LIMIT 1)",
				now, attempts, licenseKey,
			)
		}
	}
}

// ─────────────────────────────────────────────
// POST /v1/licenses/:key/renew
// ─────────────────────────────────────────────

func (h *LicenseHandler) Renew(w http.ResponseWriter, r *http.Request) {
	key, err := parseUUID(chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_key", "UUID invalide")
		return
	}

	var req model.RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	var tokenBudget, tokensUsed int64
	err = h.db.QueryRow(r.Context(), `
		UPDATE licenses SET
			status = 'active',
			token_budget = token_budget + $1,
			billing_cycle = $2::billing_cycle_type,
			current_period_start = NOW(),
			current_period_end = $3,
			updated_at = NOW()
		WHERE license_key = $4
		RETURNING token_budget, tokens_used`,
		req.TokensToCredit, string(req.BillingCycle), req.NewPeriodEnd, key,
	).Scan(&tokenBudget, &tokensUsed)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "Licence introuvable")
		return
	}

	h.db.Exec(r.Context(), `
		INSERT INTO billing_events (license_key, customer_id, event_type, tokens_credited, external_ref)
		SELECT $1, customer_id, 'renewal', $2, $3 FROM licenses WHERE license_key = $1`,
		key, req.TokensToCredit, req.ExternalRef,
	)

	remaining := tokenBudget - tokensUsed
	if remaining < 0 {
		remaining = 0
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"license_key":        key.String(),
		"status":             "active",
		"tokens_remaining":   remaining,
		"current_period_end": req.NewPeriodEnd,
	})
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func (h *LicenseHandler) getSummary(ctx context.Context, key uuid.UUID) (*model.LicenseSummary, error) {
	var s model.LicenseSummary
	var tokenBudget, tokensUsed int64
	var planStr, statusStr, billingStr string
	var modulesStr []string

	err := h.db.QueryRow(ctx, `
		SELECT
			l.license_key::text,
			c.email, c.name,
			l.plan::text, l.modules::text[], l.status::text,
			l.token_budget, l.tokens_used,
			l.max_hosts,
			COUNT(h.id) FILTER (WHERE h.status='active'),
			l.expiry_at, l.billing_cycle::text, l.current_period_end, l.created_at
		FROM licenses l
		JOIN customers c ON c.id = l.customer_id
		LEFT JOIN hosts h ON h.license_key = l.license_key
		WHERE l.license_key = $1
		GROUP BY l.license_key, c.email, c.name`, key,
	).Scan(
		&s.LicenseKey, &s.CustomerEmail, &s.CustomerName,
		&planStr, &modulesStr, &statusStr,
		&tokenBudget, &tokensUsed,
		&s.MaxHosts, &s.ActiveHosts,
		&s.ExpiryAt, &billingStr, &s.CurrentPeriodEnd, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.Plan = model.PlanType(planStr)
	s.Status = model.LicenseStatus(statusStr)
	s.BillingCycle = model.BillingCycle(billingStr)
	s.Modules = make([]model.ModuleType, len(modulesStr))
	for i, m := range modulesStr {
		s.Modules[i] = model.ModuleType(m)
	}
	s.TokenBudget = tokenBudget
	s.TokensUsed = tokensUsed
	if tokenBudget == -1 {
		s.TokensRemaining = -1
	} else {
		s.TokensRemaining = tokenBudget - tokensUsed
		if s.TokensRemaining < 0 {
			s.TokensRemaining = 0
		}
	}

	return &s, nil
}

func validateLicense(l *model.License) string {
	if l.Status != model.StatusActive {
		return string(l.Status)
	}
	if l.ExpiryAt != nil && time.Now().After(*l.ExpiryAt) {
		return "expired"
	}
	if l.TokenBudget != -1 && l.TokensUsed >= l.TokenBudget {
		return "no_tokens"
	}
	return ""
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, model.ErrorResponse{
		Error:   code,
		Message: msg,
	})
}

func fmtKey(key uuid.UUID) string {
	return fmt.Sprintf("%s...", key.String()[:8])
}
