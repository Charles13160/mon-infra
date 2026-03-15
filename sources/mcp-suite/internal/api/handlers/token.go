package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/felfoldy/mcp-suite/internal/model"
)

type TokenHandler struct {
	db  *pgxpool.Pool
	log *zap.Logger
}

func NewTokenHandler(db *pgxpool.Pool, log *zap.Logger) *TokenHandler {
	return &TokenHandler{db: db, log: log}
}

// ─────────────────────────────────────────────
// POST /v1/tokens/consume
// ─────────────────────────────────────────────

func (h *TokenHandler) Consume(w http.ResponseWriter, r *http.Request) {
	var req model.ConsumeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	licKey, err := uuid.Parse(req.LicenseKey)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_license_key", "UUID invalide")
		return
	}

	if req.TokensConsumed <= 0 {
		writeError(w, r, http.StatusBadRequest, "invalid_tokens", "tokens_consumed doit être > 0")
		return
	}

	// Mise à jour atomique avec guard budget
	// Si token_budget = -1 (illimité) → toujours accepté
	var tokenBudget, tokensUsed int64
	err = h.db.QueryRow(r.Context(), `
		UPDATE licenses SET
			tokens_used = tokens_used + $1,
			updated_at  = NOW()
		WHERE license_key = $2
		  AND status = 'active'
		  AND (token_budget = -1 OR tokens_used + $1 <= token_budget)
		RETURNING token_budget, tokens_used`,
		req.TokensConsumed, licKey,
	).Scan(&tokenBudget, &tokensUsed)

	if err != nil {
		// Vérifier si c'est un dépassement ou une licence inexistante
		var currentUsed, currentBudget int64
		checkErr := h.db.QueryRow(r.Context(),
			"SELECT token_budget, tokens_used FROM licenses WHERE license_key=$1",
			licKey,
		).Scan(&currentBudget, &currentUsed)

		if checkErr != nil {
			writeError(w, r, http.StatusNotFound, "not_found", "Licence introuvable")
			return
		}

		writeJSON(w, http.StatusPaymentRequired, map[string]interface{}{
			"accepted": false,
			"reason":   "quota_exceeded",
			"tokens_remaining": func() int64 {
				if currentBudget == -1 {
					return -1
				}
				r := currentBudget - currentUsed
				if r < 0 {
					return 0
				}
				return r
			}(),
		})
		return
	}

	// Insérer dans l'historique d'usage
	_, logErr := h.db.Exec(r.Context(), `
		INSERT INTO token_usage (license_key, host_id, action, tokens_consumed, job_id, executed_at)
		VALUES ($1, $2, $3, $4, $5, NOW())`,
		licKey, req.HostID, req.Action, req.TokensConsumed, req.JobID,
	)
	if logErr != nil {
		h.log.Error("log token_usage", zap.Error(logErr))
	}

	var remaining int64
	if tokenBudget == -1 {
		remaining = -1
	} else {
		remaining = tokenBudget - tokensUsed
		if remaining < 0 {
			remaining = 0
		}
	}

	// Alerte low balance si < 10% du budget
	lowBalance := tokenBudget > 0 && remaining < tokenBudget/10

	h.log.Debug("tokens consommés",
		zap.String("license_key", req.LicenseKey),
		zap.String("action", req.Action),
		zap.Int("consumed", req.TokensConsumed),
		zap.Int64("remaining", remaining),
	)

	writeJSON(w, http.StatusOK, model.ConsumeTokenResponse{
		Accepted:        true,
		TokensRemaining: remaining,
		LowBalanceAlert: lowBalance,
	})
}

// ─────────────────────────────────────────────
// GET /v1/tokens/usage/:key
// ─────────────────────────────────────────────

func (h *TokenHandler) Usage(w http.ResponseWriter, r *http.Request) {
	key, err := parseUUID(chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_key", "UUID invalide")
		return
	}

	// Paramètres temporels
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	groupBy := r.URL.Query().Get("group_by") // action | host | day

	var fromTime, toTime time.Time
	if from != "" {
		fromTime, _ = time.Parse(time.RFC3339, from)
	} else {
		fromTime = time.Now().AddDate(0, -1, 0) // dernier mois par défaut
	}
	if to != "" {
		toTime, _ = time.Parse(time.RFC3339, to)
	} else {
		toTime = time.Now()
	}

	// Agrégation selon group_by
	var groupExpr, labelExpr string
	switch groupBy {
	case "host":
		groupExpr = "host_id"
		labelExpr = "host_id"
	case "day":
		groupExpr = "DATE(executed_at)"
		labelExpr = "DATE(executed_at)::text"
	default: // action
		groupExpr = "action"
		labelExpr = "action"
	}

	rows, err := h.db.Query(r.Context(), `
		SELECT `+labelExpr+`, SUM(tokens_consumed), COUNT(*)
		FROM token_usage
		WHERE license_key = $1
		  AND executed_at BETWEEN $2 AND $3
		GROUP BY `+groupExpr+`
		ORDER BY SUM(tokens_consumed) DESC`,
		key, fromTime, toTime,
	)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	defer rows.Close()

	type breakdown struct {
		Key    string `json:"key"`
		Tokens int64  `json:"tokens"`
		Calls  int64  `json:"calls"`
	}

	var total int64
	var items []breakdown
	for rows.Next() {
		var item breakdown
		if err := rows.Scan(&item.Key, &item.Tokens, &item.Calls); err != nil {
			continue
		}
		total += item.Tokens
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"license_key": key.String(),
		"period":      map[string]string{"from": fromTime.Format(time.RFC3339), "to": toTime.Format(time.RFC3339)},
		"total_consumed": total,
		"breakdown":      items,
	})
}
