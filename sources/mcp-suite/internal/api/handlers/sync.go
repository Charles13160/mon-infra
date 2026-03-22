package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/virtusia/mcp-suite/internal/baserow"
	"github.com/virtusia/mcp-suite/internal/tokens"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type SyncHandler struct {
	db                  *pgxpool.Pool
	log                 *zap.Logger
	baserowClient       *baserow.Client
	tokenSecret         string
	licensesTableID     int
	customersTableID    int
	masterWebhookURL    string // ex: http://100.64.0.3:8082/webhook/revoke
	masterWebhookSecret string // WEBHOOK_SECRET du mcp-master
}

func NewSyncHandler(
	db *pgxpool.Pool,
	baserowURL, baserowToken, tokenSecret string,
	licensesTableID, customersTableID int,
	log *zap.Logger,
) *SyncHandler {
	return &SyncHandler{
		db:               db,
		log:              log,
		baserowClient:    baserow.NewClient(baserowURL, baserowToken),
		tokenSecret:      tokenSecret,
		licensesTableID:  licensesTableID,
		customersTableID: customersTableID,
	}
}

// SetMasterWebhook configure l'URL et le secret du mcp-master pour l'invalidation de cache
func (h *SyncHandler) SetMasterWebhook(webhookURL, webhookSecret string) {
	h.masterWebhookURL = webhookURL
	h.masterWebhookSecret = webhookSecret
	if webhookURL != "" {
		h.log.Info("master webhook configured", zap.String("url", webhookURL))
	}
}

type SyncResponse struct {
	Success          bool     `json:"success"`
	CustomersAdded   int      `json:"customers_added"`
	CustomersUpdated int      `json:"customers_updated"`
	LicensesAdded    int      `json:"licenses_added"`
	LicensesUpdated  int      `json:"licenses_updated"`
	Errors           []string `json:"errors,omitempty"`
	Duration         string   `json:"duration"`
}

// SyncFromBaserow - endpoint POST /v1/sync/baserow
func (h *SyncHandler) SyncFromBaserow(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	response := &SyncResponse{
		Success: true,
		Errors:  []string{},
	}

	customersAdded, customersUpdated, err := h.syncCustomers(ctx)
	if err != nil {
		h.log.Error("sync customers failed", zap.Error(err))
		response.Errors = append(response.Errors, fmt.Sprintf("customers: %v", err))
		response.Success = false
	}
	response.CustomersAdded = customersAdded
	response.CustomersUpdated = customersUpdated

	licensesAdded, licensesUpdated, err := h.syncLicenses(ctx)
	if err != nil {
		h.log.Error("sync licenses failed", zap.Error(err))
		response.Errors = append(response.Errors, fmt.Sprintf("licenses: %v", err))
		response.Success = false
	}
	response.LicensesAdded = licensesAdded
	response.LicensesUpdated = licensesUpdated

	response.Duration = time.Since(start).String()

	h.log.Info("baserow sync complete",
		zap.Int("customers_added", customersAdded),
		zap.Int("customers_updated", customersUpdated),
		zap.Int("licenses_added", licensesAdded),
		zap.Int("licenses_updated", licensesUpdated),
		zap.String("duration", response.Duration),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *SyncHandler) syncCustomers(ctx context.Context) (added, updated int, err error) {
	rows, err := h.baserowClient.ListCustomers(ctx, h.customersTableID)
	if err != nil {
		return 0, 0, err
	}

	for _, row := range rows {
		customerEmail := row.Clients
		if customerEmail == "" {
			continue
		}

		var exists bool
		err := h.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM customers WHERE email = $1)", customerEmail).Scan(&exists)
		if err != nil {
			h.log.Error("check customer exists", zap.Error(err))
			continue
		}

		if exists {
			updated++
		} else {
			_, err = h.db.Exec(ctx, `
				INSERT INTO customers (id, email, webhook_url, webhook_secret, created_at, updated_at)
				VALUES (gen_random_uuid(), $1, '', '', NOW(), NOW())
			`, customerEmail)
			if err != nil {
				h.log.Error("insert customer", zap.Error(err), zap.String("email", customerEmail))
				continue
			}
			added++
		}
	}

	return added, updated, nil
}

func (h *SyncHandler) syncLicenses(ctx context.Context) (added, updated int, err error) {
	rows, err := h.baserowClient.ListLicenses(ctx, h.licensesTableID)
	if err != nil {
		return 0, 0, err
	}

	for _, row := range rows {
		if row.UUID == "" {
			continue
		}

		var expiryAt *time.Time
		if row.DateLimite != "" {
			t, err := time.Parse("2006-01-02", row.DateLimite)
			if err == nil {
				expiryAt = &t
			}
		}

		status := "revoked"
		if row.Active {
			status = "active"
		}

		licenseToken := tokens.GenerateLicenseToken(row.UUID, h.tokenSecret)

		plan := "starter"
		for _, service := range row.MCPServices {
			if strings.Contains(strings.ToLower(service.Value), "master kit") {
				plan = "pro"
				break
			}
		}

		var exists bool
		err := h.db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM licenses WHERE license_key = $1)", row.UUID).Scan(&exists)
		if err != nil {
			h.log.Error("check license exists", zap.Error(err))
			continue
		}

		if exists {
			_, err = h.db.Exec(ctx, `
				UPDATE licenses
				SET plan = $1, status = $2, expiry_at = $3, license_token = $4, updated_at = NOW()
				WHERE license_key = $5
			`, plan, status, expiryAt, licenseToken, row.UUID)
			if err != nil {
				h.log.Error("update license", zap.Error(err), zap.String("uuid", row.UUID))
				continue
			}
			updated++
		} else {
			customerID := "7235841d-d4e1-481f-8560-4399502e1c7e"
			jwtKid := fmt.Sprintf("sync-%s", row.UUID[:8])

			_, err = h.db.Exec(ctx, `
				INSERT INTO licenses (license_key, customer_id, plan, status, expiry_at, license_token, billing_cycle, jwt_kid, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, 'monthly', $7, NOW(), NOW())
			`, row.UUID, customerID, plan, status, expiryAt, licenseToken, jwtKid)
			if err != nil {
				h.log.Error("insert license", zap.Error(err), zap.String("uuid", row.UUID))
				continue
			}
			added++
		}
	}

	return added, updated, nil
}

type WebhookPayload struct {
	TableID    int                      `json:"table_id"`
	DatabaseID int                      `json:"database_id"`
	Event      string                   `json:"event"`
	Items      []map[string]interface{} `json:"items"`
}

// WebhookFromBaserow - endpoint POST /v1/sync/baserow/webhook
func (h *SyncHandler) WebhookFromBaserow(w http.ResponseWriter, r *http.Request) {
	var payload WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.log.Error("webhook decode error", zap.Error(err))
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	h.log.Info("baserow webhook received",
		zap.Int("table_id", payload.TableID),
		zap.String("event", payload.Event),
		zap.Int("items", len(payload.Items)),
	)

	ctx := r.Context()

	if payload.TableID == h.licensesTableID {
		for _, item := range payload.Items {
			h.processLicenseWebhook(ctx, item, payload.Event)
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

// processLicenseWebhook traite un événement Baserow pour une licence :
// - Met à jour status + expiry_at en DB
// - Invalide le cache du mcp-master via /webhook/revoke
func (h *SyncHandler) processLicenseWebhook(ctx context.Context, item map[string]interface{}, event string) {
	uuid, _ := item["UUID"].(string)
	if uuid == "" {
		return
	}

	active, _ := item["Active"].(bool)
	status := "revoked"
	if active {
		status = "active"
	}

	// Parse date_limite si présente
	var expiryAt *time.Time
	if dl, ok := item["date_limite"].(string); ok && dl != "" {
		t, err := time.Parse("2006-01-02", dl)
		if err == nil {
			expiryAt = &t
		}
	}

	licenseToken := tokens.GenerateLicenseToken(uuid, h.tokenSecret)
	jwtKid := fmt.Sprintf("sync-%s", uuid[:8])

	// UPSERT avec expiry_at
	_, err := h.db.Exec(ctx, `
		INSERT INTO licenses (license_key, customer_id, plan, status, expiry_at, license_token, billing_cycle, jwt_kid, created_at, updated_at)
		VALUES ($1, $2, 'starter', $3, $4, $5, 'monthly', $6, NOW(), NOW())
		ON CONFLICT (license_key) DO UPDATE
		SET status = $3, expiry_at = COALESCE($4, licenses.expiry_at), license_token = $5, updated_at = NOW()
	`, uuid, "7235841d-d4e1-481f-8560-4399502e1c7e", status, expiryAt, licenseToken, jwtKid)

	if err != nil {
		h.log.Error("process license webhook", zap.Error(err), zap.String("uuid", uuid))
		return
	}

	h.log.Info("license webhook processed",
		zap.String("uuid", uuid),
		zap.String("status", status),
		zap.String("event", event),
	)

	// ── Invalider le cache du mcp-master immédiatement ─────────────────
	// Envoyer /webhook/revoke même si active=true pour forcer une re-validation fraîche
	go h.notifyMasterCacheInvalidation(uuid, status)
}

// notifyMasterCacheInvalidation appelle /webhook/revoke sur le mcp-master
// pour invalider immédiatement le cache de la licence modifiée
func (h *SyncHandler) notifyMasterCacheInvalidation(licenseKey, status string) {
	if h.masterWebhookURL == "" {
		return
	}

	payload := map[string]string{
		"event":       "license.revoked",
		"license_key": licenseKey,
		"reason":      "baserow_sync_" + status,
	}

	body, _ := json.Marshal(payload)

	// Signature HMAC-SHA256 si secret configuré
	sig := ""
	if h.masterWebhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(h.masterWebhookSecret))
		mac.Write(body)
		sig = "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.masterWebhookURL, bytes.NewReader(body))
	if err != nil {
		h.log.Error("master cache invalidation request build failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if sig != "" {
		req.Header.Set("X-MCP-Signature", sig)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.log.Error("master cache invalidation request failed", zap.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		h.log.Info("master cache invalidated",
			zap.String("license_key", licenseKey[:8]+"..."),
			zap.String("status", status),
		)
	} else {
		h.log.Warn("master cache invalidation returned non-200",
			zap.Int("http_status", resp.StatusCode),
			zap.String("license_key", licenseKey[:8]+"..."),
		)
	}
}
