package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/felfoldy/mcp-suite/internal/api/handlers"
	"github.com/felfoldy/mcp-suite/internal/api/middleware"
	"github.com/felfoldy/mcp-suite/internal/config"
	mcpjwt "github.com/felfoldy/mcp-suite/internal/jwt"
	"github.com/felfoldy/mcp-suite/internal/pki"
	"github.com/felfoldy/mcp-suite/internal/webhook"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewRouter(
	cfg *config.Config,
	db *pgxpool.Pool,
	jwtMgr *mcpjwt.Manager,
	ca *pki.CA,
	pusher *webhook.Pusher,
	log *zap.Logger,
	version string,
) http.Handler {
	r := chi.NewRouter()

	r.Use(chimiddleware.RealIP)
	r.Use(chimiddleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(chimiddleware.Logger)

	licHandler   := handlers.NewLicenseHandler(db, jwtMgr, pusher, log)
	hostHandler  := handlers.NewHostHandler(db, ca, cfg.PKI.CertTTLDays, jwtMgr.ActivePublicPEM(), log)
	tokenHandler := handlers.NewTokenHandler(db, log)
	pkiHandler   := handlers.NewPKIHandler(db, jwtMgr, version)
	syncHandler  := handlers.NewSyncHandler(
		db,
		cfg.Baserow.URL,
		cfg.Baserow.Token,
		cfg.JWT.AdminSecret,
		cfg.Baserow.LicensesTableID,
		cfg.Baserow.CustomersTableID,
		log,
	)

	adminAuth := middleware.AdminAuth(cfg.JWT.AdminSecret, log)

	r.Route("/v1", func(r chi.Router) {

		// Public
		r.Get("/health", pkiHandler.Health)
		r.Get("/pki/public-key", pkiHandler.PublicKey)

		// Admin
		r.Group(func(r chi.Router) {
			r.Use(adminAuth)
			r.Post("/licenses", licHandler.Create)
			r.Get("/licenses/{key}", licHandler.Get)
			r.Post("/licenses/{key}/revoke", licHandler.Revoke)
			r.Post("/licenses/{key}/renew", licHandler.Renew)
			r.Delete("/hosts/{host_id}", hostHandler.Revoke)
			r.Get("/tokens/usage/{key}", tokenHandler.Usage)
			r.Post("/sync/baserow", syncHandler.SyncFromBaserow)
		})

		// Master
		r.Group(func(r chi.Router) {
			r.Use(adminAuth)
			r.Get("/licenses/{key}/status", licHandler.Status)
			r.Post("/tokens/consume", tokenHandler.Consume)
		})

		// Worker
		r.Group(func(r chi.Router) {
			r.Use(middleware.LicenseKeyAuth)
			r.Post("/hosts/register", hostHandler.Register)
		})

		r.Get("/hosts/{host_id}/cert", hostHandler.RenewCert)
		r.Post("/hosts/{host_id}/heartbeat", hostHandler.Heartbeat)
		
		// Webhook Baserow (public, pas d'auth pour le moment - TODO: ajouter validation signature)
		r.Post("/sync/baserow/webhook", syncHandler.WebhookFromBaserow)
	})

	return r
}
