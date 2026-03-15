package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/felfoldy/mcp-suite/internal/api"
	"github.com/felfoldy/mcp-suite/internal/config"
	"github.com/felfoldy/mcp-suite/internal/db"
	mcpjwt "github.com/felfoldy/mcp-suite/internal/jwt"
	"github.com/felfoldy/mcp-suite/internal/pki"
	"github.com/felfoldy/mcp-suite/internal/webhook"
)

var (
	version   = "1.0.0"
	buildHash = "chat2"
)

func main() {
	log, _ := zap.NewProduction()
	defer log.Sync()

	log.Info("MCP License Server démarrage", zap.String("version", version))

	cfg, err := config.Load()
	if err != nil {
		log.Fatal("chargement config", zap.Error(err))
	}

	ctx := context.Background()
	pool, err := db.New(ctx, cfg.Database, log)
	if err != nil {
		log.Fatal("connexion PostgreSQL", zap.Error(err))
	}
	defer pool.Close()

	caDir := filepath.Dir(cfg.PKI.CACertPath)
	if err := os.MkdirAll(caDir, 0700); err != nil {
		log.Fatal("création répertoire PKI", zap.Error(err))
	}
	if err := pki.InitCA(cfg.PKI.CACertPath, cfg.PKI.CAKeyPath); err != nil {
		log.Fatal("initialisation CA", zap.Error(err))
	}
	ca, err := pki.LoadCA(cfg.PKI.CACertPath, cfg.PKI.CAKeyPath)
	if err != nil {
		log.Fatal("chargement CA", zap.Error(err))
	}
	log.Info("PKI CA chargée")

	jwtMgr, err := mcpjwt.NewManager(cfg.JWT.KeysDir)
	if err != nil {
		log.Fatal("initialisation JWT manager", zap.Error(err))
	}
	log.Info("JWT RS256 actif", zap.String("kid", jwtMgr.ActiveKID()))

	pusher := webhook.NewPusher(cfg.Webhook.TimeoutSec, cfg.Webhook.MaxRetries, log)
	handler := api.NewRouter(cfg, pool, jwtMgr, ca, pusher, log, version)

	go runExpirationCron(ctx, pool, log)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("License Server en écoute", zap.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("erreur serveur HTTP", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Info("Arrêt gracieux...")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv.Shutdown(ctxShutdown)
	log.Info("License Server arrêté")
}

func runExpirationCron(ctx context.Context, pool *pgxpool.Pool, log *zap.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tag, err := pool.Exec(ctx,
				"UPDATE licenses SET status='expired', updated_at=NOW() WHERE status='active' AND expiry_at IS NOT NULL AND expiry_at < NOW()",
			)
			if err != nil {
				log.Error("cron expiration", zap.Error(err))
				continue
			}
			if tag.RowsAffected() > 0 {
				log.Info("licences expirées", zap.Int64("count", tag.RowsAffected()))
			}
		}
	}
}
