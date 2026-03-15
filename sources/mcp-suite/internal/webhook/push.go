package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// RevocationPayload envoyé aux Masters lors d'une révocation
type RevocationPayload struct {
	Event      string    `json:"event"`       // "license.revoked"
	LicenseKey string    `json:"license_key"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
}

// Pusher gère l'envoi des webhooks de révocation
type Pusher struct {
	client     *http.Client
	maxRetries int
	log        *zap.Logger
}

func NewPusher(timeoutSec, maxRetries int, log *zap.Logger) *Pusher {
	return &Pusher{
		client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
		maxRetries: maxRetries,
		log:        log,
	}
}

// Push envoie un signal de révocation à une URL Master avec retry backoff
// Retourne le nombre de tentatives effectuées et l'erreur finale si échec
func (p *Pusher) Push(ctx context.Context, targetURL, secret string, payload RevocationPayload) (int, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("serialisation payload: %w", err)
	}

	var lastErr error
	for attempt := 1; attempt <= p.maxRetries; attempt++ {
		if err := p.send(ctx, targetURL, secret, body); err != nil {
			lastErr = err
			p.log.Warn("webhook révocation échoué",
				zap.String("url", targetURL),
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
			// Backoff exponentiel : 1s, 2s, 4s, 8s, 16s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			select {
			case <-ctx.Done():
				return attempt, ctx.Err()
			case <-time.After(backoff):
			}
			continue
		}

		p.log.Info("webhook révocation envoyé",
			zap.String("url", targetURL),
			zap.Int("attempt", attempt),
		)
		return attempt, nil
	}

	return p.maxRetries, fmt.Errorf("échec après %d tentatives: %w", p.maxRetries, lastErr)
}

func (p *Pusher) send(ctx context.Context, url, secret string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCP-Event", "license.revoked")

	// Signature HMAC-SHA256 du body
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-MCP-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
