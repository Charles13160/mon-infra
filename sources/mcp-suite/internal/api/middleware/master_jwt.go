package middleware

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// MasterJWTAuth valide que chaque requête entrante sur le worker
// est bien signée par le mcp-master (JWT RSA256)
type MasterJWTAuth struct {
	mu        sync.RWMutex
	publicKey *rsa.PublicKey
	keyPath   string
	log       *zap.Logger
}

func NewMasterJWTAuth(masterPubKeyPath string, log *zap.Logger) *MasterJWTAuth {
	m := &MasterJWTAuth{
		keyPath: masterPubKeyPath,
		log:     log,
	}
	if err := m.loadKey(); err != nil {
		log.Warn("MasterJWTAuth: clé publique absente — register requis",
			zap.String("path", masterPubKeyPath))
	}
	return m
}

func (m *MasterJWTAuth) loadKey() error {
	data, err := os.ReadFile(m.keyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("PEM decode failed")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("not an RSA public key")
	}
	m.mu.Lock()
	m.publicKey = rsaKey
	m.mu.Unlock()
	return nil
}

// UpdateKey recharge la clé depuis un PEM reçu lors du register
func (m *MasterJWTAuth) UpdateKey(pemData string) error {
	if err := os.WriteFile(m.keyPath, []byte(pemData), 0600); err != nil {
		return fmt.Errorf("write master public key: %w", err)
	}
	return m.loadKey()
}

// Middleware HTTP — bloque toute requête sans JWT valide signé par le master
func (m *MasterJWTAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		pubKey := m.publicKey
		m.mu.RUnlock()

		if pubKey == nil {
			http.Error(w,
				`{"error":"worker_not_registered","message":"POST /worker/register on master first"}`,
				http.StatusServiceUnavailable)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w,
				`{"error":"missing_authorization","message":"Bearer JWT required"}`,
				http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pubKey, nil
		})
		if err != nil || !token.Valid {
			m.log.Warn("MasterJWTAuth: JWT invalide",
				zap.String("remote", r.RemoteAddr),
				zap.Error(err))
			http.Error(w,
				`{"error":"invalid_token","message":"JWT invalid or expired"}`,
				http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, `{"error":"invalid_claims"}`, http.StatusUnauthorized)
			return
		}
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				http.Error(w, `{"error":"token_expired"}`, http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
