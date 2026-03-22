package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"

	mcpjwt "github.com/virtusia/mcp-suite/internal/jwt"
	"github.com/virtusia/mcp-suite/internal/model"
)

type contextKey string

const (
	RequestIDKey  contextKey = "request_id"
	LicenseKeyCtx contextKey = "license_key"
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.New().String()
		ctx := context.WithValue(r.Context(), RequestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func AdminAuth(secret string, log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				writeError(w, r, http.StatusUnauthorized, "missing_token", "Authorization header requis")
				return
			}
			if err := mcpjwt.ValidateAdminJWT(token, secret); err != nil {
				log.Warn("JWT admin invalide", zap.String("ip", r.RemoteAddr))
				writeError(w, r, http.StatusUnauthorized, "invalid_token", "JWT invalide ou expiré")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func LicenseKeyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-License-Key")
		if key == "" {
			writeError(w, r, http.StatusUnauthorized, "missing_license_key", "X-License-Key header requis")
			return
		}
		ctx := context.WithValue(r.Context(), LicenseKeyCtx, key)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	reqID, _ := r.Context().Value(RequestIDKey).(string)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(model.ErrorResponse{
		Error:     code,
		Message:   msg,
		RequestID: reqID,
	})
}
