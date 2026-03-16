package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateLicenseToken génère un token HMAC sécurisé pour une licence
// Format: HMAC-SHA256(uuid + secret + bucket_timestamp)
// bucket_timestamp = timestamp arrondi à l'heure (3600s) pour permettre rotation douce
func GenerateLicenseToken(licenseUUID, secret string) string {
	// Bucket de 1h pour stabilité cache
	bucket := time.Now().Unix() / 3600
	
	// Données à signer
	data := fmt.Sprintf("%s:%d", licenseUUID, bucket)
	
	// HMAC-SHA256
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	hash := h.Sum(nil)
	
	// Format: lic_<hex>
	return "lic_" + hex.EncodeToString(hash)
}

// ValidateLicenseToken vérifie si un token est valide pour un UUID
// Accepte les tokens des 2 derniers buckets (2h de tolérance)
func ValidateLicenseToken(token, licenseUUID, secret string) bool {
	if len(token) < 4 || token[:4] != "lic_" {
		return false
	}
	
	currentBucket := time.Now().Unix() / 3600
	
	// Vérifier bucket actuel et précédent (tolérance 1h)
	for i := int64(0); i <= 1; i++ {
		bucket := currentBucket - i
		expectedToken := generateTokenForBucket(licenseUUID, secret, bucket)
		if token == expectedToken {
			return true
		}
	}
	
	return false
}

func generateTokenForBucket(licenseUUID, secret string, bucket int64) string {
	data := fmt.Sprintf("%s:%d", licenseUUID, bucket)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	hash := h.Sum(nil)
	return "lic_" + hex.EncodeToString(hash)
}
