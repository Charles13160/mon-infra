package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// KeyPair représente une paire de clés RS256 active
type KeyPair struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	PublicPEM  []byte
}

// Manager gère les clés JWT RS256
type Manager struct {
	active  *KeyPair
	keysDir string
}

// NewManager charge ou génère les clés RS256
func NewManager(keysDir string) (*Manager, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("création répertoire clés: %w", err)
	}

	m := &Manager{keysDir: keysDir}

	// Chercher clé active existante
	activeKeyPath := filepath.Join(keysDir, "active.kid")
	if data, err := os.ReadFile(activeKeyPath); err == nil {
		kid := string(data)
		if kp, err := m.loadKey(kid); err == nil {
			m.active = kp
			return m, nil
		}
	}

	// Générer nouvelle clé
	kp, err := m.generateKey()
	if err != nil {
		return nil, err
	}
	m.active = kp

	// Sauvegarder le KID actif
	if err := os.WriteFile(activeKeyPath, []byte(kp.KID), 0600); err != nil {
		return nil, fmt.Errorf("sauvegarde KID actif: %w", err)
	}

	return m, nil
}

// generateKey génère une nouvelle paire RS256
func (m *Manager) generateKey() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("génération clé RS256: %w", err)
	}

	kid := fmt.Sprintf("kid-%s-%s", time.Now().Format("20060102"), uuid.New().String()[:8])

	// Sauvegarder clé privée (permissions strictes)
	privPath := filepath.Join(m.keysDir, kid+".key")
	privFile, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("écriture clé privée: %w", err)
	}
	defer privFile.Close()
	if err := pem.Encode(privFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		return nil, err
	}

	// Sauvegarder clé publique
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal clé publique: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath := filepath.Join(m.keysDir, kid+".pub")
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		return nil, fmt.Errorf("écriture clé publique: %w", err)
	}

	return &KeyPair{
		KID:       kid,
		PrivateKey: key,
		PublicKey: &key.PublicKey,
		PublicPEM: pubPEM,
	}, nil
}

// loadKey charge une paire de clés depuis le disque par KID
func (m *Manager) loadKey(kid string) (*KeyPair, error) {
	privPEM, err := os.ReadFile(filepath.Join(m.keysDir, kid+".key"))
	if err != nil {
		return nil, fmt.Errorf("lecture clé privée: %w", err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(m.keysDir, kid+".pub"))
	if err != nil {
		return nil, fmt.Errorf("lecture clé publique: %w", err)
	}

	privBlock, _ := pem.Decode(privPEM)
	privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		KID:       kid,
		PrivateKey: privKey,
		PublicKey: &privKey.PublicKey,
		PublicPEM: pubPEM,
	}, nil
}

// ActiveKID retourne le KID actif
func (m *Manager) ActiveKID() string {
	return m.active.KID
}

// ActivePublicPEM retourne la clé publique PEM active
func (m *Manager) ActivePublicPEM() []byte {
	return m.active.PublicPEM
}

// ─────────────────────────────────────────────
// Émission de JWT
// ─────────────────────────────────────────────

// LicenseClaims — JWT émis pour une licence (distribué au Master)
type LicenseClaims struct {
	LicenseKey string   `json:"license_key"`
	CustomerID string   `json:"customer_id"`
	Plan       string   `json:"plan"`
	Modules    []string `json:"modules"`
	MaxHosts   int      `json:"max_hosts"`
	jwt.RegisteredClaims
}

// ActionClaims — JWT émis par le Master pour une action Worker (TTL 5min)
type ActionClaims struct {
	HostID string `json:"host_id"`
	Action string `json:"action"`
	Scope  string `json:"scope"`
	jwt.RegisteredClaims
}

// IssueLicenseJWT émet un JWT RS256 pour une licence
func (m *Manager) IssueLicenseJWT(licenseKey, customerID, plan string, modules []string, maxHosts int) (string, error) {
	now := time.Now()
	claims := LicenseClaims{
		LicenseKey: licenseKey,
		CustomerID: customerID,
		Plan:       plan,
		Modules:    modules,
		MaxHosts:   maxHosts,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       uuid.New().String(),
			IssuedAt: jwt.NewNumericDate(now),
			// Pas d'expiry sur le JWT licence — c'est la DB qui fait foi
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.active.KID

	return token.SignedString(m.active.PrivateKey)
}

// IssueActionJWT émet un JWT RS256 pour une action (TTL configurable)
func (m *Manager) IssueActionJWT(hostID, action, scope string, ttlMinutes int) (string, error) {
	now := time.Now()
	claims := ActionClaims{
		HostID: hostID,
		Action: action,
		Scope:  scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // jti unique — anti-replay
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttlMinutes) * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.active.KID

	return token.SignedString(m.active.PrivateKey)
}

// ─────────────────────────────────────────────
// Validation de JWT
// ─────────────────────────────────────────────

// ValidateActionJWT valide un JWT d'action (utilisé par le Worker)
func ValidateActionJWT(tokenStr string, publicKeyPEM []byte) (*ActionClaims, error) {
	pubBlock, _ := pem.Decode(publicKeyPEM)
	if pubBlock == nil {
		return nil, fmt.Errorf("clé publique PEM invalide")
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse clé publique: %w", err)
	}
	rsaKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("clé publique n'est pas RSA")
	}

	token, err := jwt.ParseWithClaims(tokenStr, &ActionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("algorithme inattendu: %v", t.Header["alg"])
		}
		return rsaKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("JWT invalide: %w", err)
	}

	claims, ok := token.Claims.(*ActionClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("claims JWT invalides")
	}

	return claims, nil
}

// ValidateAdminJWT valide un JWT admin (HMAC-SHA256)
func ValidateAdminJWT(tokenStr, secret string) error {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("algorithme inattendu: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return fmt.Errorf("JWT admin invalide")
	}
	return nil
}
