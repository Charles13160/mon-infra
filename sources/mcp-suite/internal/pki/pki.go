package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// CA représente l'autorité de certification interne felfoldy
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	certPEM []byte
}

// LoadCA charge la CA depuis le disque
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("lecture CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("lecture CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("CA cert PEM invalide")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("CA key PEM invalide")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// InitCA crée une nouvelle CA si elle n'existe pas encore
func InitCA(certPath, keyPath string) error {
	// Vérifier si déjà existant
	if _, err := os.Stat(certPath); err == nil {
		return nil // déjà en place
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("génération clé CA: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:  []string{"felfoldy.fr"},
			CommonName:    "MCP Internal CA",
			Country:       []string{"FR"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 ans
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("création cert CA: %w", err)
	}

	// Écrire cert
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("écriture CA cert: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Écrire clé — permissions strictes
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("écriture CA key: %w", err)
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

// IssuedCert résultat d'une émission de certificat Worker
type IssuedCert struct {
	CertPEM      []byte
	SerialNumber string
	ExpiresAt    time.Time
}

// IssueWorkerCert émet un certificat mTLS pour un Worker
func (ca *CA) IssueWorkerCert(hostID string, ttlDays int) (*IssuedCert, error) {
	workerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("génération clé Worker: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("génération serial: %w", err)
	}

	expiry := time.Now().AddDate(0, 0, ttlDays)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"felfoldy.fr"},
			CommonName:   fmt.Sprintf("worker:%s", hostID),
		},
		NotBefore: time.Now(),
		NotAfter:  expiry,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &workerKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("création cert Worker: %w", err)
	}

	// Encoder cert + clé privée Worker en PEM (bundle)
	var certPEM []byte
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(workerKey),
	})...)

	return &IssuedCert{
		CertPEM:      certPEM,
		SerialNumber: fmt.Sprintf("0x%X", serial),
		ExpiresAt:    expiry,
	}, nil
}

// CACertPEM retourne le PEM du certificat CA (public)
func (ca *CA) CACertPEM() []byte {
	return ca.certPEM
}

// VerifyWorkerCert vérifie qu'un certificat est signé par cette CA
func (ca *CA) VerifyWorkerCert(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("PEM invalide")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificat: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}
