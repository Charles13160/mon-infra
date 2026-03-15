package model

import (
	"time"

	"github.com/google/uuid"
)

type PlanType string
const (
	PlanFreemium   PlanType = "freemium"
	PlanStarter    PlanType = "starter"
	PlanPro        PlanType = "pro"
	PlanEnterprise PlanType = "enterprise"
	PlanCustom     PlanType = "custom"
)

type BillingCycle string
const (
	BillingTrial   BillingCycle = "trial"
	BillingMonthly BillingCycle = "monthly"
	BillingAnnual  BillingCycle = "annual"
	BillingPrepaid BillingCycle = "prepaid"
)

type LicenseStatus string
const (
	StatusActive    LicenseStatus = "active"
	StatusSuspended LicenseStatus = "suspended"
	StatusRevoked   LicenseStatus = "revoked"
	StatusExpired   LicenseStatus = "expired"
)

type HostStatus string
const (
	HostActive  HostStatus = "active"
	HostRevoked HostStatus = "revoked"
)

type ModuleType string
const (
	ModuleAudit        ModuleType = "audit"
	ModuleSurveillance ModuleType = "surveillance"
	ModuleBackup       ModuleType = "backup"
	ModuleModification ModuleType = "modification"
	ModuleCreation     ModuleType = "creation"
	ModuleSuper        ModuleType = "super"
)

type RevocationReason string
const (
	RevNonPayment  RevocationReason = "non_payment"
	RevManualAdmin RevocationReason = "manual_admin"
	RevAbuse       RevocationReason = "abuse"
	RevExpired     RevocationReason = "expired"
	RevFraud       RevocationReason = "fraud"
)

type Customer struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Email         string    `json:"email"`
	Company       string    `json:"company,omitempty"`
	WebhookURL    string    `json:"webhook_url,omitempty"`
	WebhookSecret string    `json:"-"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type License struct {
	LicenseKey         uuid.UUID    `json:"license_key,omitempty"`
	CustomerID         uuid.UUID    `json:"customer_id"`
	Plan               PlanType     `json:"plan"`
	Modules            []ModuleType `json:"modules"`
	MaxHosts           int          `json:"max_hosts"`
	TokenBudget        int64        `json:"token_budget"`
	TokensUsed         int64        `json:"tokens_used"`
	ExpiryAt           *time.Time   `json:"expiry_at,omitempty"`
	BillingCycle       BillingCycle `json:"billing_cycle"`
	Status             LicenseStatus `json:"status"`
	JWTKid             string       `json:"jwt_kid"`
	WorkerBinaryHash   string       `json:"worker_binary_hash,omitempty"`
	CurrentPeriodStart *time.Time   `json:"current_period_start,omitempty"`
	CurrentPeriodEnd   *time.Time   `json:"current_period_end,omitempty"`
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
}

type Host struct {
	ID           uuid.UUID  `json:"id"`
	HostID       string     `json:"host_id"`
	LicenseKey   uuid.UUID  `json:"license_key"`
	Fingerprint  string     `json:"fingerprint"`
	CertSerial   string     `json:"cert_serial,omitempty"`
	CertExpiry   *time.Time `json:"cert_expiry,omitempty"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	Status       HostStatus `json:"status"`
	RegisteredAt time.Time  `json:"registered_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type ErrorResponse struct {
	Error     string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type CreateLicenseRequest struct {
	CustomerID   uuid.UUID    `json:"customer_id"`
	Plan         PlanType     `json:"plan"`
	Modules      []ModuleType `json:"modules"`
	MaxHosts     int          `json:"max_hosts"`
	TokenBudget  int64        `json:"token_budget"`
	BillingCycle BillingCycle `json:"billing_cycle"`
	ExpiryAt     *time.Time   `json:"expiry_at,omitempty"`
}

type CreateLicenseResponse struct {
	LicenseKey string    `json:"license_key"`
	JWTKid     string    `json:"jwt_kid"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
}

type LicenseSummary struct {
	LicenseKey       string        `json:"license_key"`
	CustomerEmail    string        `json:"customer_email"`
	CustomerName     string        `json:"customer_name"`
	Plan             PlanType      `json:"plan"`
	Modules          []ModuleType  `json:"modules"`
	Status           LicenseStatus `json:"status"`
	TokenBudget      int64         `json:"token_budget"`
	TokensUsed       int64         `json:"tokens_used"`
	TokensRemaining  int64         `json:"tokens_remaining"`
	MaxHosts         int           `json:"max_hosts"`
	ActiveHosts      int           `json:"active_hosts"`
	ExpiryAt         *time.Time    `json:"expiry_at,omitempty"`
	BillingCycle     BillingCycle  `json:"billing_cycle"`
	CurrentPeriodEnd *time.Time    `json:"current_period_end,omitempty"`
	CreatedAt        time.Time     `json:"created_at"`
}

type ValidateResponse struct {
	Valid            bool          `json:"valid"`
	LicenseKey       string        `json:"license_key,omitempty"`
	Plan             PlanType      `json:"plan,omitempty"`
	Modules          []ModuleType  `json:"modules,omitempty"`
	Status           LicenseStatus `json:"status,omitempty"`
	TokensRemaining  int64         `json:"tokens_remaining,omitempty"`
	MaxHosts         int           `json:"max_hosts,omitempty"`
	ExpiryAt         *time.Time    `json:"expiry_at,omitempty"`
	JWTKid           string        `json:"jwt_kid,omitempty"`
	Reason           string        `json:"reason,omitempty"`
}

type RegisterHostRequest struct {
	HostID        string `json:"host_id"`
	Fingerprint   string `json:"fingerprint"`
	WorkerVersion string `json:"worker_version"`
}

type RegisterHostResponse struct {
	HostID       string    `json:"host_id"`
	CertPEM      string    `json:"cert_pem"`
	CACertPEM    string    `json:"ca_cert_pem"`
	CertSerial   string    `json:"cert_serial"`
	CertExpiry   time.Time `json:"cert_expiry"`
	MasterPubKey string    `json:"master_public_key_pem"`
}

type ConsumeTokenRequest struct {
	LicenseKey     string `json:"license_key"`
	HostID         string `json:"host_id"`
	Action         string `json:"action"`
	TokensConsumed int    `json:"tokens_consumed"`
	JobID          string `json:"job_id,omitempty"`
}

type ConsumeTokenResponse struct {
	Accepted        bool  `json:"accepted"`
	TokensRemaining int64 `json:"tokens_remaining"`
	LowBalanceAlert bool  `json:"low_balance_alert"`
}

type RevokeRequest struct {
	Reason      RevocationReason `json:"reason"`
	InitiatedBy string           `json:"initiated_by"`
	Notes       string           `json:"notes,omitempty"`
}

type RenewRequest struct {
	BillingCycle   BillingCycle `json:"billing_cycle"`
	TokensToCredit int64        `json:"tokens_to_credit"`
	NewPeriodEnd   time.Time    `json:"new_period_end"`
	ExternalRef    string       `json:"external_ref,omitempty"`
}

func (l *License) HasModule(m ModuleType) bool {
	for _, mod := range l.Modules {
		if mod == m {
			return true
		}
	}
	return false
}

func (l *License) TokensRemaining() int64 {
	if l.TokenBudget == -1 {
		return -1
	}
	r := l.TokenBudget - l.TokensUsed
	if r < 0 {
		return 0
	}
	return r
}

func (l *License) IsLowBalance() bool {
	if l.TokenBudget <= 0 {
		return false
	}
	return l.TokensRemaining() < l.TokenBudget/10
}
