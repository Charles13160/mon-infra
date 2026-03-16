package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	PKI      PKIConfig
	Webhook  WebhookConfig
	Log      LogConfig
	Baserow  BaserowConfig
}

type ServerConfig struct {
	Port int    `mapstructure:"port"`
	Env  string `mapstructure:"env"`
	Role string `mapstructure:"role"`
}

type DatabaseConfig struct {
	URL            string `mapstructure:"url"`
	MaxConns       int    `mapstructure:"max_conns"`
	MinConns       int    `mapstructure:"min_conns"`
	ConnTimeoutSec int    `mapstructure:"conn_timeout_sec"`
}

type JWTConfig struct {
	AdminSecret string `mapstructure:"admin_secret"`
	KeysDir     string `mapstructure:"keys_dir"`
	TokenTTLMin int    `mapstructure:"token_ttl_min"`
}

type PKIConfig struct {
	CAKeyPath   string `mapstructure:"ca_key_path"`
	CACertPath  string `mapstructure:"ca_cert_path"`
	CertTTLDays int    `mapstructure:"cert_ttl_days"`
}

type WebhookConfig struct {
	TimeoutSec int `mapstructure:"timeout_sec"`
	MaxRetries int `mapstructure:"max_retries"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

type BaserowConfig struct {
	URL               string `mapstructure:"url"`
	Token             string `mapstructure:"token"`
	LicensesTableID   int    `mapstructure:"licenses_table_id"`
	CustomersTableID  int    `mapstructure:"customers_table_id"`
}

func Load() (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("server.port", 8090)
	v.SetDefault("server.env", "production")
	v.SetDefault("server.role", "license-server")
	v.SetDefault("database.max_conns", 20)
	v.SetDefault("database.min_conns", 2)
	v.SetDefault("database.conn_timeout_sec", 5)
	v.SetDefault("jwt.keys_dir", "/srv/mcp-suite/certs/jwt")
	v.SetDefault("jwt.token_ttl_min", 5)
	v.SetDefault("pki.ca_cert_path", "/srv/mcp-suite/certs/ca/ca.crt")
	v.SetDefault("pki.ca_key_path", "/srv/mcp-suite/certs/ca/ca.key")
	v.SetDefault("pki.cert_ttl_days", 90)
	v.SetDefault("webhook.timeout_sec", 10)
	v.SetDefault("webhook.max_retries", 5)
	v.SetDefault("log.level", "info")
	v.SetDefault("baserow.licenses_table_id", 648)
	v.SetDefault("baserow.customers_table_id", 649)

	// Fichier config YAML (optionnel)
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("/srv/mcp-suite/config")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")
	v.ReadInConfig() // silencieux si absent

	// Variables d'environnement — binding explicite
	v.SetEnvPrefix("MCP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bindings explicites pour les variables critiques
	v.BindEnv("database.url", "MCP_DATABASE_URL")
	v.BindEnv("jwt.admin_secret", "MCP_JWT_ADMIN_SECRET")
	v.BindEnv("server.port", "MCP_SERVER_PORT")
	v.BindEnv("log.level", "MCP_LOG_LEVEL")
	v.BindEnv("baserow.url", "BASEROW_URL")
	v.BindEnv("baserow.token", "BASEROW_TOKEN")
	v.BindEnv("baserow.licenses_table_id", "BASEROW_LICENSES_TABLE_ID")
	v.BindEnv("baserow.customers_table_id", "BASEROW_CUSTOMERS_TABLE_ID")

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("erreur parsing config: %w", err)
	}

	// Fallback direct os.Getenv si Viper rate encore
	if cfg.Database.URL == "" {
		cfg.Database.URL = os.Getenv("MCP_DATABASE_URL")
	}
	if cfg.JWT.AdminSecret == "" {
		cfg.JWT.AdminSecret = os.Getenv("MCP_JWT_ADMIN_SECRET")
	}
	if cfg.Baserow.URL == "" {
		cfg.Baserow.URL = os.Getenv("BASEROW_URL")
	}
	if cfg.Baserow.Token == "" {
		cfg.Baserow.Token = os.Getenv("BASEROW_TOKEN")
	}

	if cfg.Database.URL == "" {
		return nil, fmt.Errorf("MCP_DATABASE_URL est requis")
	}
	if cfg.JWT.AdminSecret == "" {
		return nil, fmt.Errorf("MCP_JWT_ADMIN_SECRET est requis")
	}

	return &cfg, nil
}
