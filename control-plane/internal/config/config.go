package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Address, MetricsAddress, DatabaseURL, AdminToken, ProductName string
	APIRateLimitRPS                                               float64
	APIRateLimitBurst                                             int
	LocalDevelopment                                              bool
	OIDCIssuer, OIDCAudience                                      string
	AllowBootstrap                                                bool
}

func Load() (Config, error) {
	c := Config{Address: os.Getenv("KORDEX_LISTEN_ADDRESS"), MetricsAddress: os.Getenv("KORDEX_METRICS_LISTEN_ADDRESS"), DatabaseURL: os.Getenv("DATABASE_URL"), AdminToken: os.Getenv("KORDEX_ADMIN_TOKEN"), ProductName: os.Getenv("KORDEX_PRODUCT_NAME"), LocalDevelopment: os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true"}
	c.APIRateLimitRPS, c.APIRateLimitBurst = 20, 600
	if value := os.Getenv("KORDEX_API_RATE_LIMIT_RPS"); value != "" {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || parsed <= 0 || parsed > 1000 {
			return c, fmt.Errorf("KORDEX_API_RATE_LIMIT_RPS must be greater than 0 and at most 1000")
		}
		c.APIRateLimitRPS = parsed
	}
	if value := os.Getenv("KORDEX_API_RATE_LIMIT_BURST"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100000 {
			return c, fmt.Errorf("KORDEX_API_RATE_LIMIT_BURST must be between 1 and 100000")
		}
		c.APIRateLimitBurst = parsed
	}
	c.OIDCIssuer = os.Getenv("KORDEX_OIDC_ISSUER")
	c.OIDCAudience = os.Getenv("KORDEX_OIDC_AUDIENCE")
	if port := os.Getenv("PORT"); c.Address == "" && port != "" {
		c.Address = ":" + port
	}
	if c.Address == "" {
		c.Address = "127.0.0.1:8080"
	}
	if c.MetricsAddress == "" {
		c.MetricsAddress = "127.0.0.1:9090"
	}
	if c.ProductName == "" {
		c.ProductName = "Kordex"
	}
	if (c.AdminToken != "" && (len(c.AdminToken) < 32 || strings.TrimSpace(c.AdminToken) != c.AdminToken)) || (c.AdminToken == "" && c.OIDCIssuer == "") {
		return c, fmt.Errorf("KORDEX_ADMIN_TOKEN must contain at least 32 characters without surrounding whitespace")
	}
	if err := ValidateDatabaseURL(c.DatabaseURL, c.LocalDevelopment); err != nil {
		return c, err
	}
	host, _, err := net.SplitHostPort(c.Address)
	if err != nil {
		return c, fmt.Errorf("invalid listen address: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.MetricsAddress); err != nil {
		return c, fmt.Errorf("invalid metrics listen address: %w", err)
	}
	ip := net.ParseIP(host)
	c.AllowBootstrap = c.LocalDevelopment || (ip != nil && ip.IsLoopback())
	if (c.OIDCIssuer == "") != (c.OIDCAudience == "") {
		return c, fmt.Errorf("OIDC issuer and audience must be configured together")
	}
	if c.OIDCIssuer != "" {
		issuer, err := url.Parse(c.OIDCIssuer)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
			return c, fmt.Errorf("OIDC issuer must be an HTTPS URL")
		}
	}
	if !c.LocalDevelopment && (ip == nil || !ip.IsLoopback()) && c.OIDCIssuer == "" {
		return c, fmt.Errorf("foundation admin authentication requires loopback binding; set KORDEX_LOCAL_DEVELOPMENT=true only for an isolated development network")
	}
	return c, nil
}

// ValidateDatabaseURL applies the same transport policy to API and scheduler processes.
func ValidateDatabaseURL(value string, local bool) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return fmt.Errorf("DATABASE_URL must be a PostgreSQL URL")
	}
	if !local && u.Query().Get("sslmode") != "verify-full" {
		return fmt.Errorf("database sslmode=verify-full required outside local development")
	}
	return nil
}
