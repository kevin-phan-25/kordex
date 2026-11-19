package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Config struct {
	Address, MetricsAddress, DatabaseURL, AdminToken, ProductName string
	APIRateLimitRPS                                               float64
	APIRateLimitBurst                                             int
	LocalDevelopment                                              bool
	OIDCIssuer, OIDCAudience, OIDCTokenMode, OIDCAccessClientID   string
	OIDCAccessRequiredScopes                                      []string
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
	c.OIDCTokenMode = strings.TrimSpace(os.Getenv("KORDEX_OIDC_TOKEN_MODE"))
	if c.OIDCTokenMode == "" {
		c.OIDCTokenMode = "id_token"
	}
	c.OIDCAccessClientID = os.Getenv("KORDEX_OIDC_ACCESS_CLIENT_ID")
	c.OIDCAccessRequiredScopes = strings.Fields(os.Getenv("KORDEX_OIDC_ACCESS_REQUIRED_SCOPES"))
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
	// An OIDC listener must never also accept the global foundation token,
	// including after an accidental development-flag change in production.
	c.AllowBootstrap = c.OIDCIssuer == "" && (c.LocalDevelopment || (ip != nil && ip.IsLoopback()))
	if (c.OIDCIssuer == "") != (c.OIDCAudience == "") {
		return c, fmt.Errorf("OIDC issuer and audience must be configured together")
	}
	if c.OIDCTokenMode != "id_token" && c.OIDCTokenMode != "access_token" {
		return c, fmt.Errorf("KORDEX_OIDC_TOKEN_MODE must be id_token or access_token")
	}
	if c.OIDCTokenMode == "id_token" && (c.OIDCAccessClientID != "" || len(c.OIDCAccessRequiredScopes) != 0) {
		return c, fmt.Errorf("OIDC access-token client and scopes require KORDEX_OIDC_TOKEN_MODE=access_token")
	}
	if c.OIDCTokenMode == "access_token" {
		if c.OIDCIssuer == "" || !validOIDCIdentifier(c.OIDCAccessClientID) || c.OIDCAccessClientID == c.OIDCAudience {
			return c, fmt.Errorf("access-token mode requires OIDC, a distinct API audience, and KORDEX_OIDC_ACCESS_CLIENT_ID")
		}
		if len(c.OIDCAccessRequiredScopes) == 0 {
			return c, fmt.Errorf("access-token mode requires KORDEX_OIDC_ACCESS_REQUIRED_SCOPES")
		}
		seen := make(map[string]struct{}, len(c.OIDCAccessRequiredScopes))
		for _, scope := range c.OIDCAccessRequiredScopes {
			if !validOIDCScope(scope) {
				return c, fmt.Errorf("KORDEX_OIDC_ACCESS_REQUIRED_SCOPES contains an invalid scope")
			}
			if _, ok := seen[scope]; ok {
				return c, fmt.Errorf("KORDEX_OIDC_ACCESS_REQUIRED_SCOPES contains a duplicate scope")
			}
			seen[scope] = struct{}{}
		}
	}
	if c.OIDCIssuer != "" {
		if !validOIDCIdentifier(c.OIDCAudience) {
			return c, fmt.Errorf("KORDEX_OIDC_AUDIENCE must contain 1 to 256 printable characters without surrounding whitespace")
		}
		if c.LocalDevelopment {
			return c, fmt.Errorf("OIDC cannot be combined with KORDEX_LOCAL_DEVELOPMENT; use verified database TLS and OIDC-only authentication")
		}
		issuer, err := url.Parse(c.OIDCIssuer)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
			return c, fmt.Errorf("OIDC issuer must be an HTTPS URL without credentials, query, or fragment")
		}
	}
	if !c.LocalDevelopment && (ip == nil || !ip.IsLoopback()) && c.OIDCIssuer == "" {
		return c, fmt.Errorf("foundation admin authentication requires loopback binding; set KORDEX_LOCAL_DEVELOPMENT=true only for an isolated development network")
	}
	return c, nil
}

func validOIDCScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, r := range scope {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

func validOIDCIdentifier(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
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
