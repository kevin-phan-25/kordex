package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	Address, DatabaseURL, AdminToken, ProductName string
	LocalDevelopment                              bool
}

func Load() (Config, error) {
	c := Config{Address: os.Getenv("KORDEX_LISTEN_ADDRESS"), DatabaseURL: os.Getenv("DATABASE_URL"), AdminToken: os.Getenv("KORDEX_ADMIN_TOKEN"), ProductName: os.Getenv("KORDEX_PRODUCT_NAME"), LocalDevelopment: os.Getenv("KORDEX_LOCAL_DEVELOPMENT") == "true"}
	if c.Address == "" {
		c.Address = "127.0.0.1:8080"
	}
	if c.ProductName == "" {
		c.ProductName = "Kordex"
	}
	if len(c.AdminToken) < 32 || strings.TrimSpace(c.AdminToken) != c.AdminToken {
		return c, fmt.Errorf("KORDEX_ADMIN_TOKEN must contain at least 32 characters without surrounding whitespace")
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		return c, fmt.Errorf("DATABASE_URL must be a PostgreSQL URL")
	}
	host, _, err := net.SplitHostPort(c.Address)
	if err != nil {
		return c, fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if !c.LocalDevelopment && (ip == nil || !ip.IsLoopback()) {
		return c, fmt.Errorf("foundation admin authentication requires loopback binding; set KORDEX_LOCAL_DEVELOPMENT=true only for an isolated development network")
	}
	if !c.LocalDevelopment && u.Query().Get("sslmode") != "verify-full" {
		return c, fmt.Errorf("database sslmode=verify-full required outside local development")
	}
	return c, nil
}
