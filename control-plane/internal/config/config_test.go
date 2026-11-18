package config

import "testing"

func TestSecureDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db/kordex?sslmode=verify-full")
	t.Setenv("KORDEX_ADMIN_TOKEN", "a-long-test-token-with-32-characters")
	t.Setenv("KORDEX_LISTEN_ADDRESS", "")
	t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KORDEX_LISTEN_ADDRESS", ":8080")
	if _, err := Load(); err == nil {
		t.Fatal("accepted exposed bootstrap API")
	}
	t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "true")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KORDEX_ADMIN_TOKEN", "short")
	if _, err := Load(); err == nil {
		t.Fatal("accepted weak token")
	}
}
func TestDatabaseTLS(t *testing.T) {
	t.Setenv("KORDEX_ADMIN_TOKEN", "a-long-test-token-with-32-characters")
	t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "")
	t.Setenv("KORDEX_LISTEN_ADDRESS", "127.0.0.1:8080")
	for _, dsn := range []string{"", "mysql://db/kordex", "postgres://db/kordex?sslmode=disable"} {
		t.Setenv("DATABASE_URL", dsn)
		if _, err := Load(); err == nil {
			t.Fatalf("accepted %q", dsn)
		}
	}
}

func TestCloudRunRequiresOIDCAndDisablesBootstrap(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db/kordex?sslmode=verify-full")
	t.Setenv("KORDEX_ADMIN_TOKEN", "")
	t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "")
	t.Setenv("KORDEX_LISTEN_ADDRESS", "")
	t.Setenv("PORT", "8080")
	t.Setenv("KORDEX_OIDC_ISSUER", "https://identity.example")
	t.Setenv("KORDEX_OIDC_AUDIENCE", "kordex")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != ":8080" || cfg.AllowBootstrap {
		t.Fatal("unsafe Cloud Run config")
	}
}

func TestOIDCDoesNotShareBootstrapAuthentication(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://db/kordex?sslmode=verify-full")
	t.Setenv("KORDEX_ADMIN_TOKEN", "a-long-test-token-with-32-characters")
	t.Setenv("KORDEX_OIDC_ISSUER", "https://identity.example")
	t.Setenv("KORDEX_OIDC_AUDIENCE", "kordex")
	for _, address := range []string{"127.0.0.1:8080", ":8080"} {
		t.Run(address, func(t *testing.T) {
			t.Setenv("KORDEX_LISTEN_ADDRESS", address)
			t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "")
			cfg, err := Load()
			if err != nil || cfg.AllowBootstrap {
				t.Fatalf("OIDC listener also authorized bootstrap: allow=%v err=%v", cfg.AllowBootstrap, err)
			}
			t.Setenv("KORDEX_LOCAL_DEVELOPMENT", "true")
			if _, err := Load(); err == nil {
				t.Fatal("accepted contradictory OIDC and local-development modes")
			}
		})
	}
}

func TestSchedulerDatabaseTransportPolicy(t *testing.T) {
	for _, tc := range []struct {
		dsn          string
		local, valid bool
	}{{"postgres://localhost/test?sslmode=disable", false, false}, {"postgres://localhost/test?sslmode=verify-full", false, true}, {"postgres://localhost/test?sslmode=disable", true, true}, {"http://localhost/test", true, false}} {
		if (ValidateDatabaseURL(tc.dsn, tc.local) == nil) != tc.valid {
			t.Fatalf("database policy mismatch for local=%v", tc.local)
		}
	}
}
