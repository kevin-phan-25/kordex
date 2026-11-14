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
