package store_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/store"
)

func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("CI requires KORDEX_TEST_DATABASE_URL")
		}
		t.Skip("set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The test owns the disposable database; never use a shared or production DSN.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Migrate(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	request := store.NewID()
	a, err := s.CreateOrganization(ctx, "a-"+store.NewID(), "integration", request)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateOrganization(ctx, "b-"+store.NewID(), "integration", request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateOrganization(ctx, a.Name, "integration", request); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	site, err := s.CreateSite(ctx, a.ID, "dc1", "us-east", "integration", request)
	if err != nil {
		t.Fatal(err)
	}
	items, err := s.ListSites(ctx, b.ID, 100, 0)
	if err != nil || len(items) != 0 {
		t.Fatalf("cross-organization leak: %v %v", items, err)
	}
	items, err = s.ListSites(ctx, a.ID, 100, 0)
	if err != nil || len(items) != 1 || items[0].ID != site.ID {
		t.Fatalf("missing persisted site: %v %v", items, err)
	}
	if _, err = s.CreateSite(ctx, store.NewID(), "dc2", "us-east", "integration", request); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected missing org: %v", err)
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE organization_id=$1", a.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit count=%d err=%v", count, err)
	}
	// Invalid audit identity must roll back the resource write.
	if _, err = s.CreateSite(ctx, a.ID, "rollback", "us-east", "integration", "invalid-uuid"); err == nil {
		t.Fatal("expected audit insert failure")
	}
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM sites WHERE organization_id=$1 AND name='rollback'", a.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit failure did not roll back mutation")
	}
	// Reopening a fresh pool proves state is not tied to service memory.
	restarted, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	items, err = restarted.ListSites(ctx, a.ID, 100, 0)
	if err != nil || len(items) != 1 {
		t.Fatal("state not durable across pool restart")
	}
	const token = "integration-test-token-at-least-32-characters"
	h := httpapi.New(restarted, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)))
	r := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+a.ID+"/sites", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), site.ID) {
		t.Fatalf("database-backed API: %d %s", w.Code, w.Body.String())
	}
	// A committed history edit must be rejected, then restore it for repeatable runs.
	var checksum string
	if err = s.Pool.QueryRow(ctx, "SELECT checksum FROM schema_migrations WHERE version=1").Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := s.Pool.Exec(context.Background(), "UPDATE schema_migrations SET checksum=$1 WHERE version=1", checksum); err != nil {
			t.Error(err)
		}
	}()
	if _, err = s.Pool.Exec(ctx, "UPDATE schema_migrations SET checksum='tampered' WHERE version=1"); err != nil {
		t.Fatal(err)
	}
	if err = s.Ready(ctx); err == nil {
		t.Fatal("readiness accepted changed migration history")
	}
	if err = s.Migrate(ctx); err == nil {
		t.Fatal("accepted changed migration history")
	}
}
