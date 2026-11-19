package store_test

import (
	"context"
	"crypto/sha256"
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

type postgresSubjectVerifier struct{ token string }

func (v postgresSubjectVerifier) Verify(_ context.Context, token string) (string, error) {
	if token != v.token {
		return "", errors.New("invalid integration token")
	}
	return "tenant-api-integration-user", nil
}
func (v postgresSubjectVerifier) VerifyWithExpiry(_ context.Context, token string) (string, time.Time, error) {
	if token != v.token {
		return "", time.Time{}, errors.New("invalid integration token")
	}
	return "tenant-api-integration-user", time.Now().UTC().Add(time.Hour), nil
}

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
	securityRequest := store.NewID()
	if err = s.RecordSecurityDenial(ctx, store.SecurityDenial{
		OrganizationID: b.ID, Actor: "oidc:integration-subject", Reason: "membership_denied",
		Route: "GET /v1/organizations/{organizationID}/sites", Method: "GET", RequestID: securityRequest,
	}); err != nil {
		t.Fatalf("append security denial: %v", err)
	}
	securityHighWater, err := s.SecurityAuditHighWater(ctx)
	if err != nil || securityHighWater < 1 {
		t.Fatalf("security audit high-water=%d err=%v", securityHighWater, err)
	}
	if err = s.VerifySecurityAudit(ctx); err != nil {
		t.Fatalf("verify persisted security audit: %v", err)
	}
	securityRows, err := s.ListSecurityAudit(ctx, 0, securityHighWater, 1000)
	if err != nil || len(securityRows) == 0 || securityRows[len(securityRows)-1].RequestID != securityRequest {
		t.Fatalf("security audit export rows=%d err=%v", len(securityRows), err)
	}
	if _, err = s.Pool.Exec(ctx, `UPDATE security_audit_events SET actor='rewritten' WHERE id=$1`, securityHighWater); err == nil {
		t.Fatal("security audit event update was accepted")
	}
	revokedToken := sha256.Sum256([]byte("opaque-test-bearer-" + store.NewID()))
	revokedUntil := time.Now().UTC().Add(time.Hour)
	if revoked, revokeErr := s.IsTokenRevoked(ctx, revokedToken[:]); revokeErr != nil || revoked {
		t.Fatalf("new token unexpectedly revoked: revoked=%v err=%v", revoked, revokeErr)
	}
	if err = s.RevokeToken(ctx, revokedToken[:], revokedUntil, "integration-user", store.NewID()); err != nil {
		t.Fatalf("persist token revocation: %v", err)
	}
	if err = s.RevokeToken(ctx, revokedToken[:], revokedUntil, "integration-user", store.NewID()); err != nil {
		t.Fatalf("repeat token revocation was not idempotent: %v", err)
	}
	if revoked, revokeErr := s.IsTokenRevoked(ctx, revokedToken[:]); revokeErr != nil || !revoked {
		t.Fatalf("revoked token remained active: revoked=%v err=%v", revoked, revokeErr)
	}
	if _, err = s.Pool.Exec(ctx, `DELETE FROM oidc_token_revocations WHERE token_hash=$1`, revokedToken[:]); err == nil {
		t.Fatal("active token revocation was mutable")
	}
	expiredToken := sha256.Sum256([]byte("expired-test-bearer-" + store.NewID()))
	if err = s.RevokeToken(ctx, expiredToken[:], time.Now().UTC().Add(-time.Minute), "integration-user", store.NewID()); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expired token was accepted for revocation: %v", err)
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
	if err = restarted.SetMembership(ctx, a.ID, "tenant-api-integration-user", "viewer", "integration", store.NewID()); err != nil {
		t.Fatalf("seed API token revocation membership: %v", err)
	}
	bearer := "tenant-api-integration-token-" + store.NewID()
	const token = "integration-test-token-at-least-32-characters"
	h := httpapi.NewWithOptions(restarted, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), httpapi.Options{Verifier: postgresSubjectVerifier{token: bearer}})
	r := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+a.ID+"/sites", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), site.ID) {
		t.Fatalf("database-backed API: %d %s", w.Code, w.Body.String())
	}
	revoke := httptest.NewRequest(http.MethodPost, "/v1/session/revoke", nil)
	revoke.Header.Set("Authorization", "Bearer "+bearer)
	revokeResponse := httptest.NewRecorder()
	h.ServeHTTP(revokeResponse, revoke)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("database-backed token revocation: %d %s", revokeResponse.Code, revokeResponse.Body.String())
	}
	replay := httptest.NewRequest(http.MethodGet, "/v1/organizations", nil)
	replay.Header.Set("Authorization", "Bearer "+bearer)
	replayResponse := httptest.NewRecorder()
	h.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token was still accepted by API: %d %s", replayResponse.Code, replayResponse.Body.String())
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

func TestPostgresTenantScopedReadPaths(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("CI requires KORDEX_TEST_DATABASE_URL")
		}
		t.Skip("set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	type tenantFixture struct {
		org     store.Organization
		site    store.Site
		fleet   store.Fleet
		cluster store.Cluster
		nodeUID string
	}
	createTenant := func(name string) tenantFixture {
		t.Helper()
		request := store.NewID()
		org, createErr := db.CreateOrganization(ctx, name+"-"+store.NewID(), "tenant-test", request)
		if createErr != nil {
			t.Fatal(createErr)
		}
		site, createErr := db.CreateSite(ctx, org.ID, "site", "isolated", "tenant-test", store.NewID())
		if createErr != nil {
			t.Fatal(createErr)
		}
		fleet, createErr := db.CreateFleet(ctx, org.ID, "fleet", "tenant-test", store.NewID())
		if createErr != nil {
			t.Fatal(createErr)
		}
		cluster, createErr := db.CreateCluster(ctx, store.Cluster{
			OrganizationID: org.ID, FleetID: fleet.ID, SiteID: site.ID,
			Name: "cluster", Provider: "self-managed",
		}, "tenant-test", store.NewID())
		if createErr != nil {
			t.Fatal(createErr)
		}
		nodeUID := "node-" + store.NewID()
		inventory := `{"name":"worker","uid":"` + nodeUID + `","ready":true,"labels":{}}`
		if _, createErr = db.Pool.Exec(ctx,
			"INSERT INTO nodes(cluster_id,uid,name,inventory) VALUES($1,$2,$3,$4::jsonb)",
			cluster.ID, nodeUID, "worker", inventory,
		); createErr != nil {
			t.Fatal(createErr)
		}
		return tenantFixture{org: org, site: site, fleet: fleet, cluster: cluster, nodeUID: nodeUID}
	}

	left := createTenant("tenant-left")
	right := createTenant("tenant-right")
	for _, fixture := range []tenantFixture{left, right} {
		t.Run(fixture.org.Name, func(t *testing.T) {
			const limit = 20
			sites, err := db.ListInventorySites(ctx, fixture.org.ID, limit, 0)
			if err != nil || len(sites) != 1 || sites[0].ID != fixture.site.ID || sites[0].OrganizationID != fixture.org.ID {
				t.Fatalf("site list escaped tenant scope: items=%+v err=%v", sites, err)
			}
			fleets, err := db.ListInventoryFleets(ctx, fixture.org.ID, limit, 0)
			if err != nil || len(fleets) != 1 || fleets[0].ID != fixture.fleet.ID || fleets[0].OrganizationID != fixture.org.ID {
				t.Fatalf("fleet list escaped tenant scope: items=%+v err=%v", fleets, err)
			}
			clusters, err := db.ListInventoryClusters(ctx, fixture.org.ID, limit, 0)
			if err != nil || len(clusters) != 1 || clusters[0].ID != fixture.cluster.ID || clusters[0].OrganizationID != fixture.org.ID {
				t.Fatalf("cluster list escaped tenant scope: items=%+v err=%v", clusters, err)
			}
			nodes, err := db.ListInventoryNodes(ctx, fixture.org.ID, store.InventoryFilter{}, limit, 0)
			if err != nil || len(nodes) != 1 || nodes[0].ClusterID != fixture.cluster.ID || nodes[0].Node.UID != fixture.nodeUID {
				t.Fatalf("node inventory escaped tenant scope: items=%+v err=%v", nodes, err)
			}
			foreignClusterID := left.cluster.ID
			if fixture.cluster.ID == left.cluster.ID {
				foreignClusterID = right.cluster.ID
			}
			foreignNodes, err := db.ListInventoryNodes(ctx, fixture.org.ID, store.InventoryFilter{ClusterID: foreignClusterID}, limit, 0)
			if err != nil || len(foreignNodes) != 0 {
				t.Fatalf("foreign cluster filter escaped tenant scope: items=%+v err=%v", foreignNodes, err)
			}
			auditRows, err := db.ListAudit(ctx, fixture.org.ID, "", false, 0, 0, limit, 0)
			if err != nil || len(auditRows) < 4 {
				t.Fatalf("tenant audit rows missing: count=%d err=%v", len(auditRows), err)
			}
			for _, row := range auditRows {
				if row.OrganizationID != fixture.org.ID {
					t.Fatalf("foreign audit event returned: %+v", row)
				}
			}
			summary, err := db.DashboardSummary(ctx, fixture.org.ID)
			if err != nil || summary.Fleets != 1 || summary.Sites != 1 || summary.Clusters != 1 || summary.Nodes != 1 || summary.UnknownNodes != 1 {
				t.Fatalf("dashboard aggregate escaped tenant scope: summary=%+v err=%v", summary, err)
			}
		})
	}
}

func TestPostgresTenantScopedAPIEnforcesPersistedMembership(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("CI requires KORDEX_TEST_DATABASE_URL")
		}
		t.Skip("set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	left, err := db.CreateOrganization(ctx, "api-tenant-left-"+store.NewID(), "integration", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	right, err := db.CreateOrganization(ctx, "api-tenant-right-"+store.NewID(), "integration", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	leftSite, err := db.CreateSite(ctx, left.ID, "left-site", "integration", "api-test", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	rightSite, err := db.CreateSite(ctx, right.ID, "right-site", "integration", "api-test", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	bearer := "tenant-api-scoped-integration-token-" + store.NewID()
	if err = db.SetMembership(ctx, left.ID, "tenant-api-integration-user", "viewer", "integration", store.NewID()); err != nil {
		t.Fatal(err)
	}
	fleet, err := db.CreateFleet(ctx, right.ID, "right-fleet", "api-test", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := db.CreateCluster(ctx, store.Cluster{
		OrganizationID: right.ID, FleetID: fleet.ID, SiteID: rightSite.ID,
		Name: "right-cluster", Provider: "self-managed",
	}, "api-test", store.NewID())
	if err != nil {
		t.Fatal(err)
	}

	handler := httpapi.NewWithOptions(db, "", "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), httpapi.Options{Verifier: postgresSubjectVerifier{token: bearer}})
	request := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	ownSites := request("/v1/organizations/" + left.ID + "/sites")
	if ownSites.Code != http.StatusOK || !strings.Contains(ownSites.Body.String(), leftSite.ID) || strings.Contains(ownSites.Body.String(), rightSite.ID) {
		t.Fatalf("authenticated tenant site read escaped persisted membership: status=%d body=%s", ownSites.Code, ownSites.Body.String())
	}
	foreignSites := request("/v1/organizations/" + right.ID + "/sites")
	if foreignSites.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant API request status=%d body=%s, want 403", foreignSites.Code, foreignSites.Body.String())
	}
	foreignClusterNodes := request("/v1/organizations/" + left.ID + "/clusters/" + cluster.ID + "/nodes")
	if foreignClusterNodes.Code != http.StatusNotFound || strings.Contains(foreignClusterNodes.Body.String(), cluster.ID) {
		t.Fatalf("foreign cluster filter exposed another tenant's inventory: status=%d body=%s", foreignClusterNodes.Code, foreignClusterNodes.Body.String())
	}
	leftAudit := request("/v1/organizations/" + left.ID + "/audit")
	if leftAudit.Code != http.StatusOK || strings.Contains(leftAudit.Body.String(), rightSite.ID) || strings.Contains(leftAudit.Body.String(), cluster.ID) {
		t.Fatalf("tenant audit API returned another organization's evidence: status=%d body=%s", leftAudit.Code, leftAudit.Body.String())
	}
}

func TestPostgresLastAdministratorProtectionIsSerialized(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("CI requires KORDEX_TEST_DATABASE_URL")
		}
		t.Skip("set KORDEX_TEST_DATABASE_URL to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	org, err := db.CreateOrganization(ctx, "last-admin-"+store.NewID(), "test", store.NewID())
	if err != nil {
		t.Fatal(err)
	}
	admins := []string{"admin-left", "admin-right"}
	for _, subject := range admins {
		if err = db.SetMembership(ctx, org.ID, subject, "administrator", "bootstrap", store.NewID()); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	results := make(chan error, len(admins))
	var wait sync.WaitGroup
	for _, subject := range admins {
		wait.Add(1)
		go func(subject string) {
			defer wait.Done()
			<-start
			results <- db.SetMembership(ctx, org.ID, subject, "viewer", "administrator", store.NewID())
		}(subject)
	}
	close(start)
	wait.Wait()
	close(results)
	var demoted, rejected int
	for result := range results {
		switch {
		case result == nil:
			demoted++
		case errors.Is(result, store.ErrLastAdministrator):
			rejected++
		default:
			t.Fatalf("unexpected concurrent membership result: %v", result)
		}
	}
	if demoted != 1 || rejected != 1 {
		t.Fatalf("concurrent demotions=%d rejected=%d, want one of each", demoted, rejected)
	}

	var remaining string
	if err = db.Pool.QueryRow(ctx, "SELECT subject FROM memberships WHERE organization_id=$1 AND role='administrator'", org.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if err = db.SetMembership(ctx, org.ID, remaining, "operator", "administrator", store.NewID()); !errors.Is(err, store.ErrLastAdministrator) {
		t.Fatalf("final administrator demotion accepted: %v", err)
	}
	if err = db.SetMembership(ctx, org.ID, "replacement-admin", "administrator", "bootstrap", store.NewID()); err != nil {
		t.Fatal(err)
	}
	if err = db.SetMembership(ctx, org.ID, remaining, "operator", "administrator", store.NewID()); err != nil {
		t.Fatalf("administrator replacement was blocked: %v", err)
	}
	var count int
	if err = db.Pool.QueryRow(ctx, "SELECT count(*) FROM memberships WHERE organization_id=$1 AND role='administrator'", org.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("administrator count=%d err=%v, want one", count, err)
	}
}
