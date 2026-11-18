package httpapi

import (
	"context"
	"errors"
	"io"
	"kordex.local/api/lifecycle"
	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type hardeningVerifier struct{}

func (hardeningVerifier) Verify(_ context.Context, value string) (string, error) {
	if value == "oidc" {
		return "alice", nil
	}
	return "", errors.New("invalid credential")
}

type authorizationRepo struct {
	Repository
	FleetRepository
	role string
	deny bool
}

func (r *authorizationRepo) Membership(context.Context, string, string) (string, error) {
	if r.deny {
		return "", store.ErrUnauthorized
	}
	return r.role, nil
}
func TestOrganizationEndpointsDenyCrossTenantAccessBeforeRepositoryCalls(t *testing.T) {
	org := store.NewID()
	id := store.NewID()
	paths := []struct{ method, path string }{
		{"GET", ""}, {"GET", "/identity"}, {"GET", "/summary"}, {"GET", "/nodes"}, {"GET", "/audit"}, {"GET", "/lifecycle-drivers"},
		{"GET", "/sites"}, {"POST", "/sites"}, {"GET", "/fleets"}, {"POST", "/fleets"}, {"GET", "/clusters"}, {"POST", "/clusters"},
		{"GET", "/dashboard/sites"}, {"GET", "/dashboard/fleets"}, {"GET", "/dashboard/clusters"}, {"PUT", "/memberships"},
		{"GET", "/concurrency-policy"}, {"PUT", "/concurrency-policy"}, {"GET", "/campaigns"}, {"POST", "/campaigns"}, {"POST", "/campaigns/preview"},
		{"GET", "/campaigns/" + id}, {"PUT", "/campaigns/" + id},
	}
	for _, suffix := range []string{"targets", "operations", "events", "approvals"} {
		paths = append(paths, struct{ method, path string }{"GET", "/campaigns/" + id + "/" + suffix})
	}
	for _, suffix := range []string{"start", "approve", "reject", "pause", "resume", "cancel"} {
		paths = append(paths, struct{ method, path string }{"POST", "/campaigns/" + id + "/" + suffix})
	}
	for _, suffix := range []string{"nodes", "maintenance-policies", "operations"} {
		paths = append(paths, struct{ method, path string }{"GET", "/clusters/" + id + "/" + suffix})
	}
	for _, suffix := range []string{"enrollment-tokens", "revoke", "operations", "operations/" + id + "/cancel"} {
		paths = append(paths, struct{ method, path string }{"POST", "/clusters/" + id + "/" + suffix})
	}
	for _, tc := range paths {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			repo := &authorizationRepo{Repository: &fakeRepo{}, deny: true}
			h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
			response := request(h, tc.method, "/v1/organizations/"+org+tc.path, "{}", "oidc")
			if response.Code != 403 {
				t.Fatalf("cross-tenant endpoint reached handler: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
func TestOIDCListenerCannotReenableBootstrapThroughOptions(t *testing.T) {
	repo := &fakeRepo{}
	h := NewWithOptions(repo, token, "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}, AllowBootstrap: true})
	if response := request(h, "POST", "/v1/organizations", `{"name":"escape"}`, token); response.Code != 401 || repo.calls != 0 {
		t.Fatalf("OIDC listener accepted bootstrap: %d", response.Code)
	}
}
func TestReadOnlyCompatibilityCatalogIsTenantAuthenticated(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "approver", "administrator", "unknown"} {
		repo := &authorizationRepo{Repository: &fakeRepo{}, role: role}
		h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
		result := request(h, "GET", "/v1/organizations/"+store.NewID()+"/lifecycle-drivers", "", "oidc")
		if role == "unknown" {
			if result.Code != 403 {
				t.Fatal("unknown role permitted")
			}
			continue
		}
		if result.Code != 200 || !strings.Contains(result.Body.String(), `"Unverified"`) || strings.Contains(result.Body.String(), `"Qualified"`) {
			t.Fatalf("catalog=%d %s", result.Code, result.Body.String())
		}
	}
}
func TestLifecycleInventoryValidationCannotGrantUnsupportedCapabilities(t *testing.T) {
	now := time.Now()
	discovery := lifecycle.DiscoverKubernetes("v1.37.0+k3s1", "containerd://2", "", nil, false)
	report := protocol.Report{ClusterUID: "cluster", Version: 1, ObservedAt: now, KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{Name: "worker", UID: "node", Lifecycle: &discovery}}}
	if !validReport(report, now) {
		t.Fatal("valid advisory inventory rejected")
	}
	discovery.Kubernetes.ControlPlane = "safe-to-upgrade"
	if validReport(report, now) {
		t.Fatal("unsupported lifecycle claim accepted")
	}
}
