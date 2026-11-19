package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
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
	role            string
	deny            bool
	organizations   []store.Organization
	denials         []store.SecurityDenial
	auditError      error
	membershipError error
}

func (r *authorizationRepo) Membership(context.Context, string, string) (string, error) {
	if r.deny {
		return "", store.ErrUnauthorized
	}
	return r.role, nil
}
func (r *authorizationRepo) OrganizationsForSubject(context.Context, string, int, int) ([]store.Organization, error) {
	if r.deny {
		return []store.Organization{}, nil
	}
	return r.organizations, nil
}
func (r *authorizationRepo) IsTokenRevoked(ctx context.Context, hash []byte) (bool, error) {
	repository, ok := r.Repository.(TokenRevocationRepository)
	if !ok {
		return false, errors.New("token revocation repository unavailable")
	}
	return repository.IsTokenRevoked(ctx, hash)
}
func (r *authorizationRepo) RevokeToken(ctx context.Context, hash []byte, expiresAt time.Time, subject, requestID string) error {
	repository, ok := r.Repository.(TokenRevocationRepository)
	if !ok {
		return errors.New("token revocation repository unavailable")
	}
	return repository.RevokeToken(ctx, hash, expiresAt, subject, requestID)
}
func (r *authorizationRepo) RecordSecurityDenial(_ context.Context, denial store.SecurityDenial) error {
	r.denials = append(r.denials, denial)
	return r.auditError
}
func (r *authorizationRepo) SetMembership(context.Context, string, string, string, string, string) error {
	return r.membershipError
}
func TestOrganizationEndpointsDenyCrossTenantAccessBeforeRepositoryCalls(t *testing.T) {
	org := store.NewID()
	id := store.NewID()
	paths := []struct{ method, path string }{
		{"GET", ""}, {"GET", "/identity"}, {"GET", "/summary"}, {"GET", "/nodes"}, {"GET", "/audit"}, {"GET", "/lifecycle-drivers"}, {"GET", "/kubernetes-compatibility"}, {"GET", "/operations?phase=RecoveryRequired"},
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

func TestAuthorizationDenialsAreStructuredAndCredentialSafe(t *testing.T) {
	org := store.NewID()
	for _, tc := range []struct {
		name, method, path, credential, role, reason string
		denyMembership                               bool
	}{
		{name: "missing credential", method: "GET", path: "/v1/organizations/" + org + "/sites", reason: "credentials_missing"},
		{name: "membership", method: "GET", path: "/v1/organizations/" + org + "/sites", credential: "oidc", denyMembership: true, reason: "membership_denied"},
		{name: "role", method: "POST", path: "/v1/organizations/" + org + "/sites", credential: "oidc", role: "viewer", reason: "role_denied"},
		{name: "credential", method: "GET", path: "/v1/organizations/" + org + "/sites", credential: "sensitive-invalid-token", reason: "credential_rejected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			repo := &authorizationRepo{Repository: &fakeRepo{}, role: tc.role, deny: tc.denyMembership}
			h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewJSONHandler(&logs, nil)), Options{Verifier: hardeningVerifier{}})
			response := request(h, tc.method, tc.path, `{"name":"secret body"}`, tc.credential)
			if response.Code != 401 && response.Code != 403 {
				t.Fatalf("denial status=%d body=%s", response.Code, response.Body.String())
			}
			output := logs.String()
			for _, want := range []string{`"event":"authorization.denied"`, `"reason":"` + tc.reason + `"`, `"route":"` + tc.method + ` /v1/organizations/{organizationID}/sites"`, `"organization_id":"` + org + `"`} {
				if !strings.Contains(output, want) {
					t.Fatalf("security record missing %s: %s", want, output)
				}
			}
			if tc.credential == "oidc" && !strings.Contains(output, `"actor":"oidc:alice"`) {
				t.Fatalf("authenticated denial missing actor: %s", output)
			}
			if strings.Contains(output, "sensitive-invalid-token") || strings.Contains(output, "secret body") {
				t.Fatalf("security log leaked request credential or body: %s", output)
			}
			if tc.reason == "membership_denied" || tc.reason == "role_denied" {
				if len(repo.denials) != 1 {
					t.Fatalf("expected one durable denial record, got %d", len(repo.denials))
				}
				denial := repo.denials[0]
				if denial.OrganizationID != org || denial.Actor != "oidc:alice" || denial.Reason != tc.reason || denial.Method != tc.method || denial.Role != tc.role || !validID(denial.RequestID) || strings.Contains(denial.Route, "?") {
					t.Fatalf("unexpected durable denial: %+v", denial)
				}
			} else if len(repo.denials) != 0 {
				t.Fatalf("credential-only denial unexpectedly persisted: %+v", repo.denials)
			}
		})
	}
}

func TestAuthorizationDenialRemainsClosedWhenDurableAuditWriteFails(t *testing.T) {
	var logs bytes.Buffer
	repo := &authorizationRepo{
		Repository: &fakeRepo{}, role: "viewer", auditError: errors.New("database details must not be logged"),
	}
	h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewJSONHandler(&logs, nil)), Options{Verifier: hardeningVerifier{}})
	response := request(h, "POST", "/v1/organizations/"+store.NewID()+"/sites", `{}`, "oidc")
	if response.Code != 403 {
		t.Fatalf("audit failure changed authorization result: status=%d body=%s", response.Code, response.Body.String())
	}
	if len(repo.denials) != 1 || !strings.Contains(logs.String(), `"event":"authorization.audit_write_failed"`) || strings.Contains(logs.String(), "database details") {
		t.Fatalf("audit failure was not reported safely: records=%d logs=%s", len(repo.denials), logs.String())
	}
}

func TestOIDCOrganizationAccessRequiresPersistedMembership(t *testing.T) {
	org := store.NewID()
	member := &authorizationRepo{Repository: &fakeRepo{}, role: "viewer", organizations: []store.Organization{{ID: org, Name: "Local Org"}}}
	handler := NewWithOptions(member, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
	listed := request(handler, "GET", "/v1/organizations", "", "oidc")
	if listed.Code != 200 || !strings.Contains(listed.Body.String(), org) {
		t.Fatalf("member organization listing status=%d body=%s", listed.Code, listed.Body.String())
	}
	visible := request(handler, "GET", "/v1/organizations/"+org, "", "oidc")
	if visible.Code != 200 || !strings.Contains(visible.Body.String(), org) {
		t.Fatalf("member organization access status=%d body=%s", visible.Code, visible.Body.String())
	}

	nonmember := &authorizationRepo{Repository: &fakeRepo{}, deny: true}
	handler = NewWithOptions(nonmember, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
	listed = request(handler, "GET", "/v1/organizations", "", "oidc")
	var page struct {
		Items []store.Organization `json:"items"`
	}
	if listed.Code != 200 || json.Unmarshal(listed.Body.Bytes(), &page) != nil || len(page.Items) != 0 {
		t.Fatalf("nonmember received organization data: status=%d body=%s", listed.Code, listed.Body.String())
	}
	visible = request(handler, "GET", "/v1/organizations/"+org, "", "oidc")
	if visible.Code != 403 {
		t.Fatalf("nonmember organization lookup status=%d, want 403", visible.Code)
	}
	protected := request(handler, "GET", "/v1/organizations/"+org+"/sites", "", "oidc")
	if protected.Code == 200 {
		t.Fatal("authenticated nonmember accessed organization-scoped data")
	}
	unauthenticated := request(handler, "GET", "/v1/organizations", "", "")
	if unauthenticated.Code != 401 {
		t.Fatalf("unauthenticated organization listing status=%d, want 401", unauthenticated.Code)
	}
}

func TestMembershipUpdateReportsLastAdministratorConflict(t *testing.T) {
	org := store.NewID()
	repo := &authorizationRepo{
		Repository: &fakeRepo{}, role: "administrator", membershipError: store.ErrLastAdministrator,
	}
	h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
	response := request(h, "PUT", "/v1/organizations/"+org+"/memberships", `{"subject":"admin","role":"viewer"}`, "oidc")
	if response.Code != 409 || !strings.Contains(response.Body.String(), `"error":"last_administrator_required"`) {
		t.Fatalf("last administrator conflict status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConcurrencyPolicyMutationRequiresOrganizationAdministrator(t *testing.T) {
	org := store.NewID()
	for _, role := range []string{"viewer", "operator", "approver", "administrator"} {
		repo := &authorizationRepo{Repository: &fakeRepo{}, role: role}
		h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
		response := request(h, "PUT", "/v1/organizations/"+org+"/concurrency-policy", `{"revision":1,"limits":{"organization":2,"fleet":1,"site":1,"cluster":1,"node":1,"maxUnavailablePerSite":1}}`, "oidc")
		if role == "administrator" {
			if response.Code == 403 {
				t.Fatal("administrator was denied by the role gate")
			}
			continue
		}
		if response.Code != 403 {
			t.Fatalf("role %q updated concurrency policy: status=%d body=%s", role, response.Code, response.Body.String())
		}
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

func TestKubernetesCompatibilityCatalogIsTenantScopedAndUnqualified(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "approver", "administrator", "unknown"} {
		repo := &authorizationRepo{Repository: &fakeRepo{}, role: role}
		h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
		result := request(h, "GET", "/v1/organizations/"+store.NewID()+"/kubernetes-compatibility", "", "oidc")
		if role == "unknown" {
			if result.Code != 403 {
				t.Fatalf("unknown role permitted: %d", result.Code)
			}
			continue
		}
		if result.Code != 200 {
			t.Fatalf("catalog=%d %s", result.Code, result.Body.String())
		}
		var catalog struct {
			Items []struct {
				Qualification                 lifecycle.Support            `json:"qualification"`
				QualifiedKubernetesVersions   []string                     `json:"qualifiedKubernetesVersions"`
				QualifiedNodeOperatingSystems []string                     `json:"qualifiedNodeOperatingSystems"`
				QualifiedArchitectures        []string                     `json:"qualifiedArchitectures"`
				Operations                    map[string]lifecycle.Support `json:"operations"`
			} `json:"items"`
		}
		if err := json.Unmarshal(result.Body.Bytes(), &catalog); err != nil || len(catalog.Items) == 0 {
			t.Fatalf("invalid catalog response: %v %s", err, result.Body.String())
		}
		for _, item := range catalog.Items {
			if item.Qualification != lifecycle.Unverified || len(item.QualifiedKubernetesVersions)+len(item.QualifiedNodeOperatingSystems)+len(item.QualifiedArchitectures) != 0 {
				t.Fatalf("catalog advertised unqualified compatibility: %+v", item)
			}
			for operation, status := range item.Operations {
				if status == lifecycle.Supported || status == lifecycle.Qualified {
					t.Fatalf("catalog advertised %s as executable for an unqualified target", operation)
				}
			}
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

func TestClusterCapabilityReportValidationRejectsInventedSupport(t *testing.T) {
	now := time.Now().UTC()
	observed := protocol.CapabilityObservation{State: "Observed", Source: "test-source", Values: []string{"cilium"}}
	unknown := protocol.CapabilityObservation{State: "Unknown", Source: "test-source", Values: []string{}, ReasonCode: "PermissionDenied"}
	capabilities := protocol.ClusterCapabilities{
		ObservedAt: now, CNIHints: observed, CSIDrivers: unknown,
		StorageProvisioners: unknown, AdmissionAPIs: observed, PodSecurityNamespaceLabels: unknown,
	}
	report := protocol.Report{ClusterUID: "cluster", Version: 1, ObservedAt: now, KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{}, ClusterCapabilities: &capabilities}
	if !validReport(report, now) {
		t.Fatal("valid observed and unknown cluster capability evidence rejected")
	}
	capabilities.CNIHints.State = "Qualified"
	report.ClusterCapabilities = &capabilities
	if validReport(report, now) {
		t.Fatal("agent inventory was allowed to claim a qualified cluster capability")
	}
}
