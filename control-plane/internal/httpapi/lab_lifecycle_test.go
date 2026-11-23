package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"kordex.local/control-plane/internal/store"
)

func TestLabLifecycleMutationsRequireAdministrator(t *testing.T) {
	r := &http.Request{Method: http.MethodPost, Pattern: "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop"}
	for _, role := range []string{"viewer", "operator", "approver"} {
		if authorizedRoute(r, role) {
			t.Fatalf("%s was allowed to change durable lab lifecycle state", role)
		}
	}
	if !authorizedRoute(r, "administrator") {
		t.Fatal("administrator could not manage the lab lifecycle")
	}
	get := &http.Request{Method: http.MethodGet, Pattern: "GET /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle"}
	if !authorizedRoute(get, "viewer") {
		t.Fatal("viewer could not read lab lifecycle status")
	}
}

func TestLabLifecycleAuthorizationProbeIsReadOnlyAndAdministratorOnly(t *testing.T) {
	org, cluster := store.NewID(), store.NewID()
	for _, role := range []string{"viewer", "operator", "approver", "administrator"} {
		t.Run(role, func(t *testing.T) {
			repo := &authorizationRepo{Repository: &fakeRepo{}, role: role}
			h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: hardeningVerifier{}})
			response := request(h, "GET", "/v1/organizations/"+org+"/clusters/"+cluster+"/lab-lifecycle/authorization", "", "oidc")
			if role != "administrator" {
				if response.Code != http.StatusForbidden {
					t.Fatalf("role %q received authorization probe status %d", role, response.Code)
				}
				return
			}
			if response.Code != http.StatusOK || response.Body.String() != "{\"authorized\":true,\"role\":\"administrator\"}\n" {
				t.Fatalf("administrator probe status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	t.Run("bootstrap is not an organization admin", func(t *testing.T) {
		token := "bootstrap-test-token-with-at-least-32-bytes"
		repo := &fakeRepo{}
		h := NewWithOptions(repo, token, "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{AllowBootstrap: true})
		response := request(h, "GET", "/v1/organizations/"+org+"/clusters/"+cluster+"/lab-lifecycle/authorization", "", token)
		if response.Code != http.StatusForbidden {
			t.Fatalf("bootstrap token was reported as an organization administrator: %d", response.Code)
		}
	})
}
