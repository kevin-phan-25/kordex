package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kordex.local/control-plane/internal/store"
)

const token = "test-token-with-at-least-32-characters"

type fakeRepo struct {
	calls           int
	err             error
	org             string
	revoked         map[string]bool
	revocationErr   error
	operationPhase  string
	operationLimit  int
	operationOffset int
}

type staticTokenVerifier struct {
	subject   string
	expiresAt time.Time
}

func (v staticTokenVerifier) Verify(context.Context, string) (string, error) {
	return v.subject, nil
}
func (v staticTokenVerifier) VerifyWithExpiry(context.Context, string) (string, time.Time, error) {
	return v.subject, v.expiresAt, nil
}

func (f *fakeRepo) Ready(context.Context) error { return f.err }
func (f *fakeRepo) CreateOrganization(_ context.Context, name, actor, request string) (store.Organization, error) {
	f.calls++
	if actor != "bootstrap-admin" || !validID(request) {
		panic("missing audit identity")
	}
	return store.Organization{ID: store.NewID(), Name: name}, f.err
}
func (f *fakeRepo) ListOrganizations(context.Context, int, int) ([]store.Organization, error) {
	f.calls++
	return []store.Organization{}, f.err
}
func (f *fakeRepo) CreateSite(_ context.Context, org, name, region, actor, request string) (store.Site, error) {
	f.calls++
	f.org = org
	return store.Site{OrganizationID: org, Name: name, Region: region}, f.err
}
func (f *fakeRepo) ListSites(_ context.Context, org string, _ int, _ int) ([]store.Site, error) {
	f.calls++
	f.org = org
	return []store.Site{}, f.err
}
func (f *fakeRepo) ListOrganizationOperations(_ context.Context, org, phase string, limit, offset int) ([]store.NodeOperation, error) {
	f.calls++
	f.org, f.operationPhase = org, phase
	f.operationLimit, f.operationOffset = limit, offset
	return []store.NodeOperation{}, f.err
}
func (f *fakeRepo) IsTokenRevoked(_ context.Context, tokenHash []byte) (bool, error) {
	if f.revocationErr != nil {
		return false, f.revocationErr
	}
	return f.revoked[hex.EncodeToString(tokenHash)], nil
}
func (f *fakeRepo) RevokeToken(_ context.Context, tokenHash []byte, _ time.Time, _ string, _ string) error {
	if f.revocationErr != nil {
		return f.revocationErr
	}
	if f.revoked == nil {
		f.revoked = map[string]bool{}
	}
	f.revoked[hex.EncodeToString(tokenHash)] = true
	return nil
}
func handler(f *fakeRepo) http.Handler {
	return New(f, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)))
}
func request(h http.Handler, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if auth != "" {
		r.Header.Set("Authorization", "Bearer "+auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAPIValidationAndAuthentication(t *testing.T) {
	org := "80bd80f9-f097-4474-86f4-b80986fd5423"
	cases := []struct {
		name, method, path, body, auth string
		status, calls                  int
	}{
		{"unauthenticated", "GET", "/v1/organizations", "", "", 401, 0},
		{"wrong credential", "POST", "/v1/organizations", `{"name":"acme"}`, "invalid", 401, 0},
		{"create organization", "POST", "/v1/organizations", `{"name":"acme"}`, token, 201, 1},
		{"head organizations", "HEAD", "/v1/organizations", "", token, 200, 1},
		{"head sites", "HEAD", "/v1/organizations/" + org + "/sites", `{"name":"must-not-create","region":"us-east"}`, token, 200, 1},
		{"list", "GET", "/v1/organizations?limit=1&offset=0", "", token, 200, 1},
		{"empty name", "POST", "/v1/organizations", `{"name":""}`, token, 400, 0},
		{"unknown field", "POST", "/v1/organizations", `{"name":"a","admin":true}`, token, 400, 0},
		{"trailing JSON", "POST", "/v1/organizations", `{"name":"a"} {}`, token, 400, 0},
		{"large body", "POST", "/v1/organizations", `{"name":"` + strings.Repeat("a", 17000) + `"}`, token, 400, 0},
		{"invalid limit", "GET", "/v1/organizations?limit=501", "", token, 400, 0},
		{"duplicate query", "GET", "/v1/organizations?limit=1&limit=2", "", token, 400, 0},
		{"unknown query", "GET", "/v1/organizations?organization=x", "", token, 400, 0},
		{"invalid org", "GET", "/v1/organizations/not-a-uuid/sites", "", token, 400, 0},
		{"site", "POST", "/v1/organizations/" + org + "/sites", `{"name":"dc1","region":"us-east"}`, token, 201, 1},
		{"empty region", "POST", "/v1/organizations/" + org + "/sites", `{"name":"dc1","region":""}`, token, 400, 0},
		{"method", "DELETE", "/v1/organizations", "", token, 405, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRepo{}
			w := request(handler(f), tc.method, tc.path, tc.body, tc.auth)
			if w.Code != tc.status || f.calls != tc.calls {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, f.calls, w.Body.String())
			}
			if !validID(w.Header().Get("X-Request-ID")) {
				t.Fatal("missing request ID")
			}
		})
	}
}
func TestFailureResponsesDoNotLeak(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
	}{{store.ErrConflict, 409}, {store.ErrNotFound, 404}, {errors.New("postgres://secret@example"), 503}} {
		w := request(handler(&fakeRepo{err: tc.err}), "POST", "/v1/organizations", `{"name":"acme"}`, token)
		if w.Code != tc.code || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("unexpected response: %d %s", w.Code, w.Body.String())
		}
	}
}
func TestHealthAndReadiness(t *testing.T) {
	f := &fakeRepo{err: errors.New("offline")}
	h := handler(f)
	if w := request(h, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(h, "GET", "/readyz", "", ""); w.Code != 503 {
		t.Fatal(w.Code)
	}
	f.err = nil
	if w := request(h, "GET", "/readyz", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestOrganizationScopeForwarded(t *testing.T) {
	f := &fakeRepo{}
	id := store.NewID()
	w := request(handler(f), "GET", "/v1/organizations/"+id+"/sites", "", token)
	if w.Code != 200 || f.org != id {
		t.Fatal("organization scope lost")
	}
}

func TestMalformedUUIDRejectedBeforeRepository(t *testing.T) {
	f := &fakeRepo{}
	w := request(handler(f), "GET", "/v1/organizations/00000000-0000-0000-0000-00000000--00/sites", "", token)
	if w.Code != 400 || f.calls != 0 {
		t.Fatalf("invalid UUID reached repository: %d", w.Code)
	}
}

func TestOrganizationOperationQueueRequiresAllowedPhaseAndBoundsPagination(t *testing.T) {
	org := store.NewID()
	repo := &fakeRepo{}
	h := handler(repo)
	response := request(h, http.MethodGet, "/v1/organizations/"+org+"/operations?phase=RecoveryRequired&limit=7&offset=14", "", token)
	if response.Code != http.StatusOK || repo.calls != 1 || repo.org != org || repo.operationPhase != "RecoveryRequired" || repo.operationLimit != 7 || repo.operationOffset != 14 {
		t.Fatalf("queue request status=%d calls=%d org=%s phase=%s limit=%d offset=%d body=%s", response.Code, repo.calls, repo.org, repo.operationPhase, repo.operationLimit, repo.operationOffset, response.Body.String())
	}
	for _, query := range []string{"", "?phase=Pending", "?phase=Failed&phase=Blocked", "?phase=Blocked&limit=501", "?phase=Failed&extra=x"} {
		repo.calls = 0
		response = request(h, http.MethodGet, "/v1/organizations/"+org+"/operations"+query, "", token)
		if response.Code != http.StatusBadRequest || repo.calls != 0 {
			t.Fatalf("invalid queue query %q reached repository: status=%d calls=%d body=%s", query, response.Code, repo.calls, response.Body.String())
		}
	}
}

func TestAPIIdempotentlyRevokesVerifiedBearerToken(t *testing.T) {
	repo := &fakeRepo{}
	verifier := staticTokenVerifier{subject: "alice", expiresAt: time.Now().Add(time.Hour)}
	h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: verifier})

	response := request(h, http.MethodPost, "/v1/session/revoke", "", "signed-token")
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", response.Code, response.Body.String())
	}
	if response = request(h, http.MethodPost, "/v1/session/revoke", "", "signed-token"); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed revoked credential status=%d body=%s", response.Code, response.Body.String())
	}
	if response = request(h, http.MethodGet, "/v1/organizations", "", "signed-token"); response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked credential remained usable: %d %s", response.Code, response.Body.String())
	}
	if repo.calls != 0 {
		t.Fatalf("revoked credential reached a protected handler %d times", repo.calls)
	}
	digest := sha256.Sum256([]byte("signed-token"))
	if !repo.revoked[hex.EncodeToString(digest[:])] {
		t.Fatal("token digest was not recorded")
	}
}

func TestAPIRevocationFailsClosedWhenRegistryUnavailable(t *testing.T) {
	repo := &fakeRepo{revocationErr: errors.New("database unavailable")}
	h := NewWithOptions(repo, "", "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Verifier: staticTokenVerifier{subject: "alice", expiresAt: time.Now().Add(time.Hour)}})
	response := request(h, http.MethodGet, "/v1/organizations", "", "signed-token")
	if response.Code != http.StatusServiceUnavailable || repo.calls != 0 {
		t.Fatalf("revocation registry outage did not fail closed: status=%d calls=%d", response.Code, repo.calls)
	}
}
