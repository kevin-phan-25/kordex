package httpapi

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kordex.local/control-plane/internal/store"
)

const token = "test-token-with-at-least-32-characters"

type fakeRepo struct {
	calls int
	err   error
	org   string
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
