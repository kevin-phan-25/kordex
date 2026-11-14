package store_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/httpapi"
	"kordex.local/control-plane/internal/store"
)

type subjectVerifier struct{ Subject string }

func (v subjectVerifier) Verify(_ context.Context, token string) (string, error) {
	if token == "viewer-token" {
		return v.Subject, nil
	}
	return "", errors.New("invalid token")
}
func TestRegistrationAndTenantIsolation(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("database required in CI")
		}
		t.Skip("disposable database not configured")
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
	reqID := store.NewID()
	org, err := db.CreateOrganization(ctx, "registration-"+store.NewID(), "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := db.CreateOrganization(ctx, "other-"+store.NewID(), "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	site, err := db.CreateSite(ctx, org.ID, "dc1", "us-east", "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := db.CreateFleet(ctx, org.ID, "primary", "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := db.CreateFleet(ctx, other.ID, "foreign", "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: foreign.ID, SiteID: site.ID, Name: "invalid", Provider: "self-managed"}, "test", reqID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant fleet accepted: %v", err)
	}
	cluster, err := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: site.ID, Name: "cluster1", Provider: "self-managed"}, "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	e := protocol.Enrollment{ClusterID: cluster.ID, ClusterUID: "kube-" + store.NewID(), Token: enrollment.Token, PublicKey: protocol.EncodeKey(public)}
	originalUID := e.ClusterUID
	e.Proof = protocol.Proof(private, protocol.EnrollmentMessage(e))
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	viewerSubject := "viewer-" + store.NewID()
	handler := httpapi.NewWithOptions(db, "bootstrap-admin-test-token-with-32-characters", "Kordex", logger, httpapi.Options{Verifier: subjectVerifier{Subject: viewerSubject}, AllowBootstrap: false})
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	makeRequest := func(method, path string, value any, key ed25519.PrivateKey) *http.Request {
		var body []byte
		if value != nil {
			body, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, "https://hub.example"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if key != nil {
			protocol.Sign(r, cluster.ID, key, body, time.Now())
		}
		return r
	}
	spec, err := openapi3.NewLoader().LoadFromFile("../../../api/openapi/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	expect := func(r *http.Request, status int) {
		t.Helper()
		w := serve(r)
		if w.Code != status {
			t.Fatalf("%s %s: got %d expected %d: %s", r.Method, r.URL.Path, w.Code, status, w.Body.String())
		}
		if path := spec.Paths.Value(r.URL.Path); path != nil {
			operation := path.GetOperation(r.Method)
			response := operation.Responses.Status(w.Code)
			if response == nil {
				t.Fatalf("undocumented response %d", w.Code)
			}
			schema := response.Value.Content.Get("application/json").Schema.Value
			var data any
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			if err := schema.VisitJSON(data); err != nil {
				t.Fatalf("response violates contract: %v", err)
			}
		}
	}
	expect(makeRequest("POST", "/v1/agent/enroll", e, nil), 201)
	expect(makeRequest("POST", "/v1/agent/enroll", e, nil), 401)
	if _, err = db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", reqID); !errors.Is(err, store.ErrConflict) {
		t.Fatal("enrollment issued over active identity")
	}
	// A nonce is durable across new repository pools and handler instances.
	replay := makeRequest("GET", "/v1/agent/identity", nil, private)
	expect(replay, 200)
	restartedPool, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedPool.Close()
	handler = httpapi.NewWithOptions(restartedPool, "bootstrap-admin-test-token-with-32-characters", "Kordex", logger, httpapi.Options{Verifier: subjectVerifier{Subject: viewerSubject}, AllowBootstrap: false})
	expect(replay.Clone(ctx), 401)
	old := makeRequest("GET", "/v1/agent/identity", nil, private)
	protocol.Sign(old, cluster.ID, private, nil, time.Now().Add(-3*time.Minute))
	expect(old, 401)
	report := protocol.Report{ClusterUID: e.ClusterUID, Version: 1, ObservedAt: time.Now().UTC(), KubernetesVersion: "v1.37.0", Nodes: []protocol.Node{{UID: "node-uid", Name: "node1", OSImage: "Linux", Ready: true}}}
	expect(makeRequest("POST", "/v1/agent/report", report, private), 200)
	expect(makeRequest("POST", "/v1/agent/report", report, private), 409)
	report.Version = 2
	report.ObservedAt = time.Now().Add(-3 * time.Minute)
	expect(makeRequest("POST", "/v1/agent/report", report, private), 400)
	report.ObservedAt = time.Now().UTC()
	report.Nodes = append(report.Nodes, report.Nodes[0])
	expect(makeRequest("POST", "/v1/agent/report", report, private), 400)
	nodes, err := db.ListNodes(ctx, org.ID, cluster.ID, 100, 0)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "node1" {
		t.Fatalf("inventory not persisted: %v", err)
	}
	if _, err = db.ListNodes(ctx, other.ID, cluster.ID, 100, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross-tenant nodes accessible")
	}
	if err = db.SetMembership(ctx, org.ID, viewerSubject, "viewer", "test", reqID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		value        any
		status       int
	}{
		{"GET", "/v1/organizations/" + org.ID + "/sites", nil, 200},
		{"HEAD", "/v1/organizations/" + org.ID + "/sites", map[string]string{"name": "must-not-create", "region": "us-east"}, 200},
		{"GET", "/v1/organizations/" + other.ID + "/sites", nil, 403},
		{"POST", "/v1/organizations/" + org.ID + "/fleets", map[string]string{"name": "denied"}, 403},
		{"PUT", "/v1/organizations/" + org.ID + "/memberships", map[string]string{"subject": "viewer-a", "role": "administrator"}, 403},
	} {
		r := makeRequest(tc.method, tc.path, tc.value, nil)
		r.Header.Set("Authorization", "Bearer viewer-token")
		expect(r, tc.status)
	}
	r := makeRequest("GET", "/v1/organizations", nil, nil)
	r.Header.Set("Authorization", "Bearer viewer-token")
	w := serve(r)
	var page struct {
		Items []store.Organization `json:"items"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &page); err != nil || w.Code != 200 || len(page.Items) != 1 || page.Items[0].ID != org.ID {
		t.Fatal("organization enumeration leaked tenant data")
	}
	nextPublic, nextPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rotation := protocol.Rotation{PublicKey: protocol.EncodeKey(nextPublic)}
	rotation.Proof = protocol.Proof(nextPrivate, protocol.RotationMessage(cluster.ID, protocol.KeyID(public), rotation.PublicKey))
	expect(makeRequest("POST", "/v1/agent/rotate", rotation, private), 200)
	expect(makeRequest("GET", "/v1/agent/identity", nil, private), 401)
	expect(makeRequest("GET", "/v1/agent/identity", nil, nextPrivate), 200)
	if _, err = db.Pool.Exec(ctx, "UPDATE agent_identities SET expires_at=now()-interval '1 minute' WHERE cluster_id=$1", cluster.ID); err != nil {
		t.Fatal(err)
	}
	expect(makeRequest("GET", "/v1/agent/identity", nil, nextPrivate), 401)
	if _, err = db.Pool.Exec(ctx, "UPDATE agent_identities SET expires_at=now()+interval '1 hour' WHERE cluster_id=$1", cluster.ID); err != nil {
		t.Fatal(err)
	}
	if err = db.RevokeAgent(ctx, org.ID, cluster.ID, "test", reqID); err != nil {
		t.Fatal(err)
	}
	expect(makeRequest("GET", "/v1/agent/identity", nil, nextPrivate), 401)
	// A new enrollment cannot silently replace the immutable Kubernetes cluster UID.
	fresh, err := db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", reqID)
	if err != nil {
		t.Fatal(err)
	}
	e.Token = fresh.Token
	e.ClusterUID = "replacement-cluster"
	e.Proof = protocol.Proof(private, protocol.EnrollmentMessage(e))
	expect(makeRequest("POST", "/v1/agent/enroll", e, nil), 401)
	e.ClusterUID = originalUID
	e.Proof = protocol.Proof(private, protocol.EnrollmentMessage(e))
	if _, err = db.Pool.Exec(ctx, "UPDATE enrollment_tokens SET expires_at=now()-interval '1 minute' WHERE cluster_id=$1", cluster.ID); err != nil {
		t.Fatal(err)
	}
	expect(makeRequest("POST", "/v1/agent/enroll", e, nil), 401)
}

func TestEnrollmentConcurrencyAndExpiredToken(t *testing.T) {
	dsn := os.Getenv("KORDEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable database not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	id := store.NewID()
	org, err := db.CreateOrganization(ctx, "enrollment-race-"+id, "test", id)
	if err != nil {
		t.Fatal(err)
	}
	site, err := db.CreateSite(ctx, org.ID, "site", "lab", "test", id)
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := db.CreateFleet(ctx, org.ID, "fleet", "test", id)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := db.CreateCluster(ctx, store.Cluster{OrganizationID: org.ID, FleetID: fleet.ID, SiteID: site.ID, Name: "race", Provider: "self-managed"}, "test", id)
	if err != nil {
		t.Fatal(err)
	}
	token, err := db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", id)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	e := protocol.Enrollment{ClusterID: cluster.ID, ClusterUID: "race-" + id, Token: token.Token, PublicKey: protocol.EncodeKey(pub)}
	e.Proof = protocol.Proof(key, protocol.EnrollmentMessage(e))
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { _, err := db.EnrollAgent(ctx, e, store.NewID()); results <- err }()
	}
	succeeded := 0
	for i := 0; i < 8; i++ {
		err := <-results
		if err == nil {
			succeeded++
		} else if !errors.Is(err, store.ErrUnauthorized) {
			t.Fatalf("unexpected enrollment error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("single-use enrollment succeeded %d times", succeeded)
	}
	if err = db.RevokeAgent(ctx, org.ID, cluster.ID, "test", id); err != nil {
		t.Fatal(err)
	}
	token, err = db.IssueEnrollment(ctx, org.ID, cluster.ID, "test", id)
	if err != nil {
		t.Fatal(err)
	}
	e.Token = token.Token
	e.Proof = protocol.Proof(key, protocol.EnrollmentMessage(e))
	if _, err = db.Pool.Exec(ctx, "UPDATE enrollment_tokens SET expires_at=now()-interval '1 minute' WHERE token_hash=$1", protocol.TokenHash(token.Token)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.EnrollAgent(ctx, e, id); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("expired enrollment token accepted")
	}
}
