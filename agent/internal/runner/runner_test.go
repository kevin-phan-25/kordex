package runner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"kordex.local/agent/internal/client"
	"kordex.local/agent/internal/state"
	"kordex.local/api/protocol"
)

type collector struct{}

func (collector) ClusterUID(context.Context) (string, error) { return "kube-system-uid", nil }
func (collector) Collect(context.Context) (protocol.Report, error) {
	return protocol.Report{ClusterUID: "kube-system-uid", ObservedAt: time.Now(), KubernetesVersion: "v1.35.0", Nodes: []protocol.Node{}}, nil
}
func TestLostRotationResponseAndRestart(t *testing.T) {
	var public ed25519.PublicKey
	var lastVersion int64
	failRotation := true
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		respond := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Error(err)
			}
		}
		if r.URL.Path == "/v1/agent/enroll" {
			var e protocol.Enrollment
			if err := json.Unmarshal(body, &e); err != nil {
				t.Error(err)
			}
			var err error
			public, err = protocol.DecodeKey(e.PublicKey)
			if err != nil || !protocol.VerifyProof(public, protocol.EnrollmentMessage(e), e.Proof) {
				t.Error("invalid enrollment")
			}
			respond(protocol.Identity{ClusterID: e.ClusterID, KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(time.Hour)})
			return
		}
		if len(public) == 0 || !protocol.Verify(r, public, body, time.Now()) {
			w.WriteHeader(401)
			respond(map[string]string{"error": "unauthorized"})
			return
		}
		switch r.URL.Path {
		case "/v1/agent/identity":
			respond(protocol.Identity{ClusterID: r.Header.Get("X-Kordex-Cluster"), KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(24 * time.Hour)})
		case "/v1/agent/rotate":
			var rotation protocol.Rotation
			if err := json.Unmarshal(body, &rotation); err != nil {
				t.Error(err)
			}
			next, err := protocol.DecodeKey(rotation.PublicKey)
			if err != nil || !protocol.VerifyProof(next, protocol.RotationMessage(r.Header.Get("X-Kordex-Cluster"), protocol.KeyID(public), rotation.PublicKey), rotation.Proof) {
				t.Error("invalid rotation")
			}
			public = next
			if failRotation {
				failRotation = false
				w.WriteHeader(503)
				respond(map[string]string{"error": "lost_response"})
				return
			}
			respond(protocol.Identity{KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(24 * time.Hour)})
		case "/v1/agent/report":
			var report protocol.Report
			if err := json.Unmarshal(body, &report); err != nil {
				t.Error(err)
			}
			if report.Version <= lastVersion {
				t.Error("replayed inventory version")
			}
			lastVersion = report.Version
			respond(map[string]string{"status": "accepted"})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	remote, err := client.New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote.HTTP = server.Client()
	durable := state.FileStore{Path: filepath.Join(t.TempDir(), "identity.json")}
	worker := Runner{Client: remote, Store: durable, Collector: collector{}, EnrollmentToken: "single-use-test-token", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	if err = worker.Step(context.Background()); err == nil {
		t.Fatal("expected lost rotation response")
	}
	saved, err := durable.Load(context.Background())
	if err != nil || len(saved.PendingKey) == 0 {
		t.Fatal("pending rotation not persisted")
	}
	restarted := worker
	restarted.EnrollmentToken = ""
	if err = restarted.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = restarted.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err = durable.Load(context.Background())
	if err != nil || len(saved.PendingKey) != 0 || saved.Version != 2 || lastVersion != 2 {
		t.Fatal("rotation/restart state did not recover")
	}
}

func TestLostEnrollmentResponseRecoversPersistedKey(t *testing.T) {
	var public ed25519.PublicKey
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		respond := func(v any) {
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Error(err)
			}
		}
		if r.URL.Path == "/v1/agent/enroll" {
			var e protocol.Enrollment
			if err := json.Unmarshal(body, &e); err != nil {
				t.Error(err)
			}
			var err error
			public, err = protocol.DecodeKey(e.PublicKey)
			if err != nil {
				t.Error(err)
			}
			w.WriteHeader(503)
			respond(map[string]string{"error": "lost_enrollment_response"})
			return
		}
		if len(public) == 0 || !protocol.Verify(r, public, body, time.Now()) {
			w.WriteHeader(401)
			respond(map[string]string{"error": "unauthorized"})
			return
		}
		if r.URL.Path == "/v1/agent/identity" {
			respond(protocol.Identity{ClusterID: r.Header.Get("X-Kordex-Cluster"), KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(24 * time.Hour)})
			return
		}
		respond(map[string]string{"status": "accepted"})
	}))
	defer server.Close()
	c, err := client.New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = server.Client()
	durable := state.FileStore{Path: filepath.Join(t.TempDir(), "state.json")}
	r := Runner{Client: c, Store: durable, Collector: collector{}, EnrollmentToken: "test", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	if err = r.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved, err := durable.Load(context.Background())
	if err != nil || saved.Version != 1 {
		t.Fatal("enrollment response recovery failed")
	}
}
