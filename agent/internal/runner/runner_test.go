package runner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
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

type cancelCycleObserver struct {
	cancelOnError bool
	cancel        context.CancelFunc
}

func (o cancelCycleObserver) RecordCycle(err error) {
	if o.cancelOnError && err != nil || !o.cancelOnError && err == nil {
		o.cancel()
	}
}

type cycleFailureSignal chan error

func (s cycleFailureSignal) RecordCycle(err error) {
	if err != nil {
		select {
		case s <- err:
		default:
		}
	}
}

func TestRunRetriesTransientManagementOutageWithIncreasingInventoryVersion(t *testing.T) {
	server, attempts, versions := retryTestServer(t)
	defer server.Close()
	remote, err := client.New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote.HTTP = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	worker := Runner{
		Client: remote, Store: state.FileStore{Path: filepath.Join(t.TempDir(), "retry-state.json")},
		Collector: collector{}, EnrollmentToken: "retry-test-token", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Interval: 2 * time.Millisecond,
	}
	worker.Observer = cancelCycleObserver{cancel: cancel}
	if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error=%v, want cancellation after successful retry", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("report attempts=%d, want one failed attempt and one successful retry", got)
	}
	if first, second := <-versions, <-versions; first != 1 || second != 2 {
		t.Fatalf("report versions=(%d, %d), want monotonic versions (1, 2)", first, second)
	}
}

func TestRunCancellationStopsRetryLoopAfterCurrentFailedCycle(t *testing.T) {
	server, attempts, _ := retryTestServer(t)
	defer server.Close()
	remote, err := client.New(server.URL, "80bd80f9-f097-4474-86f4-b80986fd5423", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote.HTTP = server.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	failures := make(cycleFailureSignal, 1)
	worker := Runner{
		Client: remote, Store: state.FileStore{Path: filepath.Join(t.TempDir(), "cancel-state.json")},
		Collector: collector{}, EnrollmentToken: "retry-test-token", Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Interval: time.Second,
	}
	worker.Observer = failures
	go func() {
		<-failures
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	if err := worker.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error=%v, want cancellation after failed cycle", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancellation took %s while retry timer was active", elapsed)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("report attempts=%d after cancellation, want 1", got)
	}
}

func TestRetryBackoffAndJitterStayBounded(t *testing.T) {
	cases := []struct {
		current time.Duration
		want    time.Duration
	}{
		{current: 500 * time.Millisecond, want: time.Second},
		{current: 15 * time.Second, want: 30 * time.Second},
		{current: 2 * time.Minute, want: 4 * time.Minute},
		{current: 3 * time.Minute, want: maximumRetryBackoff},
		{current: maximumRetryBackoff, want: maximumRetryBackoff},
		{current: time.Duration(1<<63 - 1), want: maximumRetryBackoff},
	}
	for _, test := range cases {
		if got := nextRetryBackoff(test.current); got != test.want {
			t.Errorf("nextRetryBackoff(%s)=%s, want %s", test.current, got, test.want)
		}
	}
	if got := nextRetryBackoff(0); got <= 0 {
		t.Fatalf("nextRetryBackoff(0)=%s, must remain positive", got)
	}
	minimum := jitteredRetryDelay(maximumRetryBackoff, 0)
	maximum := jitteredRetryDelay(maximumRetryBackoff, 255)
	if minimum != maximumRetryBackoff || maximum <= minimum || maximum > maximumRetryBackoff+maximumRetryBackoff/4 {
		t.Fatalf("jitter bounds are invalid: min=%s max=%s", minimum, maximum)
	}
	if got := jitteredRetryDelay(time.Duration(1<<63-1), 255); got > maximumRetryBackoff+maximumRetryBackoff/4 {
		t.Fatalf("unbounded input produced excessive retry delay: %s", got)
	}
}

func retryTestServer(t *testing.T) (*httptest.Server, *atomic.Int32, chan int64) {
	t.Helper()
	var public ed25519.PublicKey
	var reports atomic.Int32
	versions := make(chan int64, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		respond := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(value); err != nil {
				t.Error(err)
			}
		}
		if r.URL.Path == "/v1/agent/enroll" {
			var enrollment protocol.Enrollment
			if err := json.Unmarshal(body, &enrollment); err != nil {
				t.Error(err)
			}
			var err error
			public, err = protocol.DecodeKey(enrollment.PublicKey)
			if err != nil {
				t.Error(err)
			}
			respond(protocol.Identity{ClusterID: enrollment.ClusterID, KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(24 * time.Hour)})
			return
		}
		if len(public) == 0 || !protocol.Verify(r, public, body, time.Now()) {
			w.WriteHeader(http.StatusUnauthorized)
			respond(map[string]string{"error": "unauthorized"})
			return
		}
		switch r.URL.Path {
		case "/v1/agent/identity":
			respond(protocol.Identity{ClusterID: r.Header.Get("X-Kordex-Cluster"), KeyID: protocol.KeyID(public), ExpiresAt: time.Now().Add(24 * time.Hour)})
		case "/v1/agent/report":
			var report protocol.Report
			if err := json.Unmarshal(body, &report); err != nil {
				t.Error(err)
			}
			versions <- report.Version
			attempt := reports.Add(1)
			if attempt == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				respond(map[string]string{"error": "temporary_unavailable"})
				return
			}
			respond(map[string]string{"status": "accepted"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, &reports, versions
}
