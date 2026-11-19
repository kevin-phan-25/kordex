package health

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthAndReadinessReflectLeaderAndRecentSuccessfulSync(t *testing.T) {
	state := New(time.Minute)
	started := state.startedAt
	if got := state.SnapshotAt(started.Add(time.Second)); got.Ready || got.Leader {
		t.Fatalf("new agent reported ready before leader sync: %+v", got)
	}
	state.SetLeader(true)
	state.RecordCycle(nil)
	lastSuccess := *state.SnapshotAt(time.Now().UTC()).LastSuccessfulSync
	if got := state.SnapshotAt(lastSuccess.Add(30 * time.Second)); !got.Ready || !got.Leader {
		t.Fatalf("leader with fresh successful sync is not ready: %+v", got)
	}
	if got := state.SnapshotAt(lastSuccess.Add(time.Minute + time.Second)); got.Ready {
		t.Fatalf("stale sync reported ready: %+v", got)
	}
	state.SetLeader(false)
	if got := state.SnapshotAt(lastSuccess.Add(time.Second)); got.Ready || got.Leader {
		t.Fatalf("non-leader reported ready: %+v", got)
	}

	response := httptest.NewRecorder()
	state.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("liveness failed during non-ready state: %d %q", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	state.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"ready":false`) {
		t.Fatalf("readiness did not report not-ready state: %d %s", response.Code, response.Body.String())
	}
}

func TestHealthDiagnosticsRedactCycleErrorsAndRecoverReadiness(t *testing.T) {
	state := New(time.Minute)
	state.SetLeader(true)
	state.RecordCycle(errors.New("authorization header contains private-token"))
	snapshot := state.SnapshotAt(time.Now().UTC())
	if snapshot.Ready || snapshot.ConsecutiveFailures != 1 || snapshot.LastFailureCode != "CycleFailed" {
		t.Fatalf("failed cycle status is incorrect: %+v", snapshot)
	}
	response := httptest.NewRecorder()
	state.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if strings.Contains(response.Body.String(), "private-token") || strings.Contains(response.Body.String(), "authorization header") {
		t.Fatal("agent diagnostics exposed raw cycle error data")
	}
	state.RecordCycle(nil)
	snapshot = state.SnapshotAt(time.Now().UTC())
	if !snapshot.Ready || snapshot.ConsecutiveFailures != 0 || snapshot.LastFailureCode != "" {
		t.Fatalf("successful cycle did not restore readiness: %+v", snapshot)
	}

	response = httptest.NewRecorder()
	state.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("health endpoint accepted non-GET method: %d", response.Code)
	}
}
