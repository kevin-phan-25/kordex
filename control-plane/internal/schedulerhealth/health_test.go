package schedulerhealth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthAndSchedulerReadiness(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	h := New(15 * time.Second)
	h.now = func() time.Time { return now }
	handler := h.Handler()
	request := func(path string) int {
		t.Helper()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder.Code
	}

	if got := request("/healthz"); got != http.StatusOK {
		t.Fatalf("liveness status = %d, want %d", got, http.StatusOK)
	}
	if got := request("/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("readiness before a successful tick = %d, want %d", got, http.StatusServiceUnavailable)
	}

	h.RecordSuccessfulTick(now)
	if got := request("/readyz"); got != http.StatusOK {
		t.Fatalf("readiness after a successful tick = %d, want %d", got, http.StatusOK)
	}

	now = now.Add(16 * time.Second)
	if got := request("/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("stale readiness = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if got := request("/healthz"); got != http.StatusOK {
		t.Fatalf("stale database readiness changed process liveness to %d", got)
	}

	h.RecordSuccessfulTick(now.Add(time.Second))
	if got := request("/readyz"); got != http.StatusServiceUnavailable {
		t.Fatalf("future scheduler tick = %d, want %d", got, http.StatusServiceUnavailable)
	}
}
