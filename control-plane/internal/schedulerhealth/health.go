package schedulerhealth

import (
	"net/http"
	"sync/atomic"
	"time"
)

// Health reports process liveness and recent successful scheduler transactions.
// Readiness stays false until a database-backed scheduler tick has succeeded.
type Health struct {
	maxTickAge time.Duration
	lastTick   atomic.Int64
	now        func() time.Time
}

func New(maxTickAge time.Duration) *Health {
	return &Health{maxTickAge: maxTickAge, now: time.Now}
}

func (h *Health) RecordSuccessfulTick(at time.Time) {
	h.lastTick.Store(at.UnixNano())
}

func (h *Health) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		last := h.lastTick.Load()
		age := h.now().Sub(time.Unix(0, last))
		if last == 0 || h.maxTickAge <= 0 || age < 0 || age > h.maxTickAge {
			http.Error(w, "no recent successful scheduler tick", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}
