package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type Snapshot struct {
	Ready               bool       `json:"ready"`
	Leader              bool       `json:"leader"`
	StartedAt           time.Time  `json:"startedAt"`
	LastSuccessfulSync  *time.Time `json:"lastSuccessfulSync,omitempty"`
	LastFailedSync      *time.Time `json:"lastFailedSync,omitempty"`
	ConsecutiveFailures uint64     `json:"consecutiveFailures"`
	LastFailureCode     string     `json:"lastFailureCode,omitempty"`
}

// State records only non-sensitive connection and worker health signals. It
// deliberately does not expose raw errors, credentials, node names, or tokens.
type State struct {
	mu                  sync.RWMutex
	startedAt           time.Time
	maxSyncAge          time.Duration
	leader              bool
	lastSuccessfulSync  *time.Time
	lastFailedSync      *time.Time
	consecutiveFailures uint64
	lastFailureCode     string
}

func New(maxSyncAge time.Duration) *State {
	if maxSyncAge <= 0 {
		maxSyncAge = 90 * time.Second
	}
	return &State{startedAt: time.Now().UTC(), maxSyncAge: maxSyncAge}
}

func (s *State) SetLeader(leader bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leader = leader
}

func (s *State) RecordCycle(err error) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.lastSuccessfulSync = &now
		s.consecutiveFailures = 0
		s.lastFailureCode = ""
		return
	}
	s.lastFailedSync = &now
	s.consecutiveFailures++
	s.lastFailureCode = "CycleFailed"
}

func (s *State) SnapshotAt(now time.Time) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lastSuccess, lastFailure *time.Time
	if s.lastSuccessfulSync != nil {
		v := *s.lastSuccessfulSync
		lastSuccess = &v
	}
	if s.lastFailedSync != nil {
		v := *s.lastFailedSync
		lastFailure = &v
	}
	ready := false
	if s.leader && lastSuccess != nil {
		age := now.Sub(*lastSuccess)
		ready = age >= 0 && age <= s.maxSyncAge
	}
	return Snapshot{
		Ready: ready, Leader: s.leader, StartedAt: s.startedAt,
		LastSuccessfulSync: lastSuccess, LastFailedSync: lastFailure,
		ConsecutiveFailures: s.consecutiveFailures, LastFailureCode: s.lastFailureCode,
	}
}

func (s *State) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snapshot := s.SnapshotAt(time.Now().UTC())
		if !snapshot.Ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(snapshot)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}
