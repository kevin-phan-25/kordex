package telemetry

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"kordex.local/control-plane/internal/store"
)

func TestClassifySchedulerError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: "context_timeout"},
		{name: "capacity", err: store.ErrCapacity, want: "capacity"},
		{name: "safety", err: store.ErrUpgradeAdmission, want: "safety_conflict"},
		{name: "serialization", err: &pgconn.PgError{Code: "40001", Message: "private database details"}, want: "serialization_conflict"},
		{name: "deadlock", err: &pgconn.PgError{Code: "40P01"}, want: "serialization_conflict"},
		{name: "query timeout", err: &pgconn.PgError{Code: "57014"}, want: "query_timeout"},
		{name: "connection", err: &pgconn.PgError{Code: "08006"}, want: "database_connection"},
		{name: "constraint", err: &pgconn.PgError{Code: "23505"}, want: "database_constraint"},
		{name: "unknown", err: errors.New("secret request data"), want: "internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifySchedulerError(test.err); got != test.want {
				t.Fatalf("ClassifySchedulerError() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSchedulerErrorMetricsUseBoundedClass(t *testing.T) {
	metrics := NewSchedulerMetrics()
	metrics.RecordError("database_connection")
	metrics.RecordError("attacker-controlled-label")
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	if !strings.Contains(body, `kordex_scheduler_errors_total{class="database_connection"} 1`) || !strings.Contains(body, `kordex_scheduler_errors_total{class="other"} 1`) {
		t.Fatalf("bounded scheduler error metrics missing: %s", body)
	}
	if strings.Contains(body, "attacker-controlled-label") {
		t.Fatal("unbounded scheduler error label was exported")
	}
}
