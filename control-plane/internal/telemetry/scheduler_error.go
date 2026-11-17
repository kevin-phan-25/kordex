package telemetry

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"kordex.local/control-plane/internal/store"
)

var schedulerErrorClasses = map[string]struct{}{
	"cancelled": {}, "capacity": {}, "context_timeout": {}, "database": {}, "database_connection": {},
	"database_constraint": {}, "internal": {}, "not_found": {}, "query_timeout": {},
	"safety_conflict": {}, "serialization_conflict": {}, "stale_evidence": {},
	"unauthorized": {}, "other": {},
}

// ClassifySchedulerError returns a low-cardinality diagnostic class without
// exposing SQL text, tenant data, or operation payloads in logs or metrics.
func ClassifySchedulerError(err error) string {
	if err == nil {
		return "other"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_timeout"
	case errors.Is(err, store.ErrCapacity):
		return "capacity"
	case errors.Is(err, store.ErrSiteHealth), errors.Is(err, store.ErrSnapshotChanged), errors.Is(err, store.ErrUpgradeAdmission):
		return "safety_conflict"
	case errors.Is(err, store.ErrStale):
		return "stale_evidence"
	case errors.Is(err, store.ErrUnauthorized), errors.Is(err, store.ErrForbidden):
		return "unauthorized"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "40001" || pgErr.Code == "40P01":
			return "serialization_conflict"
		case pgErr.Code == "57014":
			return "query_timeout"
		case strings.HasPrefix(pgErr.Code, "08"):
			return "database_connection"
		case strings.HasPrefix(pgErr.Code, "23"):
			return "database_constraint"
		default:
			return "database"
		}
	}
	return "internal"
}
