package store

import (
	"context"
	"strings"
)

type SchedulerSnapshot struct {
	QueueAgeSeconds    float64
	ActiveReservations int64
	BlockedByReason    map[string]int64
}

var blockedReasonAllowlist = map[string]struct{}{
	"ClusterDeploymentDegraded": {}, "ClusterWorkloadDegraded": {},
	"LocalOrPersistentDataPresent": {}, "ManagementDisconnected": {},
	"PDBBlocked": {}, "PersistentStorageAdapterRequired": {},
	"WorkloadIdentityOrScaleChanged": {}, "WorkloadRecoveryPending": {},
}

func boundedBlockedReason(reason string) string {
	if _, ok := blockedReasonAllowlist[strings.TrimSpace(reason)]; ok {
		return reason
	}
	return "other"
}

// SchedulerSnapshot reads low-cardinality queue and reservation signals from
// durable state. It intentionally excludes tenant, cluster, node and operation
// identifiers from metric dimensions.
func (s *Store) SchedulerSnapshot(ctx context.Context) (SchedulerSnapshot, error) {
	var snapshot SchedulerSnapshot
	snapshot.BlockedByReason = make(map[string]int64)
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(GREATEST(EXTRACT(EPOCH FROM now()-MIN(l.next_tick_at)),0),0)
FROM organization_limits l
WHERE l.next_tick_at<=now() AND EXISTS (
 SELECT 1 FROM campaigns c WHERE c.organization_id=l.organization_id
 AND c.phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures'))`).Scan(&snapshot.QueueAgeSeconds)
	if err != nil {
		return snapshot, err
	}
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM operation_reservations r
JOIN node_operations o ON o.id=r.operation_id
WHERE r.released_at IS NULL AND o.phase NOT IN ('Succeeded','Failed','Cancelled')`).Scan(&snapshot.ActiveReservations); err != nil {
		return snapshot, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT COALESCE(status->>'reason',''),count(*) FROM node_operations
WHERE phase IN ('Blocked','RecoveryRequired') GROUP BY status->>'reason'`)
	if err != nil {
		return snapshot, err
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		var count int64
		if err = rows.Scan(&reason, &count); err != nil {
			return snapshot, err
		}
		snapshot.BlockedByReason[boundedBlockedReason(reason)] += count
	}
	return snapshot, rows.Err()
}
