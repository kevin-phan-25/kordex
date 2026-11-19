package store

import (
	"context"
	"strings"
)

type SchedulerSnapshot struct {
	QueueAgeSeconds      float64
	ActiveReservations   int64
	OldestReservationAge float64
	BlockedByReason      map[string]int64
	ClustersTotal        int64
	ClustersConnected    int64
	NodesTotal           int64
	HealthyNodes         int64
	UnhealthyNodes       int64
	UnknownNodes         int64
	OldestHeartbeatAge   float64
	OldestInventoryAge   float64
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

// SchedulerSnapshot reads low-cardinality queue, reservation, connectivity,
// and readiness signals from durable state. It intentionally excludes tenant,
// cluster, node and operation identifiers from metric dimensions.
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
	err = s.Pool.QueryRow(ctx, `WITH cluster_state AS (
 SELECT c.id,c.last_heartbeat_at,c.observed_at,c.created_at,
   (c.last_heartbeat_at>now()-interval '90 seconds' AND EXISTS (
     SELECT 1 FROM agent_identities a WHERE a.cluster_id=c.id
       AND a.revoked_at IS NULL AND a.expires_at>now())) connected,
   coalesce(c.observed_at,c.created_at) inventory_time,
   coalesce(c.last_heartbeat_at,c.created_at) heartbeat_time,
   EXISTS(SELECT 1 FROM agent_identities a WHERE a.cluster_id=c.id
     AND a.revoked_at IS NULL AND a.expires_at>now()) identity_active
 FROM clusters c
), node_state AS (
 SELECT n.inventory,
   coalesce(n.present AND n.last_seen_at>now()-interval '90 seconds' AND cs.last_heartbeat_at>now()-interval '90 seconds' AND cs.observed_at>now()-interval '90 seconds' AND cs.identity_active,false) fresh
 FROM nodes n JOIN cluster_state cs ON cs.id=n.cluster_id
)
SELECT
 (SELECT count(*) FROM cluster_state),
 (SELECT count(*) FROM cluster_state WHERE connected),
 (SELECT count(*) FROM node_state),
 (SELECT count(*) FROM node_state WHERE fresh AND inventory->'ready' = 'true'::jsonb),
 (SELECT count(*) FROM node_state WHERE fresh AND inventory->'ready' = 'false'::jsonb),
 (SELECT count(*) FROM node_state WHERE NOT fresh OR NOT (inventory ? 'ready') OR inventory->'ready' NOT IN ('true'::jsonb,'false'::jsonb)),
 coalesce((SELECT max(greatest(extract(epoch FROM now()-heartbeat_time),0)) FROM cluster_state),0),
 coalesce((SELECT max(greatest(extract(epoch FROM now()-inventory_time),0)) FROM cluster_state),0)`).Scan(
		&snapshot.ClustersTotal, &snapshot.ClustersConnected, &snapshot.NodesTotal,
		&snapshot.HealthyNodes, &snapshot.UnhealthyNodes, &snapshot.UnknownNodes,
		&snapshot.OldestHeartbeatAge, &snapshot.OldestInventoryAge,
	)
	if err != nil {
		return snapshot, err
	}
	if err = s.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(greatest(extract(epoch FROM now()-r.created_at),0)),0) FROM operation_reservations r
JOIN node_operations o ON o.id=r.operation_id
WHERE r.released_at IS NULL AND o.phase NOT IN ('Succeeded','Failed','Cancelled')`).Scan(&snapshot.ActiveReservations, &snapshot.OldestReservationAge); err != nil {
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
