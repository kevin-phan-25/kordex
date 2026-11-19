package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"kordex.local/api/protocol"
	"time"
)

// Readiness is unknown when inventory or the reporting identity is stale.
const inventoryFresh = `coalesce(c.last_heartbeat_at>now()-interval '90 seconds' AND c.observed_at>now()-interval '90 seconds' AND EXISTS(SELECT 1 FROM agent_identities a WHERE a.cluster_id=c.id AND a.revoked_at IS NULL AND a.expires_at>now()),false)`

type DashboardSummary struct {
	Fleets               int        `json:"fleets"`
	Sites                int        `json:"sites"`
	Clusters             int        `json:"clusters"`
	Nodes                int        `json:"nodes"`
	HealthyNodes         int        `json:"healthyNodes"`
	UnhealthyNodes       int        `json:"unhealthyNodes"`
	UnknownNodes         int        `json:"unknownNodes"`
	DisconnectedClusters int        `json:"disconnectedClusters"`
	ActiveCampaigns      int        `json:"activeCampaigns"`
	FailedOperations     int        `json:"failedOperations"`
	PendingOperations    int        `json:"pendingOperations"`
	BlockedOperations    int        `json:"blockedOperations"`
	RetainedReservations int        `json:"retainedReservations"`
	OldestPendingAt      *time.Time `json:"oldestPendingAt"`
	ObservedAt           time.Time  `json:"observedAt"`
}

func (s *Store) DashboardSummary(ctx context.Context, org string) (DashboardSummary, error) {
	var v DashboardSummary
	err := s.Pool.QueryRow(ctx, `WITH inventory AS (SELECT n.inventory,`+inventoryFresh+` fresh FROM nodes n JOIN clusters c ON c.id=n.cluster_id WHERE c.organization_id=$1)
 SELECT (SELECT count(*) FROM fleets WHERE organization_id=$1),(SELECT count(*) FROM sites WHERE organization_id=$1),(SELECT count(*) FROM clusters WHERE organization_id=$1),(SELECT count(*) FROM inventory),
 (SELECT count(*) FROM inventory WHERE fresh AND (inventory->>'ready')::boolean),(SELECT count(*) FROM inventory WHERE fresh AND NOT (inventory->>'ready')::boolean),(SELECT count(*) FROM inventory WHERE NOT fresh),
 (SELECT count(*) FROM clusters c WHERE organization_id=$1 AND NOT (`+inventoryFresh+`)),
 (SELECT count(*) FROM campaigns WHERE organization_id=$1 AND phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures')),
 (SELECT count(*) FROM node_operations WHERE organization_id=$1 AND phase='Failed'),(SELECT count(*) FROM node_operations WHERE organization_id=$1 AND phase='Pending'),
 (SELECT count(*) FROM node_operations WHERE organization_id=$1 AND phase IN ('Blocked','RecoveryRequired')),
 (SELECT count(*) FROM operation_reservations r JOIN node_operations o ON o.id=r.operation_id WHERE r.organization_id=$1 AND r.released_at IS NULL AND o.phase NOT IN ('Succeeded','Failed','Cancelled')),
 (SELECT min(created_at) FROM node_operations WHERE organization_id=$1 AND phase='Pending'),now()`, org).Scan(&v.Fleets, &v.Sites, &v.Clusters, &v.Nodes, &v.HealthyNodes, &v.UnhealthyNodes, &v.UnknownNodes, &v.DisconnectedClusters, &v.ActiveCampaigns, &v.FailedOperations, &v.PendingOperations, &v.BlockedOperations, &v.RetainedReservations, &v.OldestPendingAt, &v.ObservedAt)
	return v, err
}

type InventoryFilter struct{ ClusterID, FleetID, SiteID, Health, Search, NodeUID string }
type InventoryNode struct {
	ClusterID   string        `json:"clusterId"`
	ClusterName string        `json:"clusterName"`
	FleetID     string        `json:"fleetId"`
	SiteID      string        `json:"siteId"`
	ObservedAt  *time.Time    `json:"observedAt"`
	Fresh       bool          `json:"fresh"`
	Node        protocol.Node `json:"node"`
}

func (s *Store) ListInventoryNodes(ctx context.Context, org string, f InventoryFilter, limit, offset int) ([]InventoryNode, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id,c.name,c.fleet_id,c.site_id,c.observed_at,`+inventoryFresh+`,n.inventory FROM nodes n JOIN clusters c ON c.id=n.cluster_id WHERE c.organization_id=$1
 AND ($2='' OR c.id::text=$2) AND ($3='' OR c.fleet_id::text=$3) AND ($4='' OR c.site_id::text=$4)
 AND ($5='' OR ($5='unknown' AND NOT (`+inventoryFresh+`)) OR ($5='healthy' AND (`+inventoryFresh+`) AND (n.inventory->>'ready')::boolean) OR ($5='unhealthy' AND (`+inventoryFresh+`) AND NOT (n.inventory->>'ready')::boolean))
 AND ($6='' OR n.uid=$6)
 AND ($7='' OR position(lower($7) in lower(n.name||' '||coalesce(n.inventory->>'osImage','')||' '||c.name))>0) ORDER BY c.name,c.id,n.name,n.uid LIMIT $8 OFFSET $9`, org, f.ClusterID, f.FleetID, f.SiteID, f.Health, f.NodeUID, f.Search, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []InventoryNode{}
	for rows.Next() {
		var item InventoryNode
		var data []byte
		if err = rows.Scan(&item.ClusterID, &item.ClusterName, &item.FleetID, &item.SiteID, &item.ObservedAt, &item.Fresh, &data); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &item.Node); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

type AuditEntry struct {
	ID             int64           `json:"id"`
	OrganizationID string          `json:"organizationId"`
	Actor          string          `json:"actor"`
	Action         string          `json:"action"`
	ResourceID     string          `json:"resourceId"`
	RequestID      string          `json:"requestId"`
	OccurredAt     time.Time       `json:"occurredAt"`
	Metadata       json.RawMessage `json:"metadata"`
	PreviousHash   string          `json:"previousHash"`
	EventHash      string          `json:"eventHash"`
}

func (s *Store) ListAudit(ctx context.Context, org, search string, ascending bool, afterID, throughID int64, limit, offset int) ([]AuditEntry, error) {
	order := "occurred_at DESC,id DESC"
	query := `SELECT id,organization_id,actor,action,resource_id,request_id,occurred_at,metadata,previous_hash,event_hash FROM audit_events WHERE organization_id=$1 AND ($2='' OR position(lower($2) in lower(actor||' '||action||' '||resource_id::text))>0) AND ($3=0 OR id<$3) AND ($4=0 OR id<=$4) ORDER BY ` + order + ` LIMIT $5 OFFSET $6`
	if ascending {
		query = `SELECT id,organization_id,actor,action,resource_id,request_id,occurred_at,metadata,previous_hash,event_hash FROM audit_events WHERE organization_id=$1 AND ($2='' OR position(lower($2) in lower(actor||' '||action||' '||resource_id::text))>0) AND ($3=0 OR id>$3) AND ($4=0 OR id<=$4) ORDER BY id ASC LIMIT $5 OFFSET $6`
	}
	rows, err := s.Pool.Query(ctx, query, org, search, afterID, throughID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AuditEntry{}
	for rows.Next() {
		var item AuditEntry
		var previous, current []byte
		if err = rows.Scan(&item.ID, &item.OrganizationID, &item.Actor, &item.Action, &item.ResourceID, &item.RequestID, &item.OccurredAt, &item.Metadata, &previous, &current); err != nil {
			return nil, err
		}
		if len(previous) != 0 {
			item.PreviousHash = hex.EncodeToString(previous)
		}
		if len(current) != 0 {
			item.EventHash = hex.EncodeToString(current)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListInventoryFleets(ctx context.Context, org string, limit, offset int) ([]Fleet, error) {
	return s.ListFleets(ctx, org, limit, offset)
}
func (s *Store) ListInventorySites(ctx context.Context, org string, limit, offset int) ([]Site, error) {
	return s.ListSites(ctx, org, limit, offset)
}
func (s *Store) ListInventoryClusters(ctx context.Context, org string, limit, offset int) ([]Cluster, error) {
	return s.ListClusters(ctx, org, limit, offset)
}
