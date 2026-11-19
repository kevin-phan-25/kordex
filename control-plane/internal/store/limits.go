package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/campaign"
)

var ErrCapacity = fmt.Errorf("concurrency or availability capacity exhausted: %w", ErrConflict)
var ErrSiteHealth = errors.New("site health unknown")
var ErrSnapshotChanged = errors.New("target snapshot changed")
var ErrInvalid = errors.New("invalid campaign request")
var ErrForbidden = errors.New("campaign action forbidden")

type ConcurrencyPolicy struct {
	Limits   campaign.Limits `json:"limits"`
	Revision int64           `json:"revision"`
}

func lockOrganization(ctx context.Context, tx pgx.Tx, org string) (ConcurrencyPolicy, error) {
	var result ConcurrencyPolicy
	var data []byte
	err := tx.QueryRow(ctx, "SELECT limits,revision FROM organization_limits WHERE organization_id=$1 FOR UPDATE", org).Scan(&data, &result.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result.Limits)
	result.Limits = result.Limits.WithDefaults()
	return result, err
}
func (s *Store) GetConcurrencyPolicy(ctx context.Context, org string) (ConcurrencyPolicy, error) {
	var result ConcurrencyPolicy
	var data []byte
	err := s.Pool.QueryRow(ctx, "SELECT limits,revision FROM organization_limits WHERE organization_id=$1", org).Scan(&data, &result.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result.Limits)
	result.Limits = result.Limits.WithDefaults()
	return result, err
}
func (s *Store) SetConcurrencyPolicy(ctx context.Context, org string, expected int64, limits campaign.Limits, actor, request string) (ConcurrencyPolicy, error) {
	limits = limits.WithDefaults()
	if limits.Validate() != nil {
		return ConcurrencyPolicy{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ConcurrencyPolicy{}, err
	}
	defer tx.Rollback(ctx)
	policy, err := lockOrganization(ctx, tx, org)
	if err != nil {
		return policy, err
	}
	if policy.Revision != expected {
		return policy, ErrConflict
	}
	data, err := json.Marshal(limits)
	if err != nil {
		return policy, err
	}
	if _, err = tx.Exec(ctx, "UPDATE organization_limits SET limits=$2,revision=revision+1,next_tick_at=now() WHERE organization_id=$1", org, string(data)); err != nil {
		return policy, err
	}
	if err = audit(ctx, tx, org, actor, "concurrency.updated", org, request); err != nil {
		return policy, err
	}
	policy.Limits = limits
	policy.Revision++
	return policy, tx.Commit(ctx)
}
func cleanupReservations(ctx context.Context, tx pgx.Tx, org string) error {
	_, err := tx.Exec(ctx, `UPDATE operation_reservations r SET released_at=now() FROM node_operations o WHERE o.id=r.operation_id AND r.organization_id=$1 AND r.released_at IS NULL AND o.phase IN ('Succeeded','Failed','Cancelled')`, org)
	return err
}

// All admissions hold organization_limits FOR UPDATE before locking cluster rows.
// Terminal status can only reduce usage; no delivery or scheduler timeout frees a reservation.
func checkCapacity(ctx context.Context, tx pgx.Tx, org, fleet, site, zone, cluster, node string, limits campaign.Limits, campaignID *string) error {
	var organizationCount, fleetCount, siteCount, zoneCount, clusterCount, nodeCount int
	err := tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE r.fleet_id=$2),count(*) FILTER(WHERE r.site_id=$3),count(*) FILTER(WHERE $4='' OR r.zone_id='' OR r.zone_id=$4),count(*) FILTER(WHERE r.cluster_id=$5),count(*) FILTER(WHERE r.cluster_id=$5 AND r.node_uid=$6)
 FROM operation_reservations r JOIN node_operations o ON o.id=r.operation_id WHERE r.organization_id=$1 AND r.released_at IS NULL AND o.phase NOT IN ('Succeeded','Failed','Cancelled') AND ($7::uuid IS NULL OR r.campaign_id=$7)`, org, fleet, site, zone, cluster, node, campaignID).Scan(&organizationCount, &fleetCount, &siteCount, &zoneCount, &clusterCount, &nodeCount)
	if err != nil {
		return err
	}
	if organizationCount >= limits.Organization || fleetCount >= limits.Fleet || siteCount >= limits.Site || zoneCount >= limits.Zone || clusterCount >= limits.Cluster || nodeCount >= limits.Node {
		return ErrCapacity
	}
	var stale bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clusters c WHERE c.organization_id=$1 AND c.site_id=$2 AND (c.last_heartbeat_at IS NULL OR c.observed_at IS NULL OR c.last_heartbeat_at<=now()-interval '90 seconds' OR c.observed_at<=now()-interval '90 seconds' OR NOT EXISTS(SELECT 1 FROM agent_identities a WHERE a.cluster_id=c.id AND a.revoked_at IS NULL AND a.expires_at>now())))`, org, site).Scan(&stale); err != nil {
		return err
	}
	if stale {
		return ErrSiteHealth
	}
	var unavailable int
	var already bool
	err = tx.QueryRow(ctx, `WITH unavailable AS (
 SELECT n.cluster_id,n.uid FROM nodes n JOIN clusters c ON c.id=n.cluster_id WHERE c.organization_id=$1 AND c.site_id=$2 AND NOT coalesce((n.inventory->>'controlPlane')::boolean,false) AND NOT coalesce((n.inventory->>'ready')::boolean,false)
 UNION SELECT r.cluster_id,r.node_uid FROM operation_reservations r JOIN node_operations o ON o.id=r.operation_id WHERE r.organization_id=$1 AND r.site_id=$2 AND r.released_at IS NULL AND o.phase NOT IN ('Succeeded','Failed','Cancelled'))
 SELECT count(*),coalesce(bool_or(cluster_id=$3 AND uid=$4),false) FROM unavailable`, org, site, cluster, node).Scan(&unavailable, &already)
	if err != nil {
		return err
	}
	if !already {
		unavailable++
	}
	if unavailable > limits.MaxUnavailablePerSite {
		return ErrCapacity
	}
	return nil
}
func reserve(ctx context.Context, tx pgx.Tx, operation, org, fleet, site, zone, cluster, node string, campaignID *string) error {
	_, err := tx.Exec(ctx, "INSERT INTO operation_reservations(operation_id,organization_id,fleet_id,site_id,zone_id,cluster_id,node_uid,campaign_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", operation, org, fleet, site, zone, cluster, node, campaignID)
	return err
}

type admission struct {
	OrganizationLimits campaign.Limits
	CampaignLimits     *campaign.Limits
	CampaignID         *string
	Snapshot           *campaign.Target
	SnapshotDigest     string
	PlanGeneration     int64
	Attempt            int
	WindowEnd          *time.Time
	Selector           string
}
