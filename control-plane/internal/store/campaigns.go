package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/labels"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
)

type Campaign struct {
	ID                string        `json:"id"`
	OrganizationID    string        `json:"organizationId"`
	Spec              campaign.Spec `json:"spec"`
	Phase             string        `json:"phase"`
	Reason            string        `json:"reason"`
	Revision          int64         `json:"revision"`
	PlanGeneration    int64         `json:"planGeneration"`
	Stage             int           `json:"stage"`
	ApprovalEpoch     int64         `json:"approvalEpoch"`
	SnapshotDigest    string        `json:"snapshotDigest"`
	CreatedBy         string        `json:"createdBy"`
	FailedBaseline    int           `json:"failedBaseline"`
	CompletedBaseline int           `json:"completedBaseline"`
	TerminalAfterStop string        `json:"terminalAfterStop"`
	CreatedAt         time.Time     `json:"createdAt"`
	UpdatedAt         time.Time     `json:"updatedAt"`
	Progress          Progress      `json:"progress"`
}
type Progress struct {
	Total               int `json:"total"`
	Pending             int `json:"pending"`
	Active              int `json:"active"`
	RetryWaiting        int `json:"retryWaiting"`
	Succeeded           int `json:"succeeded"`
	Failed              int `json:"failed"`
	Cancelled           int `json:"cancelled"`
	CompletedAttempts   int `json:"completedAttempts"`
	FailedAttempts      int `json:"failedAttempts"`
	ConsecutiveFailures int `json:"consecutiveFailures"`
}
type CampaignTarget struct {
	ID            string          `json:"id"`
	Snapshot      campaign.Target `json:"snapshot"`
	State         string          `json:"state"`
	Reason        string          `json:"reason"`
	Attempts      int             `json:"attempts"`
	Failures      int             `json:"failures"`
	NextAttemptAt time.Time       `json:"nextAttemptAt"`
}
type CampaignEvent struct {
	ID        int64           `json:"id"`
	Revision  int64           `json:"revision"`
	Actor     string          `json:"actor"`
	Kind      string          `json:"kind"`
	Details   json.RawMessage `json:"details"`
	CreatedAt time.Time       `json:"createdAt"`
}
type Approval struct {
	ID             string    `json:"id"`
	Stage          int       `json:"stage"`
	PlanGeneration int64     `json:"planGeneration"`
	Epoch          int64     `json:"epoch"`
	Digest         string    `json:"digest"`
	Actor          string    `json:"actor"`
	Decision       string    `json:"decision"`
	CreatedAt      time.Time `json:"createdAt"`
}

const campaignColumns = "id,organization_id,spec,phase,reason,revision,plan_generation,stage,approval_epoch,snapshot_digest,created_by,failed_baseline,completed_baseline,terminal_after_stop,created_at,updated_at"

func scanCampaign(row pgx.Row) (Campaign, error) {
	var c Campaign
	var spec []byte
	err := row.Scan(&c.ID, &c.OrganizationID, &spec, &c.Phase, &c.Reason, &c.Revision, &c.PlanGeneration, &c.Stage, &c.ApprovalEpoch, &c.SnapshotDigest, &c.CreatedBy, &c.FailedBaseline, &c.CompletedBaseline, &c.TerminalAfterStop, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(spec, &c.Spec)
}
func getCampaignTx(ctx context.Context, tx pgx.Tx, org, id string) (Campaign, error) {
	c, err := scanCampaign(tx.QueryRow(ctx, "SELECT "+campaignColumns+" FROM campaigns WHERE organization_id=$1 AND id=$2 FOR UPDATE", org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}
func campaignEvent(ctx context.Context, tx pgx.Tx, c *Campaign, actor, kind, request string, details any) error {
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}
	spec, err := json.Marshal(c.Spec)
	if err != nil {
		return err
	}
	c.Revision++
	err = tx.QueryRow(ctx, `UPDATE campaigns SET spec=$3,phase=$4,reason=$5,revision=$6,plan_generation=$7,stage=$8,approval_epoch=$9,snapshot_digest=$10,failed_baseline=$11,completed_baseline=$12,terminal_after_stop=$13,updated_at=now() WHERE organization_id=$1 AND id=$2 RETURNING updated_at`, c.OrganizationID, c.ID, string(spec), c.Phase, c.Reason, c.Revision, c.PlanGeneration, c.Stage, c.ApprovalEpoch, c.SnapshotDigest, c.FailedBaseline, c.CompletedBaseline, c.TerminalAfterStop).Scan(&c.UpdatedAt)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO campaign_events(campaign_id,organization_id,revision,actor,kind,details,request_id) VALUES ($1,$2,$3,$4,$5,$6,$7)", c.ID, c.OrganizationID, c.Revision, actor, kind, string(data), request); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE organization_limits SET next_tick_at=now() WHERE organization_id=$1", c.OrganizationID); err != nil {
		return err
	}
	return audit(ctx, tx, c.OrganizationID, actor, "campaign."+kind, c.ID, request)
}
func (s *Store) CreateCampaign(ctx context.Context, org, id string, spec campaign.Spec, actor, request string) (Campaign, error) {
	normalized, err := spec.Normalize()
	if err != nil || !protocol.ValidUUID(id) {
		return Campaign{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Campaign{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganization(ctx, tx, org); err != nil {
		return Campaign{}, err
	}
	existing, err := getCampaignTx(ctx, tx, org, id)
	if err == nil {
		a, err := json.Marshal(existing.Spec)
		if err != nil {
			return existing, err
		}
		b, err := json.Marshal(normalized)
		if err != nil {
			return existing, err
		}
		if string(a) != string(b) {
			return existing, ErrConflict
		}
		return existing, tx.Commit(ctx)
	}
	if !errors.Is(err, ErrNotFound) {
		return Campaign{}, err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return Campaign{}, err
	}
	c, err := scanCampaign(tx.QueryRow(ctx, "INSERT INTO campaigns(id,organization_id,spec,created_by,revision) VALUES ($1,$2,$3,$4,0) RETURNING "+campaignColumns, id, org, string(data), actor))
	if err != nil {
		return c, classify(err)
	}
	if err = campaignEvent(ctx, tx, &c, actor, "created", request, map[string]any{"planGeneration": c.PlanGeneration}); err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}
func (s *Store) UpdateCampaign(ctx context.Context, org, id string, revision int64, spec campaign.Spec, actor, request string) (Campaign, error) {
	normalized, err := spec.Normalize()
	if err != nil {
		return Campaign{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Campaign{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganization(ctx, tx, org); err != nil {
		return Campaign{}, err
	}
	c, err := getCampaignTx(ctx, tx, org, id)
	if err != nil {
		return c, err
	}
	if c.Revision != revision || c.Phase != "Draft" {
		return c, ErrConflict
	}
	c.Spec = normalized
	c.PlanGeneration++
	if err = campaignEvent(ctx, tx, &c, actor, "plan_updated", request, map[string]any{"planGeneration": c.PlanGeneration}); err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}
func snapshotTargets(ctx context.Context, tx pgx.Tx, org string, spec campaign.Spec) ([]campaign.Target, string, error) {
	for _, scope := range []struct {
		table string
		ids   []string
	}{{"clusters", spec.Selection.ClusterIDs}, {"fleets", spec.Selection.FleetIDs}, {"sites", spec.Selection.SiteIDs}} {
		if len(scope.ids) == 0 {
			continue
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+scope.table+" WHERE organization_id=$1 AND id=ANY($2::uuid[])", org, scope.ids).Scan(&count); err != nil {
			return nil, "", err
		}
		if count != len(scope.ids) {
			return nil, "", ErrNotFound
		}
	}
	rows, err := tx.Query(ctx, `SELECT c.id,c.cluster_uid,c.fleet_id,c.site_id,n.inventory,c.maintenance_policy_catalog,
 coalesce(c.maintenance_policy_catalog_observed_at>now()-interval '90 seconds',false),
 coalesce(c.last_heartbeat_at>now()-interval '90 seconds' AND c.observed_at>now()-interval '90 seconds',false)
 FROM clusters c JOIN nodes n ON n.cluster_id=c.id WHERE c.organization_id=$1 AND ($2::uuid[] IS NULL OR c.id=ANY($2)) AND ($3::uuid[] IS NULL OR c.fleet_id=ANY($3)) AND ($4::uuid[] IS NULL OR c.site_id=ANY($4)) ORDER BY c.site_id,c.id,n.uid LIMIT 20001`, org, nilIfEmpty(spec.Selection.ClusterIDs), nilIfEmpty(spec.Selection.FleetIDs), nilIfEmpty(spec.Selection.SiteIDs))
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	bindings := map[string]campaign.PolicyBinding{}
	for _, binding := range spec.Policies {
		bindings[binding.ClusterID] = binding
	}
	type policyCatalogState struct {
		entries map[string]protocol.MaintenancePolicyCatalogEntry
	}
	catalogs := map[string]policyCatalogState{}
	selector, err := labels.Parse(spec.Selection.NodeSelector)
	if err != nil {
		return nil, "", ErrInvalid
	}
	targets := []campaign.Target{}
	scanned := 0
	for rows.Next() {
		scanned++
		if scanned > 20000 {
			return nil, "", ErrInvalid
		}
		var target campaign.Target
		var uid *string
		var data, catalogData []byte
		var fresh, catalogFresh bool
		if err = rows.Scan(&target.ClusterID, &uid, &target.FleetID, &target.SiteID, &data, &catalogData, &catalogFresh, &fresh); err != nil {
			return nil, "", err
		}
		if err = json.Unmarshal(data, &target.Node); err != nil {
			return nil, "", err
		}
		if target.Node.ControlPlane {
			continue
		}
		if spec.Selection.NodeSelector != "" && target.Node.Labels == nil {
			return nil, "", ErrStale
		}
		if !selector.Matches(labels.Set(target.Node.Labels)) {
			continue
		}
		if !fresh || uid == nil || !target.Node.Ready {
			return nil, "", ErrStale
		}
		target.ClusterUID = *uid
		binding, ok := bindings[target.ClusterID]
		if !ok {
			return nil, "", ErrInvalid
		}
		target.Policy = binding.Policy
		target.PlanDigest = binding.PlanDigest
		if spec.Action == protocol.UpgradePackages || spec.Action == protocol.UpgradeNodePool {
			if !catalogFresh || len(catalogData) == 0 {
				return nil, "", ErrStale
			}
			state, loaded := catalogs[target.ClusterID]
			if !loaded {
				var catalog protocol.MaintenancePolicyCatalog
				if err = json.Unmarshal(catalogData, &catalog); err != nil || catalog.Items == nil {
					return nil, "", ErrStale
				}
				state.entries = make(map[string]protocol.MaintenancePolicyCatalogEntry, len(catalog.Items))
				for _, item := range catalog.Items {
					if _, duplicate := state.entries[item.Policy.Name]; duplicate {
						return nil, "", ErrStale
					}
					state.entries[item.Policy.Name] = item
				}
				catalogs[target.ClusterID] = state
			}
			entry, found := state.entries[binding.Policy.Name]
			if !found || entry.Policy != binding.Policy {
				return nil, "", ErrStale
			}
			if entry.Suspended {
				return nil, "", ErrInvalid
			}
			selector, selectorErr := metav1.LabelSelectorAsSelector(&entry.NodeSelector)
			if selectorErr != nil {
				return nil, "", ErrStale
			}
			if !selector.Matches(labels.Set(target.Node.Labels)) {
				continue
			}
			if spec.Action == protocol.UpgradePackages {
				if entry.Upgrade == nil || entry.UpgradePlanInvalid || entry.UpgradePlanDigest != binding.PlanDigest {
					return nil, "", ErrStale
				}
				digest, digestErr := entry.Upgrade.Digest()
				if digestErr != nil || digest != entry.UpgradePlanDigest {
					return nil, "", ErrStale
				}
			} else {
				if entry.ProviderUpgrade == nil || entry.ProviderPlanInvalid || entry.ProviderPlanDigest != binding.PlanDigest {
					return nil, "", ErrStale
				}
				digest, digestErr := entry.ProviderUpgrade.Digest()
				if digestErr != nil || digest != entry.ProviderPlanDigest {
					return nil, "", ErrStale
				}
			}
		}
		targets = append(targets, target)
		if len(targets) > campaign.MaxTargets {
			return nil, "", ErrInvalid
		}
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	if len(targets) == 0 {
		return nil, "", ErrInvalid
	}
	return campaign.Plan(targets, spec)
}
func nilIfEmpty(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return values
}
func (s *Store) StartCampaign(ctx context.Context, org, id string, revision int64, actor, request string) (Campaign, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Campaign{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganization(ctx, tx, org); err != nil {
		return Campaign{}, err
	}
	c, err := getCampaignTx(ctx, tx, org, id)
	if err != nil {
		return c, err
	}
	if c.Revision != revision || c.Phase != "Draft" {
		return c, ErrConflict
	}
	targets, digest, err := snapshotTargets(ctx, tx, org, c.Spec)
	if err != nil {
		return c, err
	}
	rows := make([][]any, 0, len(targets))
	for _, target := range targets {
		data, err := json.Marshal(target)
		if err != nil {
			return c, err
		}
		rows = append(rows, []any{NewID(), id, org, target.ClusterID, target.FleetID, target.SiteID, target.Node.UID, target.Node.Name, string(data), target.Ordinal, target.Stage})
	}
	if _, err = tx.CopyFrom(ctx, pgx.Identifier{"campaign_targets"}, []string{"id", "campaign_id", "organization_id", "cluster_id", "fleet_id", "site_id", "node_uid", "node_name", "snapshot", "ordinal", "stage"}, pgx.CopyFromRows(rows)); err != nil {
		return c, err
	}
	for i, window := range c.Spec.Windows {
		if _, err = tx.Exec(ctx, "INSERT INTO campaign_windows(campaign_id,ordinal,start_at,end_at,time_zone) VALUES ($1,$2,$3,$4,$5)", id, i, window.Start.UTC(), window.End.UTC(), window.TimeZone); err != nil {
			return c, err
		}
	}
	c.SnapshotDigest = digest
	c.Phase = "Scheduled"
	c.Reason = "TargetsSnapshotted"
	if c.Spec.NeedsApproval(0) {
		c.Phase = "AwaitingApproval"
		c.Reason = "IndependentApprovalRequired"
	}
	if err = campaignEvent(ctx, tx, &c, actor, "started", request, map[string]any{"snapshotDigest": digest, "targets": len(targets), "planGeneration": c.PlanGeneration}); err != nil {
		return c, err
	}
	c.Progress, err = campaignProgress(ctx, tx, id)
	if err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}

type progressReader interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func progressBatch(ctx context.Context, db progressReader, ids []string) (map[string]Progress, error) {
	rows, err := db.Query(ctx, `WITH target_counts AS (
 SELECT campaign_id,count(*) total,count(*) FILTER(WHERE state='Pending') pending,count(*) FILTER(WHERE state='Active') active,count(*) FILTER(WHERE state='RetryWaiting') retry,count(*) FILTER(WHERE state='Succeeded') succeeded,count(*) FILTER(WHERE state='Failed') failed,count(*) FILTER(WHERE state='Cancelled') cancelled
 FROM campaign_targets WHERE campaign_id=ANY($1::uuid[]) GROUP BY campaign_id), ranked AS (
 SELECT campaign_id,phase,row_number() OVER(PARTITION BY campaign_id ORDER BY finished_at DESC,operation_id DESC) rn FROM campaign_attempts WHERE campaign_id=ANY($1::uuid[]) AND finished_at IS NOT NULL), attempt_counts AS (
 SELECT campaign_id,count(*) completed,count(*) FILTER(WHERE phase='Failed') failed,coalesce(min(rn) FILTER(WHERE phase='Succeeded')-1,count(*)) consecutive FROM ranked GROUP BY campaign_id)
 SELECT t.campaign_id,t.total,t.pending,t.active,t.retry,t.succeeded,t.failed,t.cancelled,coalesce(a.completed,0),coalesce(a.failed,0),coalesce(a.consecutive,0) FROM target_counts t LEFT JOIN attempt_counts a USING(campaign_id)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]Progress{}
	for rows.Next() {
		var id string
		var p Progress
		if err = rows.Scan(&id, &p.Total, &p.Pending, &p.Active, &p.RetryWaiting, &p.Succeeded, &p.Failed, &p.Cancelled, &p.CompletedAttempts, &p.FailedAttempts, &p.ConsecutiveFailures); err != nil {
			return nil, err
		}
		result[id] = p
	}
	return result, rows.Err()
}
func campaignProgress(ctx context.Context, tx pgx.Tx, id string) (Progress, error) {
	result, err := progressBatch(ctx, tx, []string{id})
	return result[id], err
}
func (s *Store) GetCampaign(ctx context.Context, org, id string) (Campaign, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Campaign{}, err
	}
	defer tx.Rollback(ctx)
	c, err := scanCampaign(tx.QueryRow(ctx, "SELECT "+campaignColumns+" FROM campaigns WHERE organization_id=$1 AND id=$2", org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.Progress, err = campaignProgress(ctx, tx, id)
	if err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}
func (s *Store) ListCampaigns(ctx context.Context, org string, limit, offset int) ([]Campaign, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+campaignColumns+" FROM campaigns WHERE organization_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3", org, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Campaign{}
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	ids := make([]string, len(items))
	for i := range items {
		ids[i] = items[i].ID
	}
	if len(ids) > 0 {
		progress, err := progressBatch(ctx, s.Pool, ids)
		if err != nil {
			return nil, err
		}
		for i := range items {
			items[i].Progress = progress[items[i].ID]
		}
	}
	return items, nil
}
func (s *Store) ListCampaignTargets(ctx context.Context, org, id string, limit, offset int) ([]CampaignTarget, error) {
	if _, err := s.GetCampaign(ctx, org, id); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,snapshot,state,reason,attempts,failures,next_attempt_at FROM campaign_targets WHERE campaign_id=$1 ORDER BY ordinal LIMIT $2 OFFSET $3", id, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CampaignTarget{}
	for rows.Next() {
		var item CampaignTarget
		var data []byte
		if err = rows.Scan(&item.ID, &data, &item.State, &item.Reason, &item.Attempts, &item.Failures, &item.NextAttemptAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(data, &item.Snapshot); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Store) ListCampaignEvents(ctx context.Context, org, id string, limit, offset int) ([]CampaignEvent, error) {
	if _, err := s.GetCampaign(ctx, org, id); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,revision,actor,kind,details,created_at FROM campaign_events WHERE campaign_id=$1 ORDER BY id LIMIT $2 OFFSET $3", id, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CampaignEvent{}
	for rows.Next() {
		var item CampaignEvent
		if err = rows.Scan(&item.ID, &item.Revision, &item.Actor, &item.Kind, &item.Details, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Store) ListCampaignApprovals(ctx context.Context, org, id string, limit, offset int) ([]Approval, error) {
	if _, err := s.GetCampaign(ctx, org, id); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,stage,plan_generation,approval_epoch,snapshot_digest,actor,decision,created_at FROM campaign_approvals WHERE campaign_id=$1 ORDER BY created_at,id LIMIT $2 OFFSET $3", id, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Approval{}
	for rows.Next() {
		var item Approval
		if err = rows.Scan(&item.ID, &item.Stage, &item.PlanGeneration, &item.Epoch, &item.Digest, &item.Actor, &item.Decision, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
