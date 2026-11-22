package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
	"kordex.local/api/protocol"
)

type NodeOperation struct {
	ID                string                      `json:"id"`
	OrganizationID    string                      `json:"organizationId"`
	ClusterID         string                      `json:"clusterId"`
	Request           protocol.MaintenanceRequest `json:"request"`
	Command           protocol.MaintenanceCommand `json:"command"`
	Phase             string                      `json:"phase"`
	Sequence          int64                       `json:"sequence"`
	Status            *protocol.OperationReport   `json:"status"`
	ExpiresAt         time.Time                   `json:"expiresAt"`
	DeliveredAt       *time.Time                  `json:"deliveredAt"`
	CampaignID        *string                     `json:"campaignId"`
	CancelRequestedAt *time.Time                  `json:"cancelRequestedAt"`
	CreatedAt         time.Time                   `json:"createdAt"`
	Evidence          *OperationEvidence          `json:"evidence,omitempty"`
}

// OperationEvidence is a point-in-time view of cluster inventory and agent
// connectivity when a campaign operation page is read. It is not a claim that
// the operation itself is progressing; local phase timestamps remain separate.
type OperationEvidence struct {
	InventoryObservedAt *time.Time `json:"inventoryObservedAt"`
	AgentLastSeenAt     *time.Time `json:"agentLastSeenAt"`
	InventoryFresh      bool       `json:"inventoryFresh"`
	AgentConnected      bool       `json:"agentConnected"`
}

func scanOperation(row pgx.Row) (NodeOperation, error) {
	var op NodeOperation
	var request, command, status []byte
	err := row.Scan(&op.ID, &op.OrganizationID, &op.ClusterID, &request, &command, &op.Phase, &op.Sequence, &status, &op.ExpiresAt, &op.DeliveredAt, &op.CreatedAt, &op.CampaignID, &op.CancelRequestedAt)
	if err != nil {
		return op, err
	}
	return decodeOperation(op, request, command, status)
}

func scanCampaignOperation(row pgx.Row) (NodeOperation, error) {
	var op NodeOperation
	var request, command, status []byte
	var evidence OperationEvidence
	err := row.Scan(&op.ID, &op.OrganizationID, &op.ClusterID, &request, &command, &op.Phase, &op.Sequence, &status, &op.ExpiresAt, &op.DeliveredAt, &op.CreatedAt, &op.CampaignID, &op.CancelRequestedAt,
		&evidence.InventoryObservedAt, &evidence.AgentLastSeenAt, &evidence.InventoryFresh, &evidence.AgentConnected)
	if err != nil {
		return op, err
	}
	op, err = decodeOperation(op, request, command, status)
	if err != nil {
		return op, err
	}
	op.Evidence = &evidence
	return op, nil
}

func decodeOperation(op NodeOperation, request, command, status []byte) (NodeOperation, error) {
	if err := json.Unmarshal(request, &op.Request); err != nil {
		return op, err
	}
	if err := json.Unmarshal(command, &op.Command); err != nil {
		return op, err
	}
	if op.Sequence == 0 {
		return op, nil
	}
	return op, json.Unmarshal(status, &op.Status)
}

func validateOperationReport(previous *protocol.OperationReport, request protocol.MaintenanceRequest, report protocol.OperationReport) error {
	if !report.ValidateForAction(request.Action) {
		return ErrConflict
	}
	if previous != nil {
		if err := protocol.ValidateOperationCheckpointAdvance(*previous, report); err != nil {
			return ErrConflict
		}
	}
	if report.UpgradeCheckpoint != nil && (request.Action != protocol.UpgradePackages || report.UpgradeCheckpoint.PlanDigest != request.PlanDigest || report.UpgradeCheckpoint.NodeUID != request.NodeUID) {
		return ErrConflict
	}
	if report.ProviderUpgradeCheckpoint != nil && (request.Action != protocol.UpgradeNodePool || report.ProviderUpgradeCheckpoint.PlanDigest != request.PlanDigest) {
		return ErrConflict
	}
	return nil
}

func operationCheckpointAudit(report protocol.OperationReport, previous *protocol.OperationReport) (string, json.RawMessage, bool, error) {
	if report.UpgradeCheckpoint == nil && report.ProviderUpgradeCheckpoint == nil {
		return "", nil, false, nil
	}
	if previous != nil && reflect.DeepEqual(previous.UpgradeCheckpoint, report.UpgradeCheckpoint) && reflect.DeepEqual(previous.ProviderUpgradeCheckpoint, report.ProviderUpgradeCheckpoint) {
		return "", nil, false, nil
	}
	action := "maintenance.upgrade_checkpoint"
	metadata := map[string]any{"upgradeCheckpoint": report.UpgradeCheckpoint}
	if report.ProviderUpgradeCheckpoint != nil {
		action = "maintenance.provider_upgrade_checkpoint"
		metadata = map[string]any{"providerUpgradeCheckpoint": report.ProviderUpgradeCheckpoint}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "", nil, false, err
	}
	return action, json.RawMessage(encoded), true, nil
}

const operationColumns = "id,organization_id,cluster_id,request,command,phase,sequence,status,expires_at,delivered_at,created_at,campaign_id,cancel_requested_at"

func expireUndelivered(ctx context.Context, tx pgx.Tx, cluster, org, requestID string) error {
	rows, err := tx.Query(ctx, "SELECT id FROM node_operations WHERE cluster_id=$1 AND delivered_at IS NULL AND phase='Pending' AND expires_at<=now() FOR UPDATE", cluster)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range ids {
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET phase='Failed',terminal_at=now() WHERE id=$1", id); err != nil {
			return err
		}
		if err = audit(ctx, tx, org, "control-plane", "maintenance.expired_before_delivery", id, requestID); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) CreateNodeOperation(ctx context.Context, org, cluster string, input protocol.MaintenanceRequest, key ed25519.PrivateKey, actor, requestID string) (NodeOperation, error) {
	if input.Validate() != nil || len(key) != ed25519.PrivateKeySize {
		return NodeOperation{}, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return NodeOperation{}, err
	}
	defer tx.Rollback(ctx)
	policy, err := lockOrganization(ctx, tx, org)
	if err != nil {
		return NodeOperation{}, err
	}
	op, err := s.createOperationTx(ctx, tx, org, cluster, input, key, actor, requestID, admission{OrganizationLimits: policy.Limits})
	if err != nil {
		return op, err
	}
	return op, tx.Commit(ctx)
}
func (s *Store) createOperationTx(ctx context.Context, tx pgx.Tx, org, cluster string, input protocol.MaintenanceRequest, key ed25519.PrivateKey, actor, requestID string, options admission) (NodeOperation, error) {
	var empty NodeOperation
	var err error
	var actual string
	var fleet, site string
	var uid *string
	var fresh bool
	var now time.Time
	err = tx.QueryRow(ctx, `SELECT organization_id,fleet_id,site_id,cluster_uid,coalesce(last_heartbeat_at>now()-interval '90 seconds' AND observed_at>now()-interval '90 seconds',false),now() FROM clusters WHERE id=$1 FOR UPDATE`, cluster).Scan(&actual, &fleet, &site, &uid, &fresh, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrNotFound
	}
	if err != nil {
		return empty, err
	}
	if actual != org {
		return empty, ErrNotFound
	}
	var lifecycleState string
	err = tx.QueryRow(ctx, "SELECT state FROM lab_lifecycle WHERE cluster_id=$1", cluster).Scan(&lifecycleState)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return empty, err
	}
	if err == nil && lifecycleState != LabRunning {
		return empty, ErrLabBarrier
	}
	existing, err := scanOperation(tx.QueryRow(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE id=$1", input.OperationID))
	if err == nil {
		if existing.OrganizationID != org || existing.ClusterID != cluster {
			return empty, ErrConflict
		}
		if existing.Request != input {
			return empty, ErrConflict
		}
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return empty, err
	}
	if uid == nil || !fresh {
		return empty, ErrStale
	}
	var known bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE cluster_id=$1 AND uid=$2 AND name=$3 AND present AND last_seen_at>now()-interval '90 seconds') AND EXISTS(SELECT 1 FROM agent_identities WHERE cluster_id=$1 AND revoked_at IS NULL AND expires_at>now())`, cluster, input.NodeUID, input.NodeName).Scan(&known); err != nil {
		return empty, err
	}
	if !known {
		return empty, ErrNotFound
	}
	var inventoryData []byte
	if err = tx.QueryRow(ctx, "SELECT inventory FROM nodes WHERE cluster_id=$1 AND uid=$2 AND name=$3 AND present AND last_seen_at>now()-interval '90 seconds'", cluster, input.NodeUID, input.NodeName).Scan(&inventoryData); err != nil {
		return empty, ErrSnapshotChanged
	}
	var node protocol.Node
	if err = json.Unmarshal(inventoryData, &node); err != nil || node.UID != input.NodeUID || node.Name != input.NodeName {
		return empty, ErrSnapshotChanged
	}
	zone := maintenanceZone(node)
	if options.Snapshot != nil {
		expected := options.Snapshot
		if expected.ClusterUID != *uid || expected.FleetID != fleet || expected.SiteID != site || expected.Node.UID != node.UID || expected.Node.Name != node.Name || maintenanceZone(expected.Node) != zone {
			return empty, ErrSnapshotChanged
		}
		selector, err := labels.Parse(options.Selector)
		if err != nil {
			return empty, err
		}
		if !node.Ready || node.ControlPlane || (options.Selector != "" && node.Labels == nil) || !selector.Matches(labels.Set(node.Labels)) {
			return empty, ErrSnapshotChanged
		}
	}
	if err = s.validatePolicyAdmission(ctx, tx, cluster, input, now); err != nil {
		return empty, err
	}
	if err = expireUndelivered(ctx, tx, cluster, org, requestID); err != nil {
		return empty, err
	}
	var busy bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM node_operations WHERE cluster_id=$1 AND phase NOT IN ('Succeeded','Failed','Cancelled'))", cluster).Scan(&busy); err != nil {
		return empty, err
	}
	if busy {
		return empty, ErrCapacity
	}
	if err = cleanupReservations(ctx, tx, org); err != nil {
		return empty, err
	}
	if err = checkCapacity(ctx, tx, org, fleet, site, zone, cluster, input.NodeUID, options.OrganizationLimits, nil); err != nil {
		return empty, err
	}
	if options.CampaignLimits != nil {
		if err = checkCapacity(ctx, tx, org, fleet, site, zone, cluster, input.NodeUID, *options.CampaignLimits, options.CampaignID); err != nil {
			return empty, err
		}
	}
	permit := protocol.MaintenancePermit{OrganizationID: org, ClusterID: cluster, ClusterUID: *uid, MaintenanceRequest: input, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(15 * time.Minute)}
	if options.WindowEnd != nil && permit.ExpiresAt.After(*options.WindowEnd) {
		permit.ExpiresAt = *options.WindowEnd
	}
	if !permit.ExpiresAt.After(now) {
		return empty, ErrStale
	}
	if options.CampaignID != nil {
		permit.CampaignID = *options.CampaignID
		permit.CampaignStage = options.Snapshot.Stage
		permit.CampaignPlanGeneration = options.PlanGeneration
		permit.SnapshotDigest = options.SnapshotDigest
		permit.Attempt = options.Attempt
	}
	command, err := protocol.SignMaintenance(permit, key)
	if err != nil {
		return empty, err
	}
	requestJSON, err := json.Marshal(input)
	if err != nil {
		return empty, err
	}
	commandJSON, err := json.Marshal(command)
	if err != nil {
		return empty, err
	}
	op, err := scanOperation(tx.QueryRow(ctx, "INSERT INTO node_operations(id,organization_id,cluster_id,request,command,expires_at,campaign_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING "+operationColumns, input.OperationID, org, cluster, string(requestJSON), string(commandJSON), permit.ExpiresAt, options.CampaignID))
	if err != nil {
		return empty, classify(err)
	}
	if err = reserve(ctx, tx, op.ID, org, fleet, site, zone, cluster, input.NodeUID, options.CampaignID); err != nil {
		return empty, err
	}
	if err = audit(ctx, tx, org, actor, "maintenance.requested", input.OperationID, requestID); err != nil {
		return empty, err
	}
	return op, nil
}

func maintenanceZone(node protocol.Node) string {
	zone, valid := validMaintenanceZone(node.Zone)
	if !valid {
		return ""
	}
	if node.Labels != nil {
		for _, labelKey := range []string{"topology.kubernetes.io/zone", "failure-domain.beta.kubernetes.io/zone"} {
			labelZone, valid := validMaintenanceZone(node.Labels[labelKey])
			if !valid {
				return ""
			}
			if labelZone == "" {
				continue
			}
			if zone != "" && zone != labelZone {
				return ""
			}
			zone = labelZone
		}
	}
	return zone
}

func validMaintenanceZone(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	return value, strings.TrimSpace(value) == value && len(validation.IsValidLabelValue(value)) == 0
}

func (s *Store) ListNodeOperations(ctx context.Context, org, cluster string, limit, offset int) ([]NodeOperation, error) {
	actual, err := s.ClusterOrganization(ctx, cluster)
	if err != nil {
		return nil, err
	}
	if actual != org {
		return nil, ErrNotFound
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE organization_id=$1 AND cluster_id=$2 ORDER BY created_at,id LIMIT $3 OFFSET $4", org, cluster, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []NodeOperation{}
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, op)
	}
	return items, rows.Err()
}
func (s *Store) SyncNodeOperations(ctx context.Context, cluster, key, nonce string, input protocol.OperationSync, requestID string) (protocol.OperationSyncResult, error) {
	if len(input.Reports) > 10 {
		return protocol.OperationSyncResult{}, ErrConflict
	}
	for _, report := range input.Reports {
		if !report.Validate() {
			return protocol.OperationSyncResult{}, ErrConflict
		}
	}
	result := protocol.OperationSyncResult{Controls: []protocol.OperationControl{}, Commands: []protocol.MaintenanceCommand{}, Acknowledged: map[string]int64{}}
	tx, org, err := s.beginAgent(ctx, cluster, key, nonce)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	var lifecycleState string
	err = tx.QueryRow(ctx, "SELECT state FROM lab_lifecycle WHERE cluster_id=$1", cluster).Scan(&lifecycleState)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if err == nil && len(input.Reports) > 0 && (lifecycleState == LabStopping || lifecycleState == LabStopped || lifecycleState == LabStarting) {
		// beginAgent holds the cluster row lock shared with lifecycle transitions.
		// Once shutdown owns STOPPING, no late report can reopen recovery after
		// the last blocker check. Reports may still advance during DRAINING so
		// already-admitted work can finish and be durably collected.
		return result, ErrLabBarrier
	}
	var hubNow time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&hubNow); err != nil {
		return result, err
	}
	for _, report := range input.Reports {
		if !report.ValidateAt(hubNow, protocol.ClockSkew) {
			return result, ErrConflict
		}
	}
	for _, report := range input.Reports {
		op, err := scanOperation(tx.QueryRow(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE id=$1 AND cluster_id=$2 FOR UPDATE", report.OperationID, cluster))
		if errors.Is(err, pgx.ErrNoRows) {
			return result, ErrNotFound
		}
		if err != nil {
			return result, err
		}
		if report.Sequence < op.Sequence {
			result.Acknowledged[op.ID] = op.Sequence
			continue
		}
		if report.Sequence == op.Sequence {
			incoming, err := json.Marshal(report)
			if err != nil {
				return result, err
			}
			previous, err := json.Marshal(op.Status)
			if err != nil {
				return result, err
			}
			if string(incoming) != string(previous) {
				return result, ErrConflict
			}
			result.Acknowledged[op.ID] = op.Sequence
			continue
		}
		if protocol.TerminalPhase(op.Phase) {
			return result, ErrConflict
		}
		if op.Sequence > 0 {
			if op.Status == nil || len(op.Status.Events) != int(op.Sequence) {
				return result, ErrConflict
			}
			previous, err := json.Marshal(op.Status.Events)
			if err != nil {
				return result, err
			}
			prefix, err := json.Marshal(report.Events[:op.Sequence])
			if err != nil {
				return result, err
			}
			if string(previous) != string(prefix) {
				return result, ErrConflict
			}
		}
		if err = validateOperationReport(op.Status, op.Request, report); err != nil {
			return result, err
		}
		for _, event := range report.Events {
			if event.Sequence <= op.Sequence {
				continue
			}
			metadata, err := json.Marshal(event)
			if err != nil {
				return result, err
			}
			if err = audit(ctx, tx, org, "agent:"+key, "maintenance."+event.Phase, op.ID, requestID, json.RawMessage(metadata)); err != nil {
				return result, err
			}
		}
		if action, metadata, changed, auditErr := operationCheckpointAudit(report, op.Status); auditErr != nil {
			return result, auditErr
		} else if changed {
			if err = audit(ctx, tx, org, "agent:"+key, action, op.ID, requestID, metadata); err != nil {
				return result, err
			}
		}
		data, err := json.Marshal(report)
		if err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET phase=$2,sequence=$3,status=$4,terminal_at=CASE WHEN $2 IN ('Succeeded','Failed','Cancelled') THEN now() ELSE terminal_at END WHERE id=$1", op.ID, report.Phase, report.Sequence, string(data)); err != nil {
			return result, err
		}
		if err = releaseTerminalReservation(ctx, tx, op.ID, report.Phase); err != nil {
			return result, err
		}
		result.Acknowledged[op.ID] = report.Sequence
	}
	if err = expireUndelivered(ctx, tx, cluster, org, requestID); err != nil {
		return result, err
	}
	controlRows, err := tx.Query(ctx, "SELECT x.payload FROM operation_controls x JOIN node_operations o ON o.id=x.operation_id WHERE o.cluster_id=$1 AND o.phase NOT IN ('Succeeded','Failed','Cancelled') ORDER BY o.id", cluster)
	if err != nil {
		return result, err
	}
	for controlRows.Next() {
		var data []byte
		var control protocol.OperationControl
		if err = controlRows.Scan(&data); err != nil {
			controlRows.Close()
			return result, err
		}
		if err = json.Unmarshal(data, &control); err != nil {
			controlRows.Close()
			return result, err
		}
		result.Controls = append(result.Controls, control)
	}
	if err = controlRows.Err(); err != nil {
		controlRows.Close()
		return result, err
	}
	controlRows.Close()
	rows, err := tx.Query(ctx, "SELECT id,command FROM node_operations WHERE cluster_id=$1 AND phase NOT IN ('Succeeded','Failed','Cancelled') ORDER BY created_at LIMIT 1", cluster)
	if err != nil {
		return result, err
	}
	var delivered []string
	for rows.Next() {
		var id string
		var data []byte
		var command protocol.MaintenanceCommand
		if err = rows.Scan(&id, &data); err != nil {
			rows.Close()
			return result, err
		}
		if err = json.Unmarshal(data, &command); err != nil {
			rows.Close()
			return result, err
		}
		result.Commands = append(result.Commands, command)
		delivered = append(delivered, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return result, err
	}
	rows.Close()
	for _, id := range delivered {
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET delivered_at=coalesce(delivered_at,now()) WHERE id=$1", id); err != nil {
			return result, err
		}
	}
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&result.ServerTime); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
