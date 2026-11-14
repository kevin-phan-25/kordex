package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/protocol"
)

type NodeOperation struct {
	ID             string                      `json:"id"`
	OrganizationID string                      `json:"organizationId"`
	ClusterID      string                      `json:"clusterId"`
	Request        protocol.MaintenanceRequest `json:"request"`
	Command        protocol.MaintenanceCommand `json:"command"`
	Phase          string                      `json:"phase"`
	Sequence       int64                       `json:"sequence"`
	Status         *protocol.OperationReport   `json:"status"`
	ExpiresAt      time.Time                   `json:"expiresAt"`
	DeliveredAt    *time.Time                  `json:"deliveredAt"`
	CreatedAt      time.Time                   `json:"createdAt"`
}

func scanOperation(row pgx.Row) (NodeOperation, error) {
	var op NodeOperation
	var request, command, status []byte
	err := row.Scan(&op.ID, &op.OrganizationID, &op.ClusterID, &request, &command, &op.Phase, &op.Sequence, &status, &op.ExpiresAt, &op.DeliveredAt, &op.CreatedAt)
	if err != nil {
		return op, err
	}
	if err = json.Unmarshal(request, &op.Request); err != nil {
		return op, err
	}
	if err = json.Unmarshal(command, &op.Command); err != nil {
		return op, err
	}
	if op.Sequence == 0 {
		return op, nil
	}
	return op, json.Unmarshal(status, &op.Status)
}

const operationColumns = "id,organization_id,cluster_id,request,command,phase,sequence,status,expires_at,delivered_at,created_at"

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
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET phase='Failed' WHERE id=$1", id); err != nil {
			return err
		}
		if err = audit(ctx, tx, org, "control-plane", "maintenance.expired_before_delivery", id, requestID); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) CreateNodeOperation(ctx context.Context, org, cluster string, input protocol.MaintenanceRequest, key ed25519.PrivateKey, actor, requestID string) (NodeOperation, error) {
	var empty NodeOperation
	if input.Validate() != nil || len(key) != ed25519.PrivateKeySize {
		return empty, ErrConflict
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)
	var actual string
	var uid *string
	var fresh bool
	var now time.Time
	err = tx.QueryRow(ctx, `SELECT organization_id,cluster_uid,coalesce(last_heartbeat_at>now()-interval '90 seconds' AND observed_at>now()-interval '90 seconds',false),now() FROM clusters WHERE id=$1 FOR UPDATE`, cluster).Scan(&actual, &uid, &fresh, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, ErrNotFound
	}
	if err != nil {
		return empty, err
	}
	if actual != org {
		return empty, ErrNotFound
	}
	existing, err := scanOperation(tx.QueryRow(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE id=$1", input.OperationID))
	if err == nil {
		if existing.OrganizationID != org || existing.ClusterID != cluster {
			return empty, ErrConflict
		}
		if existing.Request != input {
			return empty, ErrConflict
		}
		return existing, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return empty, err
	}
	if uid == nil || !fresh {
		return empty, ErrStale
	}
	var known bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE cluster_id=$1 AND uid=$2 AND name=$3) AND EXISTS(SELECT 1 FROM agent_identities WHERE cluster_id=$1 AND revoked_at IS NULL AND expires_at>now())`, cluster, input.NodeUID, input.NodeName).Scan(&known); err != nil {
		return empty, err
	}
	if !known {
		return empty, ErrNotFound
	}
	if err = expireUndelivered(ctx, tx, cluster, org, requestID); err != nil {
		return empty, err
	}
	permit := protocol.MaintenancePermit{OrganizationID: org, ClusterID: cluster, ClusterUID: *uid, MaintenanceRequest: input, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(15 * time.Minute)}
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
	op, err := scanOperation(tx.QueryRow(ctx, "INSERT INTO node_operations(id,organization_id,cluster_id,request,command,expires_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING "+operationColumns, input.OperationID, org, cluster, string(requestJSON), string(commandJSON), permit.ExpiresAt))
	if err != nil {
		return empty, classify(err)
	}
	if err = audit(ctx, tx, org, actor, "maintenance.requested", input.OperationID, requestID); err != nil {
		return empty, err
	}
	return op, tx.Commit(ctx)
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
	result := protocol.OperationSyncResult{Commands: []protocol.MaintenanceCommand{}, Acknowledged: map[string]int64{}}
	tx, org, err := s.beginAgent(ctx, cluster, key, nonce)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
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
		for _, event := range report.Events {
			if event.Sequence <= op.Sequence {
				continue
			}
			metadata, err := json.Marshal(event)
			if err != nil {
				return result, err
			}
			if _, err = tx.Exec(ctx, "INSERT INTO audit_events(organization_id,actor,action,resource_id,request_id,metadata) VALUES ($1,$2,$3,$4,$5,$6)", org, "agent:"+key, "maintenance."+event.Phase, op.ID, requestID, string(metadata)); err != nil {
				return result, err
			}
		}
		data, err := json.Marshal(report)
		if err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET phase=$2,sequence=$3,status=$4 WHERE id=$1", op.ID, report.Phase, report.Sequence, string(data)); err != nil {
			return result, err
		}
		result.Acknowledged[op.ID] = report.Sequence
	}
	if err = expireUndelivered(ctx, tx, cluster, org, requestID); err != nil {
		return result, err
	}
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
	if err = tx.QueryRow(ctx, "SELECT now()").Scan(&result.ServerTime); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
