package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
)

type CampaignControl struct {
	Revision             int64 `json:"revision"`
	AcknowledgedFailures int   `json:"acknowledgedFailures"`
}

func approval(ctx context.Context, tx pgx.Tx, c Campaign, actor, decision string) error {
	var participated bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM campaign_events WHERE campaign_id=$1 AND actor=$2 AND kind IN ('created','plan_updated','started'))", c.ID, actor).Scan(&participated); err != nil {
		return err
	}
	if actor == c.CreatedBy || participated {
		return ErrForbidden
	}
	_, err := tx.Exec(ctx, "INSERT INTO campaign_approvals(id,campaign_id,plan_generation,stage,approval_epoch,snapshot_digest,actor,decision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", NewID(), c.ID, c.PlanGeneration, c.Stage, c.ApprovalEpoch, c.SnapshotDigest, actor, decision)
	return classify(err)
}
func approved(ctx context.Context, tx pgx.Tx, c Campaign) (bool, error) {
	if !c.Spec.NeedsApproval(c.Stage) {
		return true, nil
	}
	var ok bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM campaign_approvals WHERE campaign_id=$1 AND plan_generation=$2 AND stage=$3 AND approval_epoch=$4 AND snapshot_digest=$5 AND decision IN ('Approved','FailureResume'))", c.ID, c.PlanGeneration, c.Stage, c.ApprovalEpoch, c.SnapshotDigest).Scan(&ok)
	return ok, err
}
func (s *Store) ControlCampaign(ctx context.Context, org, id, action string, input CampaignControl, actor, role, request string, key ed25519.PrivateKey) (Campaign, error) {
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
	if c.Revision != input.Revision {
		return c, ErrConflict
	}
	progress, err := campaignProgress(ctx, tx, c.ID)
	if err != nil {
		return c, err
	}
	c.Progress = progress
	switch action {
	case "approve", "reject":
		if role != "administrator" && role != "approver" {
			return c, ErrForbidden
		}
		if c.Phase != "AwaitingApproval" {
			return c, ErrConflict
		}
		decision := "Approved"
		if action == "reject" {
			decision = "Rejected"
		}
		if err = approval(ctx, tx, c, actor, decision); err != nil {
			return c, err
		}
		if action == "approve" {
			c.Phase = "Scheduled"
			c.Reason = "StageApproved"
		} else {
			c.Phase = "Failed"
			c.Reason = "ApprovalRejected"
			if _, err = tx.Exec(ctx, "UPDATE campaign_targets SET state='Cancelled',reason='ApprovalRejected' WHERE campaign_id=$1 AND state IN ('Pending','RetryWaiting')", c.ID); err != nil {
				return c, err
			}
		}
	case "pause":
		if campaign.Terminal(c.Phase) || c.Phase == "Draft" || c.Phase == "Cancelling" || c.Phase == "Paused" {
			return c, ErrConflict
		}
		c.Phase = "Paused"
		c.Reason = "UserPaused"
	case "resume":
		if c.Phase != "Paused" {
			return c, ErrConflict
		}
		safety := c.Reason != "UserPaused"
		if safety {
			if role != "administrator" && role != "approver" {
				return c, ErrForbidden
			}
			if progress.Active > 0 || input.AcknowledgedFailures != progress.FailedAttempts {
				return c, ErrConflict
			}
			if err = approval(ctx, tx, c, actor, "FailureResume"); err != nil {
				return c, err
			}
			c.FailedBaseline = progress.FailedAttempts
			c.CompletedBaseline = progress.CompletedAttempts
		}
		c.Phase = "Scheduled"
		c.Reason = "UserResumed"
		ok, err := approved(ctx, tx, c)
		if err != nil {
			return c, err
		}
		if !ok {
			c.Phase = "AwaitingApproval"
			c.Reason = "IndependentApprovalRequired"
		}
	case "cancel":
		if campaign.Terminal(c.Phase) || c.Phase == "Cancelling" {
			return c, ErrConflict
		}
		if len(key) != ed25519.PrivateKeySize && progress.Active > 0 {
			return c, ErrConflict
		}
		c.Phase = "Cancelling"
		c.Reason = "UserCancelled"
		c.TerminalAfterStop = "Cancelled"
		if _, err = tx.Exec(ctx, "UPDATE campaign_targets SET state='Cancelled',reason='UserCancelled' WHERE campaign_id=$1 AND state IN ('Pending','RetryWaiting')", c.ID); err != nil {
			return c, err
		}
		if err = s.cancelCampaignOperations(ctx, tx, c, key, actor, request); err != nil {
			return c, err
		}
		if progress.Active == 0 {
			c.Phase = "Cancelled"
		}
	default:
		return c, ErrInvalid
	}
	if err = campaignEvent(ctx, tx, &c, actor, action, request, map[string]any{"stage": c.Stage, "approvalEpoch": c.ApprovalEpoch, "snapshotDigest": c.SnapshotDigest, "acknowledgedFailures": input.AcknowledgedFailures}); err != nil {
		return c, err
	}
	c.Progress, err = campaignProgress(ctx, tx, c.ID)
	if err != nil {
		return c, err
	}
	return c, tx.Commit(ctx)
}
func (s *Store) cancelCampaignOperations(ctx context.Context, tx pgx.Tx, c Campaign, key ed25519.PrivateKey, actor, request string) error {
	rows, err := tx.Query(ctx, "SELECT DISTINCT cluster_id FROM node_operations WHERE campaign_id=$1 AND phase NOT IN ('Succeeded','Failed','Cancelled') ORDER BY cluster_id", c.ID)
	if err != nil {
		return err
	}
	var clusters []string
	for rows.Next() {
		var cluster string
		if err = rows.Scan(&cluster); err != nil {
			rows.Close()
			return err
		}
		clusters = append(clusters, cluster)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, cluster := range clusters {
		var locked string
		if err = tx.QueryRow(ctx, "SELECT id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&locked); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE campaign_id=$1 AND phase NOT IN ('Succeeded','Failed','Cancelled') ORDER BY id FOR UPDATE", c.ID)
	if err != nil {
		return err
	}
	var operations []NodeOperation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			rows.Close()
			return err
		}
		operations = append(operations, op)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, op := range operations {
		if err = cancelOperationTx(ctx, tx, op, key, actor, request); err != nil {
			return err
		}
	}
	return nil
}
func cancelOperationTx(ctx context.Context, tx pgx.Tx, op NodeOperation, key ed25519.PrivateKey, actor, request string) error {
	if protocol.TerminalPhase(op.Phase) || op.CancelRequestedAt != nil {
		return nil
	}
	if op.DeliveredAt == nil {
		if _, err := tx.Exec(ctx, "UPDATE node_operations SET phase='Cancelled',terminal_at=now(),cancel_requested_at=now(),cancel_reason='CancelledBeforeDelivery' WHERE id=$1", op.ID); err != nil {
			return err
		}
	} else {
		if len(key) != ed25519.PrivateKeySize {
			return ErrConflict
		}
		var now = op.CreatedAt
		if err := tx.QueryRow(ctx, "SELECT now()").Scan(&now); err != nil {
			return err
		}
		control, err := protocol.SignCancellation(op.ID, op.ClusterID, op.Command.Digest(), now, key)
		if err != nil {
			return err
		}
		data, err := json.Marshal(control)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO operation_controls(operation_id,payload) VALUES ($1,$2) ON CONFLICT(operation_id) DO NOTHING", op.ID, string(data)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE node_operations SET cancel_requested_at=now(),cancel_reason='CancelledByHub' WHERE id=$1", op.ID); err != nil {
			return err
		}
	}
	return audit(ctx, tx, op.OrganizationID, actor, "maintenance.cancel_requested", op.ID, request)
}
func (s *Store) CancelNodeOperation(ctx context.Context, org, cluster, id string, key ed25519.PrivateKey, actor, request string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = lockOrganization(ctx, tx, org); err != nil {
		return err
	}
	var actual string
	if err = tx.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&actual); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if actual != org {
		return ErrNotFound
	}
	op, err := scanOperation(tx.QueryRow(ctx, "SELECT "+operationColumns+" FROM node_operations WHERE organization_id=$1 AND cluster_id=$2 AND id=$3 FOR UPDATE", org, cluster, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err = cancelOperationTx(ctx, tx, op, key, actor, request); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
