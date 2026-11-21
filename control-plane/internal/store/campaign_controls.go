package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
)

type CampaignControl struct {
	Revision             int64  `json:"revision"`
	AcknowledgedFailures int    `json:"acknowledgedFailures"`
	ApprovalID           string `json:"approvalId,omitempty"`
	Reason               string `json:"reason,omitempty"`
}

const campaignApprovalLifetime = 24 * time.Hour

func validApprovalRevocation(reason string) bool {
	return reason != "" && len(reason) <= 512 && strings.TrimSpace(reason) == reason && !strings.ContainsAny(reason, "\r\n\x00")
}

type approvalState struct {
	Status    string
	ID        string
	ExpiresAt time.Time
}

func approvalScope(c Campaign) (stage int, epoch *int64) {
	if c.Spec.ApprovalMode == "BeforeStart" && !c.ApprovalRevalidationRequired {
		return 0, nil
	}
	return c.Stage, &c.ApprovalEpoch
}

func campaignApprovalState(ctx context.Context, tx pgx.Tx, c Campaign) (approvalState, error) {
	if !c.ApprovalRevalidationRequired && !c.Spec.NeedsApproval(c.Stage) {
		return approvalState{Status: "NotRequired"}, nil
	}
	stage, epoch := approvalScope(c)
	var state approvalState
	var decision string
	var revokedAt *time.Time
	var expired bool
	query := `SELECT id,decision,expires_at,revoked_at,expires_at<=clock_timestamp()
 FROM campaign_approvals WHERE campaign_id=$1 AND plan_generation=$2 AND stage=$3 AND snapshot_digest=$4`
	args := []any{c.ID, c.PlanGeneration, stage, c.SnapshotDigest}
	if epoch != nil {
		query += " AND approval_epoch=$5"
		args = append(args, *epoch)
	}
	query += " ORDER BY approval_epoch DESC,created_at DESC LIMIT 1 FOR UPDATE"
	err := tx.QueryRow(ctx, query, args...).Scan(&state.ID, &decision, &state.ExpiresAt, &revokedAt, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		state.Status = "Required"
		return state, nil
	}
	if err != nil {
		return approvalState{}, err
	}
	switch {
	case revokedAt != nil:
		state.Status = "Revoked"
	case decision == "Rejected":
		state.Status = "Rejected"
	case expired:
		state.Status = "Expired"
	case decision == "Approved" || decision == "FailureResume":
		state.Status = "Active"
	default:
		state.Status = "Required"
	}
	return state, nil
}

func approval(ctx context.Context, tx pgx.Tx, c Campaign, actor, decision string) (string, time.Time, error) {
	var participated bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM campaign_events WHERE campaign_id=$1 AND actor=$2 AND kind IN ('created','plan_updated','started'))", c.ID, actor).Scan(&participated); err != nil {
		return "", time.Time{}, err
	}
	if actor == c.CreatedBy || participated {
		return "", time.Time{}, ErrForbidden
	}
	var id string
	var expiresAt time.Time
	err := tx.QueryRow(ctx, `INSERT INTO campaign_approvals(id,campaign_id,plan_generation,stage,approval_epoch,snapshot_digest,actor,decision,created_at,expires_at)
	 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp(),clock_timestamp()+$9*interval '1 second') RETURNING id,expires_at`, NewID(), c.ID, c.PlanGeneration, c.Stage, c.ApprovalEpoch, c.SnapshotDigest, actor, decision, int64(campaignApprovalLifetime/time.Second)).Scan(&id, &expiresAt)
	return id, expiresAt, classify(err)
}
func approved(ctx context.Context, tx pgx.Tx, c Campaign) (bool, error) {
	state, err := campaignApprovalState(ctx, tx, c)
	return state.Status == "NotRequired" || state.Status == "Active", err
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
		// A client may lose the response after a successful revoke and retry with
		// its original revision. Preserve idempotency only for an already-revoked
		// approval; a stale request cannot revoke a currently active one.
		if action == "revoke-approval" {
			if role != "administrator" && role != "approver" {
				return c, ErrForbidden
			}
			if input.ApprovalID == "" || !validApprovalRevocation(input.Reason) {
				return c, ErrInvalid
			}
			var revokedAt *time.Time
			err = tx.QueryRow(ctx, "SELECT revoked_at FROM campaign_approvals WHERE campaign_id=$1 AND id=$2 FOR UPDATE", c.ID, input.ApprovalID).Scan(&revokedAt)
			if errors.Is(err, pgx.ErrNoRows) {
				return c, ErrNotFound
			}
			if err != nil {
				return c, err
			}
			if revokedAt != nil {
				return c, tx.Commit(ctx)
			}
		}
		return c, ErrConflict
	}
	progress, err := campaignProgress(ctx, tx, c.ID)
	if err != nil {
		return c, err
	}
	c.Progress = progress
	eventKind := action
	eventDetails := map[string]any{"stage": c.Stage, "approvalEpoch": c.ApprovalEpoch, "snapshotDigest": c.SnapshotDigest, "acknowledgedFailures": input.AcknowledgedFailures}
	switch action {
	case "approve", "reject":
		if role != "administrator" && role != "approver" {
			return c, ErrForbidden
		}
		if c.Phase != "AwaitingApproval" {
			return c, ErrConflict
		}
		approvalStatus, err := campaignApprovalState(ctx, tx, c)
		if err != nil {
			return c, err
		}
		if approvalStatus.Status == "Expired" || approvalStatus.Status == "Revoked" {
			if !c.ApprovalRevalidationRequired {
				c.ApprovalRevalidationRequired = true
				c.ApprovalEpoch++
				c.Reason = "Approval" + approvalStatus.Status
				if err = campaignEvent(ctx, tx, &c, "control-plane", "approval_"+strings.ToLower(approvalStatus.Status), request, map[string]any{"approvalId": approvalStatus.ID, "expiresAt": approvalStatus.ExpiresAt}); err != nil {
					return c, err
				}
			}
		}
		decision := "Approved"
		if action == "reject" {
			decision = "Rejected"
		}
		approvalID, expiresAt, err := approval(ctx, tx, c, actor, decision)
		if err != nil {
			return c, err
		}
		eventDetails["approvalId"] = approvalID
		eventDetails["approvalExpiresAt"] = expiresAt
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
			// A recovery approval must be current-stage scoped. Once a campaign
			// needs revalidation, keep that stricter gate for its remaining stages.
			c.ApprovalRevalidationRequired = true
			approvalID, expiresAt, approvalErr := approval(ctx, tx, c, actor, "FailureResume")
			if approvalErr != nil {
				return c, approvalErr
			}
			eventDetails["approvalId"] = approvalID
			eventDetails["approvalExpiresAt"] = expiresAt
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
	case "revoke-approval":
		if role != "administrator" && role != "approver" {
			return c, ErrForbidden
		}
		reason := input.Reason
		if input.ApprovalID == "" || !validApprovalRevocation(reason) {
			return c, ErrInvalid
		}
		if campaign.Terminal(c.Phase) || c.Phase == "Draft" || c.Phase == "Cancelling" {
			return c, ErrConflict
		}
		var revokedAt *time.Time
		var generation int64
		var stage int
		var digest, decision string
		var expiresAt time.Time
		err = tx.QueryRow(ctx, `SELECT plan_generation,stage,snapshot_digest,decision,expires_at,revoked_at
 FROM campaign_approvals WHERE campaign_id=$1 AND id=$2 FOR UPDATE`, c.ID, input.ApprovalID).Scan(&generation, &stage, &digest, &decision, &expiresAt, &revokedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return c, ErrNotFound
		}
		if err != nil {
			return c, err
		}
		if revokedAt != nil {
			// Repeated revocation is an idempotent no-op. The first event retains
			// the actor and reason that actually performed the transition.
			return c, tx.Commit(ctx)
		}
		state, err := campaignApprovalState(ctx, tx, c)
		if err != nil {
			return c, err
		}
		if state.Status == "Expired" && state.ID == input.ApprovalID {
			return c, ErrApprovalExpired
		}
		if state.Status != "Active" || state.ID != input.ApprovalID || generation != c.PlanGeneration || digest != c.SnapshotDigest || (decision != "Approved" && decision != "FailureResume") {
			return c, ErrConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE campaign_approvals SET revoked_at=clock_timestamp(),revoked_by=$2,revocation_reason=$3 WHERE id=$1 AND revoked_at IS NULL`, input.ApprovalID, actor, reason); err != nil {
			return c, err
		}
		c.ApprovalRevalidationRequired = true
		c.ApprovalEpoch++
		c.Phase = "AwaitingApproval"
		c.Reason = "ApprovalRevoked"
		eventKind = "approval_revoked"
		eventDetails["approvalId"] = input.ApprovalID
		eventDetails["approvalStage"] = stage
		eventDetails["revocationReason"] = reason
		eventDetails["inFlightWorkContinues"] = true
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
	if err = campaignEvent(ctx, tx, &c, actor, eventKind, request, eventDetails); err != nil {
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
