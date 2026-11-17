package store

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
)

type ScheduleResult struct {
	Claimed        bool     `json:"claimed"`
	OrganizationID string   `json:"organizationId"`
	CampaignID     string   `json:"campaignId"`
	Epoch          int64    `json:"epoch"`
	Operations     []string `json:"operations"`
}

// ScheduleOnce performs one bounded, fenced transaction. No process-local state owns work.
func (s *Store) ScheduleOnce(ctx context.Context, key ed25519.PrivateKey, worker string, delay time.Duration) (ScheduleResult, error) {
	result := ScheduleResult{Operations: []string{}}
	if len(key) != ed25519.PrivateKeySize || worker == "" || len(worker) > 128 || delay < 0 || delay > time.Minute {
		return result, ErrInvalid
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	var limitsJSON []byte
	err = tx.QueryRow(ctx, `SELECT l.organization_id,l.limits,l.scheduler_epoch+1 FROM organization_limits l WHERE l.next_tick_at<=now() AND EXISTS(SELECT 1 FROM campaigns c WHERE c.organization_id=l.organization_id AND c.phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures')) ORDER BY l.next_tick_at,l.organization_id FOR UPDATE OF l SKIP LOCKED LIMIT 1`).Scan(&result.OrganizationID, &limitsJSON, &result.Epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.Claimed = true
	var limits campaign.Limits
	if err = json.Unmarshal(limitsJSON, &limits); err != nil {
		return result, err
	}
	c, err := scanCampaign(tx.QueryRow(ctx, "SELECT "+campaignColumns+" FROM campaigns WHERE organization_id=$1 AND phase NOT IN ('Draft','Succeeded','Failed','Cancelled','CompletedWithFailures') ORDER BY last_scheduled_at NULLS FIRST,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1", result.OrganizationID))
	if err != nil {
		return result, err
	}
	result.CampaignID = c.ID
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT now()").Scan(&now); err != nil {
		return result, err
	}
	request := NewID()
	actor := "scheduler:" + worker
	if err = cleanupReservations(ctx, tx, c.OrganizationID); err != nil {
		return result, err
	}
	if err = s.reconcileCampaignAttempts(ctx, tx, &c, now, actor, request); err != nil {
		return result, err
	}
	if err = s.scheduleCampaign(ctx, tx, &c, limits, key, now, actor, request, &result); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "UPDATE campaigns SET last_scheduled_at=now() WHERE id=$1", c.ID); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "UPDATE organization_limits SET scheduler_epoch=$2,last_worker=$3,next_tick_at=now()+$4*interval '1 millisecond' WHERE organization_id=$1", c.OrganizationID, result.Epoch, worker, delay.Milliseconds()); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
func (s *Store) reconcileCampaignAttempts(ctx context.Context, tx pgx.Tx, c *Campaign, now time.Time, actor, request string) error {
	// Expiry can only end an operation that has never been offered to an agent.
	rows, err := tx.Query(ctx, "SELECT DISTINCT cluster_id FROM node_operations WHERE campaign_id=$1 AND delivered_at IS NULL AND phase='Pending' AND expires_at<=now() ORDER BY cluster_id", c.ID)
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, cluster := range expired {
		var locked string
		if err = tx.QueryRow(ctx, "SELECT id FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&locked); err != nil {
			return err
		}
		if err = expireUndelivered(ctx, tx, cluster, c.OrganizationID, request); err != nil {
			return err
		}
	}
	type finished struct {
		op, target, phase string
		status            []byte
		cancelReason      *string
		failures          int
		ended             time.Time
	}
	rows, err = tx.Query(ctx, `SELECT o.id,t.id,o.phase,o.status,t.failures,coalesce(o.terminal_at,now()),o.cancel_reason FROM campaign_attempts a JOIN node_operations o ON o.id=a.operation_id JOIN campaign_targets t ON t.id=a.target_id WHERE a.campaign_id=$1 AND a.finished_at IS NULL AND o.phase IN ('Succeeded','Failed','Cancelled') ORDER BY coalesce(o.terminal_at,now()),o.id`, c.ID)
	if err != nil {
		return err
	}
	var finishedRows []finished
	for rows.Next() {
		var f finished
		if err = rows.Scan(&f.op, &f.target, &f.phase, &f.status, &f.failures, &f.ended, &f.cancelReason); err != nil {
			rows.Close()
			return err
		}
		finishedRows = append(finishedRows, f)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, f := range finishedRows {
		var status protocol.OperationReport
		if err = json.Unmarshal(f.status, &status); err != nil {
			return err
		}
		reason := status.Reason
		if reason == "" {
			reason = "AuthorizationExpiredBeforeDelivery"
			if f.cancelReason != nil {
				reason = *f.cancelReason
			}
		}
		state := f.phase
		attemptPhase := f.phase
		failures := f.failures
		next := now
		if f.phase != "Succeeded" {
			if c.Phase == "Cancelling" {
				state = "Cancelled"
			} else {
				failures++
				attemptPhase = "Failed"
				if f.phase == "Cancelled" {
					reason = "UnexpectedCancellation"
				}
				state = "Failed"
				if c.Spec.Retry.Allows(reason, failures) {
					state = "RetryWaiting"
					seconds := min(3600, c.Spec.Retry.BackoffSeconds*(1<<(failures-1)))
					digest := sha256.Sum256([]byte(f.op))
					jitter := int(digest[0]) * seconds / 1280
					next = now.Add(time.Duration(seconds+jitter) * time.Second)
				}
			}
		}
		if _, err = tx.Exec(ctx, "UPDATE campaign_attempts SET phase=$2,reason=$3,finished_at=$4 WHERE operation_id=$1", f.op, attemptPhase, reason, f.ended); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE campaign_targets SET state=$2,reason=$3,failures=$4,next_attempt_at=$5 WHERE id=$1", f.target, state, reason, failures, next); err != nil {
			return err
		}
		if err = campaignEvent(ctx, tx, c, actor, "attempt_finished", request, map[string]any{"operationId": f.op, "targetId": f.target, "outcome": attemptPhase, "reason": reason, "targetState": state}); err != nil {
			return err
		}
	}
	return nil
}
func pauseForSafety(ctx context.Context, tx pgx.Tx, c *Campaign, reason, actor, request string, details any) error {
	if c.Phase == "Paused" && c.Reason != "UserPaused" {
		return nil
	}
	c.Phase = "Paused"
	c.Reason = reason
	c.ApprovalEpoch++
	return campaignEvent(ctx, tx, c, actor, "safety_paused", request, details)
}
func setCampaignState(ctx context.Context, tx pgx.Tx, c *Campaign, phase, reason, actor, request string) error {
	if c.Phase == phase && c.Reason == reason {
		return nil
	}
	c.Phase = phase
	c.Reason = reason
	return campaignEvent(ctx, tx, c, actor, "state_changed", request, map[string]any{"phase": phase, "reason": reason, "stage": c.Stage})
}
func (s *Store) scheduleCampaign(ctx context.Context, tx pgx.Tx, c *Campaign, limits campaign.Limits, key ed25519.PrivateKey, now time.Time, actor, request string, result *ScheduleResult) error {
	progress, err := campaignProgress(ctx, tx, c.ID)
	if err != nil {
		return err
	}
	c.Progress = progress
	if c.Phase != "Cancelling" && progress.Pending+progress.RetryWaiting+progress.Active > 0 && !c.Spec.HasFutureWindow(now) {
		c.Phase = "Cancelling"
		c.Reason = "MaintenanceWindowsExpired"
		c.TerminalAfterStop = "Failed"
		if _, err = tx.Exec(ctx, "UPDATE campaign_targets SET state='Cancelled',reason='MaintenanceWindowsExpired' WHERE campaign_id=$1 AND state IN ('Pending','RetryWaiting')", c.ID); err != nil {
			return err
		}
		if err = campaignEvent(ctx, tx, c, actor, "windows_expired", request, map[string]any{}); err != nil {
			return err
		}
	}
	if c.Phase == "Cancelling" {
		if err = s.cancelCampaignOperations(ctx, tx, *c, key, actor, request); err != nil {
			return err
		}
		if progress.Active == 0 {
			return setCampaignState(ctx, tx, c, c.TerminalAfterStop, c.Reason, actor, request)
		}
		return nil
	}
	var unsafe bool
	var unsafeReason string
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM node_operations WHERE campaign_id=$1 AND phase IN ('Blocked','RecoveryRequired')),
 coalesce((SELECT reason FROM (
   SELECT a.phase,a.reason,o.request->>'action' AS action
   FROM campaign_attempts a JOIN node_operations o ON o.id=a.operation_id
   WHERE a.campaign_id=$1 AND a.finished_at IS NOT NULL
   ORDER BY a.finished_at,a.operation_id OFFSET $2
 ) recent
 WHERE phase='Failed' AND CASE WHEN action IN ('UpgradePackages','UpgradeNodePool')
          THEN reason <> 'AuthorizationExpiredBeforeDelivery'
          ELSE reason NOT IN ('AuthorizationExpired','AuthorizationExpiredBeforeDelivery','APIServerHealthUnknown','NodeHeartbeatStale','ManagementDisconnected','PDBBlocked','EvictionPDBBlocked','WorkloadRecoveryPending') END
 LIMIT 1),'')`, c.ID, c.CompletedBaseline).Scan(&unsafe, &unsafeReason)
	if err != nil {
		return err
	}
	if unsafe {
		return pauseForSafety(ctx, tx, c, "SafetyBlocked", actor, request, map[string]any{"stage": c.Stage})
	}
	// Acknowledged historical failures are retained but do not repeatedly re-trigger the same gate.
	failed := max(0, progress.FailedAttempts-c.FailedBaseline)
	completed := max(0, progress.CompletedAttempts-c.CompletedBaseline)
	consecutive := min(progress.ConsecutiveFailures, completed)
	if unsafeReason != "" && failed > 0 {
		return pauseForSafety(ctx, tx, c, "SafetyViolation", actor, request, map[string]any{"reason": unsafeReason})
	}
	if c.Spec.Failure.Breached(failed, completed, consecutive) {
		return pauseForSafety(ctx, tx, c, "FailureThresholdBreached", actor, request, map[string]any{"failed": failed, "completed": completed, "consecutive": consecutive})
	}
	if c.Phase == "Paused" {
		return nil
	}
	var remaining int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM campaign_targets WHERE campaign_id=$1 AND stage=$2 AND state IN ('Pending','RetryWaiting','Active')", c.ID, c.Stage).Scan(&remaining); err != nil {
		return err
	}
	if remaining == 0 {
		var next *int
		if err = tx.QueryRow(ctx, "SELECT min(stage) FROM campaign_targets WHERE campaign_id=$1 AND stage>$2", c.ID, c.Stage).Scan(&next); err != nil {
			return err
		}
		if next == nil {
			phase := "Succeeded"
			if progress.Failed > 0 {
				phase = "CompletedWithFailures"
			}
			return setCampaignState(ctx, tx, c, phase, "RolloutCompleted", actor, request)
		}
		previous := c.Stage
		c.Stage = *next
		c.ApprovalEpoch++
		c.Phase = "Scheduled"
		c.Reason = "StageCompleted"
		if c.Spec.NeedsApproval(c.Stage) {
			c.Phase = "AwaitingApproval"
			c.Reason = "IndependentApprovalRequired"
		}
		if err = campaignEvent(ctx, tx, c, actor, "stage_advanced", request, map[string]any{"from": previous, "to": c.Stage, "snapshotDigest": c.SnapshotDigest}); err != nil {
			return err
		}
	}
	ok, err := approved(ctx, tx, *c)
	if err != nil {
		return err
	}
	if !ok {
		return setCampaignState(ctx, tx, c, "AwaitingApproval", "IndependentApprovalRequired", actor, request)
	}
	window, open := c.Spec.CurrentWindow(now)
	if !open {
		return setCampaignState(ctx, tx, c, "Scheduled", "WaitingForWindow", actor, request)
	}
	if window.End.Sub(now) < time.Duration(c.Spec.MinimumWindowSeconds)*time.Second {
		return setCampaignState(ctx, tx, c, "Scheduled", "InsufficientWindowRemainder", actor, request)
	}
	if err = setCampaignState(ctx, tx, c, "Running", "StageExecuting", actor, request); err != nil {
		return err
	}
	var active int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM campaign_targets WHERE campaign_id=$1 AND stage=$2 AND state='Active'", c.ID, c.Stage).Scan(&active); err != nil {
		return err
	}
	available := min(16, c.Spec.Stages[c.Stage].BatchSize-active)
	if available <= 0 {
		return nil
	}
	var cursor int
	if err = tx.QueryRow(ctx, "SELECT admission_cursor FROM campaigns WHERE id=$1", c.ID).Scan(&cursor); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,snapshot,attempts FROM campaign_targets t WHERE campaign_id=$1 AND stage=$2 AND state IN ('Pending','RetryWaiting') AND next_attempt_at<=now() AND NOT EXISTS(SELECT 1 FROM node_operations o WHERE o.cluster_id=t.cluster_id AND o.phase NOT IN ('Succeeded','Failed','Cancelled')) ORDER BY (ordinal>$3) DESC,ordinal LIMIT 128`, c.ID, c.Stage, cursor)
	if err != nil {
		return err
	}
	type candidate struct {
		id       string
		snapshot campaign.Target
		attempt  int
	}
	var candidates []candidate
	for rows.Next() {
		var candidate candidate
		var data []byte
		if err = rows.Scan(&candidate.id, &data, &candidate.attempt); err != nil {
			rows.Close()
			return err
		}
		if err = json.Unmarshal(data, &candidate.snapshot); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(candidates) > 0 {
		if _, err = tx.Exec(ctx, "UPDATE campaigns SET admission_cursor=$2 WHERE id=$1", c.ID, candidates[len(candidates)-1].snapshot.Ordinal); err != nil {
			return err
		}
	}
	for _, candidate := range candidates {
		if available == 0 {
			break
		}
		target := candidate.snapshot
		action := target.Action
		if action == "" { // compatibility for campaign snapshots written before per-target actions existed.
			action = c.Spec.Action
		}
		if action == campaign.UpgradeFleet {
			return fmt.Errorf("fleet upgrade target snapshot is missing its concrete executor action")
		}
		input := protocol.MaintenanceRequest{OperationID: NewID(), NodeName: target.Node.Name, NodeUID: target.Node.UID, Policy: target.Policy, Action: action, PlanDigest: target.PlanDigest}
		options := admission{OrganizationLimits: limits, CampaignLimits: &c.Spec.Limits, CampaignID: &c.ID, Snapshot: &target, SnapshotDigest: c.SnapshotDigest, PlanGeneration: c.PlanGeneration, Attempt: candidate.attempt + 1, WindowEnd: &window.End, Selector: c.Spec.Selection.NodeSelector}
		op, err := s.createOperationTx(ctx, tx, c.OrganizationID, target.ClusterID, input, key, actor, request, options)
		if errors.Is(err, ErrUpgradeAdmission) {
			var admissionErr *UpgradeAdmissionError
			reason := "UpgradeAdmissionEvidenceUnavailable"
			if errors.As(err, &admissionErr) && admissionErr.Reason != "" {
				reason = admissionErr.Reason
			}
			return pauseForSafety(ctx, tx, c, reason, actor, request, map[string]any{"targetId": candidate.id, "reason": reason})
		}
		if errors.Is(err, ErrCapacity) || errors.Is(err, ErrSiteHealth) || errors.Is(err, ErrStale) {
			continue
		}
		if errors.Is(err, ErrSnapshotChanged) || errors.Is(err, ErrNotFound) {
			return pauseForSafety(ctx, tx, c, "TargetSnapshotChanged", actor, request, map[string]any{"targetId": candidate.id})
		}
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO campaign_attempts(operation_id,target_id,campaign_id,attempt) VALUES ($1,$2,$3,$4)", op.ID, candidate.id, c.ID, candidate.attempt+1); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE campaign_targets SET state='Active',reason='OperationIssued',attempts=attempts+1 WHERE id=$1", candidate.id); err != nil {
			return err
		}
		if err = campaignEvent(ctx, tx, c, actor, "operation_admitted", request, map[string]any{"operationId": op.ID, "targetId": candidate.id, "attempt": candidate.attempt + 1, "stage": c.Stage, "schedulerEpoch": result.Epoch}); err != nil {
			return err
		}
		result.Operations = append(result.Operations, op.ID)
		available--
	}
	return nil
}
