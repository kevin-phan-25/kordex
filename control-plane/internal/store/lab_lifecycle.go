package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	LabRunning     = "RUNNING"
	LabDraining    = "DRAINING"
	LabReadyToStop = "READY_TO_STOP"
	LabStopping    = "STOPPING"
	LabStopped     = "STOPPED"
	LabStarting    = "STARTING"
)

var ErrLabBarrier = errors.New("lab lifecycle barrier blocks operation admission")

// LabLifecycle is durable cluster-scoped power state. The cluster row is locked
// for every transition and by the operation admission transaction.
type LabLifecycle struct {
	OrganizationID         string    `json:"organizationId"`
	ClusterID              string    `json:"clusterId"`
	State                  string    `json:"state"`
	Generation             int64     `json:"generation"`
	UpdatedBy              string    `json:"updatedBy"`
	UpdatedAt              time.Time `json:"updatedAt"`
	Reason                 string    `json:"reason,omitempty"`
	ActiveOperations       int       `json:"activeOperations"`
	UnsafeOperations       int       `json:"unsafeOperations"`
	UnreleasedReservations int       `json:"unreleasedReservations"`
	CanStop                bool      `json:"canStop"`
	Blockers               []string  `json:"blockers"`
}

func lockLabCluster(ctx context.Context, tx pgx.Tx, org, cluster string) error {
	var actual string
	var provider string
	err := tx.QueryRow(ctx, "SELECT organization_id,provider FROM clusters WHERE id=$1 FOR UPDATE", cluster).Scan(&actual, &provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if actual != org {
		return ErrNotFound
	}
	if provider != "self-managed" {
		return ErrConflict
	}
	return nil
}

func lifecycleInTx(ctx context.Context, tx pgx.Tx, org, cluster string, lock bool) (LabLifecycle, error) {
	var v LabLifecycle
	query := "SELECT organization_id,cluster_id,state,generation,updated_by,updated_at,reason FROM lab_lifecycle WHERE cluster_id=$1"
	if lock {
		query += " FOR UPDATE"
	}
	err := tx.QueryRow(ctx, query, cluster).Scan(&v.OrganizationID, &v.ClusterID, &v.State, &v.Generation, &v.UpdatedBy, &v.UpdatedAt, &v.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		var actual string
		err = tx.QueryRow(ctx, "SELECT organization_id FROM clusters WHERE id=$1", cluster).Scan(&actual)
		if errors.Is(err, pgx.ErrNoRows) {
			return LabLifecycle{}, ErrNotFound
		}
		if err != nil {
			return LabLifecycle{}, err
		}
		if actual != org {
			return LabLifecycle{}, ErrNotFound
		}
		return LabLifecycle{OrganizationID: org, ClusterID: cluster, State: LabRunning, Blockers: []string{}}, nil
	}
	if err != nil {
		return v, err
	}
	if v.OrganizationID != org {
		return LabLifecycle{}, ErrNotFound
	}
	v.Blockers = []string{}
	return v, nil
}

func (s *Store) LabLifecycleStatus(ctx context.Context, org, cluster string) (LabLifecycle, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return LabLifecycle{}, err
	}
	defer tx.Rollback(ctx)
	v, err := lifecycleInTx(ctx, tx, org, cluster, false)
	if err != nil {
		return v, err
	}
	if err = populateLifecycleBlockers(ctx, tx, &v); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}

func populateLifecycleBlockers(ctx context.Context, tx pgx.Tx, v *LabLifecycle) error {
	v.Blockers = []string{}
	var pending, failed, reservations int
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE phase NOT IN ('Succeeded','Failed','Cancelled')),
	 count(*) FILTER (WHERE phase IN ('Failed','Blocked','RecoveryRequired'))
	 FROM node_operations WHERE cluster_id=$1`, v.ClusterID).Scan(&pending, &failed); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM operation_reservations WHERE cluster_id=$1 AND released_at IS NULL`, v.ClusterID).Scan(&reservations); err != nil {
		return err
	}
	v.ActiveOperations, v.UnsafeOperations, v.UnreleasedReservations = pending, failed, reservations
	if pending > 0 {
		v.Blockers = append(v.Blockers, "operations_pending")
	}
	if failed > 0 {
		v.Blockers = append(v.Blockers, "failed_or_recovery_required_operation")
	}
	if reservations > 0 {
		v.Blockers = append(v.Blockers, "unreleased_operation_reservation")
	}
	var incomplete int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_operations WHERE cluster_id=$1
	 AND phase IN ('Succeeded','Cancelled') AND (sequence<=0 OR status='{}'::jsonb OR status->>'phase'<>phase OR terminal_at IS NULL)`, v.ClusterID).Scan(&incomplete); err != nil {
		return err
	}
	if incomplete > 0 {
		v.Blockers = append(v.Blockers, "terminal_operation_report_not_finalized")
	}
	v.CanStop = v.State == LabReadyToStop && len(v.Blockers) == 0
	return nil
}

func (s *Store) RequestLabStop(ctx context.Context, org, cluster, actor, requestID string) (LabLifecycle, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return LabLifecycle{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockLabCluster(ctx, tx, org, cluster); err != nil {
		return LabLifecycle{}, err
	}
	v, err := lifecycleInTx(ctx, tx, org, cluster, true)
	if err != nil {
		return v, err
	}
	switch v.State {
	case LabRunning:
		v.State = LabDraining
		if _, err = tx.Exec(ctx, `INSERT INTO lab_lifecycle(cluster_id,organization_id,state,updated_by,reason)
		 VALUES($1,$2,$3,$4,'operator requested stop') ON CONFLICT(cluster_id) DO UPDATE SET state=EXCLUDED.state,
		 generation=lab_lifecycle.generation+1,updated_by=EXCLUDED.updated_by,updated_at=now(),reason=EXCLUDED.reason`, cluster, org, v.State, actor); err != nil {
			return v, err
		}
		if err = audit(ctx, tx, org, actor, "lab.stop_requested", cluster, requestID); err != nil {
			return v, err
		}
	case LabDraining, LabReadyToStop, LabStopping, LabStopped:
		// Idempotent status/retry. A second stop never creates a second cloud action.
	default:
		return v, ErrConflict
	}
	if v.State == LabDraining {
		if err = settleLabStop(ctx, tx, &v); err != nil {
			return v, err
		}
	}
	if err = populateLifecycleBlockers(ctx, tx, &v); err != nil {
		return v, err
	}
	if current, e := lifecycleInTx(ctx, tx, org, cluster, false); e == nil {
		v.Generation, v.UpdatedBy, v.UpdatedAt, v.Reason = current.Generation, current.UpdatedBy, current.UpdatedAt, current.Reason
	}
	return v, tx.Commit(ctx)
}

func settleLabStop(ctx context.Context, tx pgx.Tx, v *LabLifecycle) error {
	if err := populateLifecycleBlockers(ctx, tx, v); err != nil {
		return err
	}
	if len(v.Blockers) != 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE lab_lifecycle SET state=$2,generation=generation+1,updated_at=now(),reason='all operations terminal; awaiting verified VM stop'
	 WHERE cluster_id=$1 AND state=$3`, v.ClusterID, LabReadyToStop, LabDraining); err != nil {
		return err
	}
	v.State = LabReadyToStop
	return nil
}

func (s *Store) MarkLabStopping(ctx context.Context, org, cluster, actor, requestID string) (LabLifecycle, error) {
	// Claiming READY_TO_STOP is a single-writer transition. A second stop
	// controller sees STOPPING and cannot issue duplicate GCE stop requests.
	return s.transitionLab(ctx, org, cluster, actor, requestID, []string{LabReadyToStop}, LabStopping, "VM stop in progress", "lab.vm_stop_started")
}

func (s *Store) CompleteLabStop(ctx context.Context, org, cluster, actor, requestID string) (LabLifecycle, error) {
	return s.transitionLab(ctx, org, cluster, actor, requestID, []string{LabStopping, LabStopped}, LabStopped, "all expected VMs verified stopped; persistent resources retained", "lab.vm_stop_verified")
}

func (s *Store) BeginLabStart(ctx context.Context, org, cluster, actor, requestID string) (LabLifecycle, error) {
	return s.transitionLab(ctx, org, cluster, actor, requestID, []string{LabStopped, LabStarting, LabStopping}, LabStarting, "VM startup in progress; admission fenced", "lab.vm_start_started")
}

func (s *Store) CompleteLabStart(ctx context.Context, org, cluster, actor, requestID string) (LabLifecycle, error) {
	return s.transitionLab(ctx, org, cluster, actor, requestID, []string{LabStarting}, LabRunning, "all expected VMs, host identities, OS identities, and health checks verified", "lab.vm_start_verified")
}

func (s *Store) transitionLab(ctx context.Context, org, cluster, actor, requestID string, from []string, to, reason, action string) (LabLifecycle, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return LabLifecycle{}, err
	}
	defer tx.Rollback(ctx)
	if err = lockLabCluster(ctx, tx, org, cluster); err != nil {
		return LabLifecycle{}, err
	}
	v, err := lifecycleInTx(ctx, tx, org, cluster, true)
	if err != nil {
		return v, err
	}
	allowed := false
	for _, state := range from {
		if v.State == state {
			allowed = true
			break
		}
	}
	if !allowed {
		return v, fmt.Errorf("lab lifecycle transition %s -> %s: %w", v.State, to, ErrConflict)
	}
	if to == LabStopping || to == LabStopped {
		if err = populateLifecycleBlockers(ctx, tx, &v); err != nil {
			return v, err
		}
		if len(v.Blockers) != 0 || (to == LabStopping && v.State != LabReadyToStop) {
			return v, ErrConflict
		}
	}
	if v.State != to {
		_, err = tx.Exec(ctx, `INSERT INTO lab_lifecycle(cluster_id,organization_id,state,updated_by,reason)
		 VALUES($1,$2,$3,$4,$5) ON CONFLICT(cluster_id) DO UPDATE SET state=EXCLUDED.state,generation=lab_lifecycle.generation+1,
		 updated_by=EXCLUDED.updated_by,updated_at=now(),reason=EXCLUDED.reason`, cluster, org, to, actor, reason)
		if err != nil {
			return v, err
		}
		if err = audit(ctx, tx, org, actor, action, cluster, requestID); err != nil {
			return v, err
		}
	}
	v, err = lifecycleInTx(ctx, tx, org, cluster, false)
	if err != nil {
		return v, err
	}
	if err = populateLifecycleBlockers(ctx, tx, &v); err != nil {
		return v, err
	}
	return v, tx.Commit(ctx)
}

// FinalizeTerminalOperationReservation releases capacity only after a validated
// success/cancel report was committed; failures retain the safety fence.
func releaseTerminalReservation(ctx context.Context, tx pgx.Tx, id string, phase string) error {
	if phase != "Succeeded" && phase != "Cancelled" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE operation_reservations SET released_at=coalesce(released_at,now()) WHERE operation_id=$1 AND released_at IS NULL`, id)
	return err
}
