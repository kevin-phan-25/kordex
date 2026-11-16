package controller

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

func (r *Reconciler) advanceUpgradeCheckpoint(m *operations.NodeMaintenance, phase protocol.UpgradePhase, reason string) error {
	if m.Status.UpgradeCheckpoint == nil {
		return errors.New("upgrade checkpoint is not initialized")
	}
	previous := *m.Status.UpgradeCheckpoint
	next := previous
	next.Phase = phase
	next.Sequence++
	next.Reason = reason
	now := r.now()
	if !now.After(previous.UpdatedAt.Time) {
		now = previous.UpdatedAt.Time.Add(time.Nanosecond)
	}
	next.UpdatedAt = metav1.NewTime(now)
	if err := protocol.ValidateUpgradeCheckpointAdvance(previous, next); err != nil {
		return err
	}
	m.Status.UpgradeCheckpoint = &next
	return nil
}

func (r *Reconciler) initializeUpgradeCheckpoint(m *operations.NodeMaintenance, permit protocol.MaintenancePermit, bootID string) error {
	if m.Status.UpgradeCheckpoint != nil {
		checkpoint := m.Status.UpgradeCheckpoint
		if err := protocol.ValidateUpgradeCheckpoint(*checkpoint); err != nil {
			return err
		}
		if checkpoint.PlanDigest != permit.PlanDigest || checkpoint.NodeUID != permit.NodeUID || checkpoint.BootID != bootID {
			return errors.New("persisted upgrade identity does not match signed authorization")
		}
		return nil
	}
	m.Status.UpgradeCheckpoint = &protocol.UpgradeCheckpoint{
		PlanDigest: permit.PlanDigest,
		NodeUID:    permit.NodeUID,
		BootID:     bootID,
		Phase:      protocol.UpgradePending,
		Sequence:   1,
		UpdatedAt:  metav1.NewTime(r.now()),
	}
	return protocol.ValidateUpgradeCheckpointAdvance(protocol.UpgradeCheckpoint{}, *m.Status.UpgradeCheckpoint)
}

func (r *Reconciler) rejectUnsupportedUpgrade(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, bootID string) error {
	if bootID == "" {
		return r.abort(ctx, m, "UpgradeHostIdentityUnknown", false)
	}
	if err := r.initializeUpgradeCheckpoint(m, permit, bootID); err != nil {
		return r.abort(ctx, m, "UpgradeCheckpointIdentityChanged", false)
	}
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint.Sequence == 1 && checkpoint.Phase == protocol.UpgradePending && checkpoint.Reason == "" {
		return r.checkpoint(ctx, m, "UpgradeIntentPersisted", "")
	}
	if checkpoint.Phase != protocol.UpgradePending {
		return r.abort(ctx, m, "UpgradeCheckpointUnexpected", false)
	}
	if err := r.advanceUpgradeCheckpoint(m, protocol.UpgradeFailed, "UpgradeExecutorUnavailable"); err != nil {
		return r.abort(ctx, m, "UpgradeCheckpointTransitionInvalid", false)
	}
	return r.abort(ctx, m, "UpgradeExecutorUnavailable", false)
}
