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
	return r.advanceUpgradeCheckpointState(m, phase, reason, nil)
}

func (r *Reconciler) advanceUpgradeCheckpointState(m *operations.NodeMaintenance, phase protocol.UpgradePhase, reason string, update func(*protocol.UpgradeCheckpoint)) error {
	if m.Status.UpgradeCheckpoint == nil {
		return errors.New("upgrade checkpoint is not initialized")
	}
	previous := *m.Status.UpgradeCheckpoint
	next := previous
	next.Phase = phase
	next.Sequence++
	next.Reason = reason
	// metav1.Time is serialized at RFC3339 second precision. Canonicalize to
	// that persisted representation before comparing or advancing so two
	// in-memory nanosecond timestamps cannot collapse to the same stored value.
	now := metav1.NewTime(r.now()).Rfc3339Copy()
	previousUpdatedAt := previous.UpdatedAt.Rfc3339Copy()
	if !now.After(previousUpdatedAt.Time) {
		now = metav1.NewTime(previousUpdatedAt.Add(time.Second)).Rfc3339Copy()
	}
	next.UpdatedAt = now
	if update != nil {
		update(&next)
	}
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
		UpdatedAt:  metav1.NewTime(r.now()).Rfc3339Copy(),
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
