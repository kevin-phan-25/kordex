package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/operator/internal/reboot"
)

const kuredLockReference = "operations.kordex.local/kured-lock"

func kuredReference(m *operations.NodeMaintenance) (reboot.Reference, error) {
	var ref reboot.Reference
	if err := json.Unmarshal([]byte(m.Annotations[kuredLockReference]), &ref); err != nil {
		return ref, err
	}
	return ref, ref.Validate(m.UID)
}

// ensureKuredLock persists intent, then external ownership, before host actions.
// After acquisition a missing lock is a safety loss, never an acquisition retry.
func (r *Reconciler) ensureKuredLock(ctx context.Context, m *operations.NodeMaintenance, phase string) (bool, error) {
	if m.Annotations[kuredLockReference] == "" {
		if r.Kured == nil || !r.Kured.Enabled {
			return true, nil
		}
		if phase != "Validating" {
			return false, errors.New("kured lock was not reserved before host maintenance")
		}
		ref, err := r.Kured.Prepare(ctx, m.UID)
		if err != nil {
			return false, err
		}
		data, err := json.Marshal(ref)
		if err != nil {
			return false, err
		}
		if m.Annotations == nil {
			m.Annotations = map[string]string{}
		}
		m.Annotations[kuredLockReference] = string(data)
		return false, r.Client.Update(ctx, m)
	}
	if r.Kured == nil {
		return false, errors.New("persisted kured lock requires its coordination client")
	}
	ref, err := kuredReference(m)
	if err != nil {
		return false, err
	}
	if ref.Acquired {
		if err := r.Kured.Check(ctx, ref); err != nil {
			return false, err
		}
		return true, nil
	}
	if phase != "Validating" {
		return false, errors.New("kured acquisition was not committed before host maintenance")
	}
	if err := r.Kured.Acquire(ctx, ref); err != nil {
		return false, err
	}
	ref.Acquired = true
	data, err := json.Marshal(ref)
	if err != nil {
		return false, err
	}
	m.Annotations[kuredLockReference] = string(data)
	return false, r.Client.Update(ctx, m)
}

func (r *Reconciler) checkKuredLock(ctx context.Context, m *operations.NodeMaintenance) error {
	if m.Annotations[kuredLockReference] == "" {
		if m.Status.UpgradeCheckpoint != nil && r.Kured != nil && r.Kured.Enabled {
			return errors.New("host operation lacks its durable kured lock reference")
		}
		return nil
	}
	ref, err := kuredReference(m)
	if err != nil {
		return err
	}
	if !ref.Acquired {
		return errors.New("kured acquisition is not committed")
	}
	if r.Kured == nil {
		return errors.New("kured coordination client unavailable")
	}
	return r.Kured.Check(ctx, ref)
}

func (r *Reconciler) releaseKuredLock(ctx context.Context, m *operations.NodeMaintenance) error {
	if m.Annotations[kuredLockReference] == "" {
		return nil
	}
	if r.Kured == nil {
		return errors.New("kured lock cleanup requires its coordination client")
	}
	ref, err := kuredReference(m)
	if err != nil {
		return err
	}
	if err := r.Kured.Release(ctx, ref); err != nil {
		return fmt.Errorf("release kured lock: %w", err)
	}
	return nil
}
