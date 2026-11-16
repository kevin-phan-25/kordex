package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/observability"
	"kordex.local/operator/internal/safety"
)

// recover performs verification and an operation-owned uncordon only. It never starts an eviction.
// It remains available offline, after authorization expiry and while the CR is being deleted.
func (r *Reconciler) recover(ctx context.Context, m *operations.NodeMaintenance) error {
	if m.Status.OriginalUnschedulable == nil {
		return r.transition(ctx, m, "Failed", "NoRecoverableCheckpoint")
	}
	var node corev1.Node
	if err := r.Reader.Get(ctx, types.NamespacedName{Name: m.Status.TargetNodeName}, &node); err != nil {
		return err
	}
	if string(node.UID) != m.Status.TargetNodeUID {
		return r.recoveryWait(ctx, m, "NodeIdentityChanged")
	}
	if node.Status.NodeInfo.BootID != m.Status.OriginalBootID {
		return r.recoveryWait(ctx, m, "UnexpectedNodeReboot")
	}
	pods, result, err := r.Checker.Cluster(ctx, node.Name, m.Status.Evictions)
	if err != nil {
		return err
	}
	if !result.Allowed {
		return r.recoveryWait(ctx, m, result.Reason)
	}
	if r.Checker.Storage == nil || r.Checker.Quorum == nil {
		return r.recoveryWait(ctx, m, "RecoverySafetyUnknown")
	}
	storagePods, storageResult, err := r.Checker.RecoveryStoragePods(ctx, &node, pods)
	if err != nil {
		return err
	}
	if !storageResult.Allowed {
		return r.recoveryWait(ctx, m, storageResult.Reason)
	}
	if result, err = r.Checker.Storage.Check(ctx, &node, storagePods); err != nil {
		return err
	} else if !result.Allowed {
		return r.recoveryWait(ctx, m, result.Reason)
	}
	if result, err = r.Checker.Quorum.Check(ctx, &node); err != nil {
		return err
	} else if !result.Allowed {
		return r.recoveryWait(ctx, m, result.Reason)
	}

	var recovered safety.Result
	if m.Status.Outcome == "Cancelled" {
		recovered, err = r.Checker.AllRecoveredAfterCancellation(ctx, m.Status.Evictions)
	} else {
		recovered, err = r.Checker.AllRecovered(ctx, m.Status.Evictions)
	}
	if err != nil {
		return err
	} else if !recovered.Allowed {
		return r.recoveryWait(ctx, m, recovered.Reason)
	}
	if m.Status.Phase == "VerifyingNode" {
		return r.transition(ctx, m, "VerifyingWorkloads", "NodeRecoveryVerified")
	}
	if m.Status.RecoveryStartedAt == nil {
		t := metav1.NewTime(r.now())
		m.Status.RecoveryStartedAt = &t
		return r.Client.Status().Update(ctx, m)
	}
	if r.now().Sub(m.Status.RecoveryStartedAt.Time) < time.Duration(max(10, m.Status.RecoverySeconds))*time.Second {
		return nil
	}
	if m.Status.Phase != "Uncordoning" {
		return r.transition(ctx, m, "Uncordoning", "WorkloadRecoveryVerified")
	}
	owner := node.Annotations[execution.OwnerAnnotation]
	if owner == string(m.UID) {
		if *m.Status.OriginalUnschedulable {
			return r.recoveryWait(ctx, m, "OriginalCordonMustBePreserved")
		}
		if err := execution.Cordon(ctx, r.Client, &node, string(m.UID), false); err != nil {
			return err
		}
		return nil
	}
	if owner != "" || node.Spec.Unschedulable {
		return r.recoveryWait(ctx, m, "CordonOwnershipChanged")
	}
	outcome := m.Status.Outcome
	if outcome == "" {
		outcome = "Failed"
	}
	if !m.DeletionTimestamp.IsZero() {
		outcome = "Cancelled"
	}
	reason := "RecoveryVerified"
	if outcome != "Succeeded" && m.Status.FailureReason != "" {
		reason = m.Status.FailureReason
	}
	return r.transition(ctx, m, outcome, reason)
}
func (r *Reconciler) recoveryWait(ctx context.Context, m *operations.NodeMaintenance, reason string) error {
	if m.Status.Reason != reason {
		observability.RecoveryBlocked(reason)
	}
	if m.Status.RecoveryStartedAt != nil {
		m.Status.RecoveryStartedAt = nil
		return r.Client.Status().Update(ctx, m)
	}
	// Keep the active recovery blocker visible. Persist suppresses identical
	// phase/reason pairs, so repeated reconciles do not create duplicate events.
	if m.Status.Phase == "RecoveryRequired" {
		return r.transition(ctx, m, "RecoveryRequired", reason)
	}
	return r.transition(ctx, m, m.Status.Phase, reason)
}
