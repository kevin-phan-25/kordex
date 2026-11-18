package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/safety"
)

// authorizeBoundary repeats identity/ownership/freshness checks after potentially slow preflight reads.
// Cross-resource health cannot be one atomic Kubernetes transaction; eviction still enforces its PDB.
func (r *Reconciler) authorizeBoundary(ctx context.Context, m *operations.NodeMaintenance, p protocol.MaintenancePermit, phase string) (*corev1.Node, error) {
	var current operations.NodeMaintenance
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: m.Name}, &current); err != nil {
		return nil, err
	}
	if current.UID != m.UID || current.Status.Sequence != m.Status.Sequence {
		return nil, fmt.Errorf("operation checkpoint changed; reconcile fresh state")
	}
	if current.Annotations[protocol.CancellationAnnotation] != "" {
		return nil, fmt.Errorf("operation control changed; reconcile before disruption")
	}
	if !current.DeletionTimestamp.IsZero() {
		return nil, r.abort(ctx, m, "OperationDeleted", true)
	}
	var policy operations.MaintenancePolicy
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: p.Policy.Name}, &policy); err != nil {
		return nil, err
	}
	if string(policy.UID) != p.Policy.UID || policy.Generation != p.Policy.Generation || policy.Spec.Suspended {
		return nil, r.abort(ctx, m, "PolicyGenerationChanged", false)
	}
	var node corev1.Node
	if err := r.Reader.Get(ctx, types.NamespacedName{Name: p.NodeName}, &node); err != nil {
		return nil, err
	}
	if string(node.UID) != p.NodeUID {
		return nil, r.abort(ctx, m, "NodeIdentityChanged", false)
	}
	if node.Status.NodeInfo.BootID != m.Status.OriginalBootID {
		return nil, r.abort(ctx, m, "UnexpectedNodeReboot", false)
	}
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.NodeSelector)
	if err != nil || !selector.Matches(labels.Set(node.Labels)) || node.Labels[safety.StatelessLabel] != "stateless" {
		return nil, r.abort(ctx, m, "NodeEligibilityChanged", false)
	}
	if (phase == "Draining" || phase == "Executing" || phase == "Rebooting") && (node.Annotations[execution.OwnerAnnotation] != string(m.UID) || !node.Spec.Unschedulable) {
		return nil, r.abort(ctx, m, "CordonOwnershipChanged", false)
	}
	held, err := r.slot(ctx, m.UID, false)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, r.abort(ctx, m, "ReservationLost", false)
	}
	candidates, safe, err := r.Checker.Preflight(ctx, &node, &policy, m.Status.Evictions)
	if err != nil {
		return nil, err
	}
	if !safe.Allowed {
		return nil, r.block(ctx, m, phase, safe.Reason)
	}
	for i := range candidates {
		pdb, err := r.Checker.PDB(ctx, &candidates[i])
		if err != nil {
			return nil, err
		}
		if !pdb.Allowed {
			return nil, r.block(ctx, m, phase, pdb.Reason)
		}
	}
	result, err := r.Checker.NodeReady(ctx, &node)
	if err != nil {
		return nil, err
	}
	if !result.Allowed {
		return nil, r.block(ctx, m, phase, result.Reason)
	}
	if !r.connected(ctx, m.Namespace) {
		return nil, r.block(ctx, m, phase, "ManagementDisconnected")
	}
	if err := r.checkKuredLock(ctx, m); err != nil {
		return nil, r.block(ctx, m, phase, "KuredLockUnavailable")
	}
	// This must be last: previous reads may have consumed the remaining permit lifetime.
	if !permitFreshForBoundary(m, p, phase, r.now()) {
		return nil, r.abort(ctx, m, "AuthorizationExpired", false)
	}
	return &node, nil
}

func permitFreshForBoundary(m *operations.NodeMaintenance, p protocol.MaintenancePermit, phase string, now time.Time) bool {
	if p.Fresh(now) {
		return true
	}
	checkpoint := m.Status.UpgradeCheckpoint
	// A valid permit accepted the complete UpgradePackages action. If its first
	// package phase completed with a verified receipt, the separately checkpointed
	// reboot is continuation of that action, not a stale new command.
	return p.Action == protocol.UpgradePackages && !now.Before(p.ExpiresAt) && !now.Before(p.NotBefore) && !p.IssuedAt.After(now.Add(5*time.Second)) && phase == "Rebooting" && checkpoint != nil && checkpoint.PlanDigest == p.PlanDigest && checkpoint.NodeUID == p.NodeUID && checkpoint.Phase == protocol.UpgradeRebooting && checkpoint.Outcome == "PackagesVerified" && checkpoint.RebootRequested && hasVerifiedApplyReceipt(checkpoint)
}
