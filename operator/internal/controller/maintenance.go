package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/safety"
)

type Reconciler struct {
	Client    client.Client
	Reader    client.Reader
	Checker   *safety.Checker
	Evictor   execution.Evictor
	Keys      map[string]ed25519.PublicKey
	ClusterID string
	Logger    *slog.Logger
	Now       func() time.Time
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&operations.NodeMaintenance{}).Complete(r)
}
func (r *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = bounded
	retry := ctrl.Result{RequeueAfter: 2 * time.Second}
	var m operations.NodeMaintenance
	if err := r.Reader.Get(ctx, request.NamespacedName, &m); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if protocol.TerminalPhase(m.Status.Phase) {
		return ctrl.Result{}, r.finish(ctx, &m)
	}
	if !hasFinalizer(&m) {
		m.Finalizers = append(m.Finalizers, Finalizer)
		return retry, r.Client.Update(ctx, &m)
	}
	id := strings.TrimPrefix(m.Name, "op-")
	if !protocol.ValidUUID(id) || m.Name != "op-"+id {
		return retry, r.abort(ctx, &m, "InvalidOperationName", false)
	}
	if err := r.receipt(ctx, &m, protocol.MaintenancePermit{MaintenanceRequest: protocol.MaintenanceRequest{OperationID: id}}); err != nil {
		if errors.Is(err, ErrDuplicateOperation) {
			return retry, r.abort(ctx, &m, "DuplicateOperation", false)
		}
		return retry, err
	}
	if raw := m.Annotations[protocol.CancellationAnnotation]; raw != "" && m.Status.Outcome != "Cancelled" && m.Status.FailureReason != "InvalidCancellation" {
		var control protocol.OperationControl
		if json.Unmarshal([]byte(raw), &control) != nil || control.Verify(r.Keys, id, r.ClusterID, m.Spec.Command().Digest(), r.now()) != nil {
			return retry, r.abort(ctx, &m, "InvalidCancellation", false)
		}
		return retry, r.abort(ctx, &m, "CancelledByHub", true)
	}
	// Recovery uses the already validated, durable target, even after a signing key is revoked.
	recovering := m.Status.Phase == "RecoveryRequired" || m.Status.Phase == "VerifyingNode" || m.Status.Phase == "VerifyingWorkloads" || m.Status.Phase == "Uncordoning"
	if !m.DeletionTimestamp.IsZero() && !recovering {
		return retry, r.abort(ctx, &m, "OperationDeleted", true)
	}
	if recovering {
		return retry, r.recover(ctx, &m)
	}
	permit, err := protocol.DecodeMaintenance(m.Spec.Command(), r.Keys)
	if err != nil {
		return retry, r.abort(ctx, &m, "InvalidAuthorization", false)
	}
	if permit.ClusterID != r.ClusterID || m.Name != "op-"+permit.OperationID {
		return retry, r.abort(ctx, &m, "IdentityMismatch", false)
	}
	var cluster corev1.Namespace
	if err = r.Reader.Get(ctx, types.NamespacedName{Name: "kube-system"}, &cluster); err != nil {
		return retry, err
	}
	if string(cluster.UID) != permit.ClusterUID {
		return retry, r.abort(ctx, &m, "ClusterIdentityChanged", false)
	}
	if m.Status.OperationID == "" {
		m.Status.OperationID = permit.OperationID
		m.Status.TargetNodeName = permit.NodeName
		m.Status.TargetNodeUID = permit.NodeUID
		return retry, r.transition(ctx, &m, "Pending", "RequestAccepted")
	}
	if !permit.Fresh(r.now()) {
		return retry, r.abort(ctx, &m, "AuthorizationExpired", false)
	}
	if m.Status.OperationID != permit.OperationID || m.Status.TargetNodeUID != permit.NodeUID || m.Status.TargetNodeName != permit.NodeName {
		return retry, r.abort(ctx, &m, "PersistedIdentityMismatch", false)
	}

	var node corev1.Node
	if err = r.Reader.Get(ctx, types.NamespacedName{Name: permit.NodeName}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			return retry, r.abort(ctx, &m, "NodeMissing", false)
		}
		return retry, err
	}
	if string(node.UID) != permit.NodeUID {
		return retry, r.abort(ctx, &m, "NodeIdentityChanged", false)
	}
	var policy operations.MaintenancePolicy
	if err = r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: permit.Policy.Name}, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return retry, r.abort(ctx, &m, "PolicyMissing", false)
		}
		return retry, err
	}
	if string(policy.UID) != permit.Policy.UID || policy.Generation != permit.Policy.Generation {
		return retry, r.abort(ctx, &m, "PolicyGenerationChanged", false)
	}
	phase := m.Status.Phase
	if phase == "Blocked" {
		phase = m.Status.ResumePhase
	}
	if phase == "Pending" {
		return retry, r.transition(ctx, &m, "Validating", "AuthorizationValidated")
	}
	held, err := r.slot(ctx, m.UID, true)
	if err != nil {
		return retry, err
	}
	if !held {
		return retry, r.block(ctx, &m, phase, "ClusterConcurrencyLimit")
	}
	if !r.connected(ctx, m.Namespace) {
		return retry, r.block(ctx, &m, phase, "ManagementDisconnected")
	}
	if phase == "Validating" {
		return retry, r.transition(ctx, &m, "SafetyChecking", "SlotReserved")
	}
	if node.Status.NodeInfo.BootID == "" {
		return retry, r.block(ctx, &m, phase, "BootIdentityUnknown")
	}
	if m.Status.OriginalUnschedulable == nil && node.Annotations[execution.OwnerAnnotation] != "" {
		return retry, r.block(ctx, &m, phase, "ForeignCordonOwner")
	}
	if m.Status.OriginalUnschedulable != nil && node.Status.NodeInfo.BootID != m.Status.OriginalBootID {
		return retry, r.abort(ctx, &m, "UnexpectedNodeReboot", false)
	}
	if m.Status.OriginalUnschedulable == nil && node.Spec.Unschedulable {
		return retry, r.block(ctx, &m, phase, "NodeAlreadyCordoned")
	}
	if m.Status.OriginalUnschedulable != nil && (node.Annotations[execution.OwnerAnnotation] != string(m.UID) || !node.Spec.Unschedulable) {
		// The Cordoning phase may not have applied its persisted intent yet.
		if phase != "Cordoning" || node.Spec.Unschedulable || node.Annotations[execution.OwnerAnnotation] != "" {
			return retry, r.abort(ctx, &m, "CordonOwnershipChanged", false)
		}
	}
	candidates, result, err := r.Checker.Preflight(ctx, &node, &policy, m.Status.Evictions)
	if err != nil {
		return retry, err
	}
	if !result.Allowed {
		return retry, r.block(ctx, &m, phase, result.Reason)
	}
	switch phase {
	case "SafetyChecking":
		for i := range candidates {
			result, err = r.Checker.PDB(ctx, &candidates[i])
			if err != nil {
				return retry, err
			}
			if !result.Allowed {
				return retry, r.block(ctx, &m, phase, result.Reason)
			}
		}
		if permit.Action == protocol.ValidateOnly {
			m.Status.Outcome = "Succeeded"
			return retry, r.transition(ctx, &m, "Succeeded", "ValidationPassed")
		}
		original := node.Spec.Unschedulable
		m.Status.OriginalUnschedulable = &original
		m.Status.OriginalBootID = node.Status.NodeInfo.BootID
		m.Status.RecoverySeconds = max(10, policy.Spec.RecoverySeconds)
		return retry, r.transition(ctx, &m, "Cordoning", "CordonIntentPersisted")
	case "Cordoning":
		if m.Status.Phase == "Blocked" {
			return retry, r.transition(ctx, &m, "Cordoning", "SafetyRestored")
		}
		fresh, err := r.authorizeBoundary(ctx, &m, permit, "Cordoning")
		if err != nil || fresh == nil {
			return retry, err
		}
		if err = execution.Cordon(ctx, r.Client, fresh, string(m.UID), true); err != nil {
			return retry, err
		}
		return retry, r.transition(ctx, &m, "Draining", "NodeCordoned")
	case "Draining":
		if m.Status.Phase == "Blocked" {
			return retry, r.transition(ctx, &m, "Draining", "SafetyRestored")
		}
		if result, err = r.Checker.AllRecovered(ctx, m.Status.Evictions); err != nil {
			return retry, err
		}
		if !result.Allowed {
			return retry, r.block(ctx, &m, phase, result.Reason)
		}
		if len(candidates) == 0 {
			m.Status.Outcome = "Succeeded"
			return retry, r.transition(ctx, &m, "VerifyingNode", "DrainObservedComplete")
		}
		pod := &candidates[0]
		if result, err = r.Checker.PDB(ctx, pod); err != nil {
			return retry, err
		}
		if !result.Allowed {
			return retry, r.block(ctx, &m, phase, result.Reason)
		}
		recorded := false
		for _, v := range m.Status.Evictions {
			if v.UID == string(pod.UID) {
				recorded = true
				break
			}
		}
		if !recorded {
			workload, result, err := r.Checker.Workload(ctx, pod)
			if err != nil {
				return retry, err
			}
			if !result.Allowed {
				return retry, r.block(ctx, &m, phase, result.Reason)
			}
			m.Status.Evictions = append(m.Status.Evictions, operations.EvictionRecord{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Workload: workload})
			return retry, r.checkpoint(ctx, &m, "EvictionIntentPersisted", string(pod.UID))
		}
		fresh, err := r.authorizeBoundary(ctx, &m, permit, "Draining")
		if err != nil || fresh == nil {
			return retry, err
		}
		if err = r.Evictor.Evict(ctx, pod, max(1, policy.Spec.GracePeriodSeconds)); err != nil {
			if apierrors.IsTooManyRequests(err) {
				return retry, r.block(ctx, &m, phase, "EvictionPDBBlocked")
			}
			if apierrors.IsNotFound(err) {
				return retry, nil
			}
			return retry, err
		}
		return retry, r.checkpoint(ctx, &m, "EvictionAccepted", string(pod.UID))
	default:
		return retry, r.abort(ctx, &m, "UnsupportedPhase", false)
	}
}
func (r *Reconciler) block(ctx context.Context, m *operations.NodeMaintenance, resume, reason string) error {
	m.Status.ResumePhase = resume
	return r.transition(ctx, m, "Blocked", reason)
}
func (r *Reconciler) abort(ctx context.Context, m *operations.NodeMaintenance, reason string, cancelled bool) error {
	outcome := "Failed"
	if cancelled {
		outcome = "Cancelled"
	}
	m.Status.Outcome = outcome
	m.Status.FailureReason = reason
	if m.Status.OriginalUnschedulable != nil {
		return r.transition(ctx, m, "RecoveryRequired", reason)
	}
	return r.transition(ctx, m, outcome, reason)
}
func (r *Reconciler) finish(ctx context.Context, m *operations.NodeMaintenance) error {
	if m.Status.OriginalUnschedulable != nil {
		var node corev1.Node
		err := r.Reader.Get(ctx, types.NamespacedName{Name: m.Status.TargetNodeName}, &node)
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		// A completed operation must not adopt a later external cordon or a replacement node.
		if err == nil && string(node.UID) == m.Status.TargetNodeUID && node.Annotations[execution.OwnerAnnotation] == string(m.UID) {
			return r.abort(ctx, m, "TerminalRecoveryIncomplete", false)
		}
	}
	if err := r.release(ctx, m); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// Do not delete the only durable completion record before the hub has committed it.
	ack, err := strconv.ParseInt(m.Annotations[protocol.AckAnnotation], 10, 64)
	if err != nil || ack < m.Status.Sequence {
		return nil
	}
	if hasFinalizer(m) {
		removeFinalizer(m)
		return r.Client.Update(ctx, m)
	}
	return nil
}
