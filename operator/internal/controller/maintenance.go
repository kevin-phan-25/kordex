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

	"go.opentelemetry.io/otel"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
	"kordex.local/operator/internal/observability"
	"kordex.local/operator/internal/provider/gke"
	"kordex.local/operator/internal/reboot"
	"kordex.local/operator/internal/safety"
)

type Reconciler struct {
	Client    client.Client
	Reader    client.Reader
	Checker   *safety.Checker
	Evictor   execution.Evictor
	Upgrader  UpgradeJobExecutor
	Kured     *reboot.Kured
	GKE       GKENodePoolExecutor
	Keys      map[string]ed25519.PublicKey
	ClusterID string
	Logger    *slog.Logger
	Now       func() time.Time
}

type UpgradeJobExecutor interface {
	RecoveryTrustDigest(context.Context) (string, error)
	Ensure(context.Context, execution.AnsibleJobRequest) (string, error)
	Start(context.Context, execution.AnsibleJobRequest, string) error
	Observe(context.Context, execution.AnsibleJobRequest, string) (execution.AnsibleJobObservation, error)
	Cancel(context.Context, execution.AnsibleJobRequest, string) error
}

type GKENodePoolExecutor interface {
	GetNodePool(context.Context, protocol.GKENodePoolReference) (gke.NodePool, error)
	UpdateNodePool(context.Context, protocol.GKENodePoolReference, string, string, string) (gke.Operation, error)
	GetOperation(context.Context, protocol.GKENodePoolReference, string) (gke.Operation, error)
	ListOperations(context.Context, protocol.GKENodePoolReference) ([]gke.Operation, error)
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&operations.NodeMaintenance{}).Complete(r)
}
func (r *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (reconcileResult ctrl.Result, reconcileErr error) {
	ctx, span := observability.StartMaintenanceReconcile(ctx, otel.Tracer("kordex.operator"))
	var m operations.NodeMaintenance
	action := ""
	defer func() {
		outcome := "complete"
		errorClass := ""
		if reconcileErr != nil {
			outcome = "error"
			errorClass = reconcileErrorClass(reconcileErr)
		} else if reconcileResult.Requeue || reconcileResult.RequeueAfter > 0 {
			outcome = "requeue"
		}
		observability.EndMaintenanceReconcile(span, m.Status.Phase, action, outcome, errorClass)
	}()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ctx = bounded
	retry := ctrl.Result{RequeueAfter: 2 * time.Second}
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
		if m.Status.ProviderUpgradeCheckpoint != nil {
			if !m.Status.ProviderUpgradeCheckpoint.CancelRequested {
				return retry, r.cancelProviderUpgrade(ctx, &m)
			}
			// The withdrawal is durable. Continue the provider observer below so
			// an already submitted or ambiguous external operation is tracked to
			// verified completion instead of remaining stuck in cancellation.
		} else {
			if m.Status.UpgradeCheckpoint != nil && r.Upgrader != nil {
				var permit protocol.MaintenancePermit
				if json.Unmarshal([]byte(m.Spec.Authorization), &permit) != nil || permit.OperationID != id || permit.Action != protocol.UpgradePackages {
					return retry, r.interruptUnresolvedUpgrade(ctx, &m, "CancellationPermitUnavailable")
				}
				var node corev1.Node
				if err := r.Reader.Get(ctx, types.NamespacedName{Name: permit.NodeName}, &node); err != nil {
					return retry, err
				}
				var policy operations.MaintenancePolicy
				if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: permit.Policy.Name}, &policy); err != nil {
					return retry, err
				}
				if policy.Spec.Upgrade == nil {
					return retry, r.interruptUnresolvedUpgrade(ctx, &m, "CancellationPolicyUnavailable")
				}
				return retry, r.interruptUpgrade(ctx, &m, permit, &node, *policy.Spec.Upgrade, "CancelledByHub")
			}
			return retry, r.abort(ctx, &m, "CancelledByHub", true)
		}
	}
	// Recovery uses the already validated, durable target, even after a signing key is revoked.
	recovering := (m.Status.Phase == "RecoveryRequired" || m.Status.Phase == "VerifyingNode" || m.Status.Phase == "VerifyingWorkloads" || m.Status.Phase == "Uncordoning") && m.Status.ProviderUpgradeCheckpoint == nil
	providerOutcomeUncertain := false
	if checkpoint := m.Status.ProviderUpgradeCheckpoint; checkpoint != nil {
		providerOutcomeUncertain = checkpoint.Phase == "Submitting" || checkpoint.Phase == "Updating" || checkpoint.Phase == "Verifying" || checkpoint.Phase == "RecoveryRequired"
	}
	if !m.DeletionTimestamp.IsZero() && !recovering && !providerOutcomeUncertain {
		return retry, r.abort(ctx, &m, "OperationDeleted", true)
	}
	if !m.DeletionTimestamp.IsZero() && providerOutcomeUncertain && m.Status.ProviderUpgradeCheckpoint != nil && !m.Status.ProviderUpgradeCheckpoint.CancelRequested {
		return retry, r.cancelProviderUpgrade(ctx, &m)
	}
	if recovering {
		return retry, r.recover(ctx, &m)
	}
	permit, err := protocol.DecodeMaintenance(m.Spec.Command(), r.Keys)
	if err != nil {
		return retry, r.abort(ctx, &m, "InvalidAuthorization", false)
	}
	action = permit.Action
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
	if !permit.Fresh(r.now()) && !(permit.Action == protocol.UpgradePackages && m.Status.UpgradeCheckpoint != nil) && !(permit.Action == protocol.UpgradeNodePool && m.Status.ProviderUpgradeCheckpoint != nil) {
		return retry, r.abort(ctx, &m, "AuthorizationExpired", false)
	}
	if m.Status.OperationID != permit.OperationID || m.Status.TargetNodeUID != permit.NodeUID || m.Status.TargetNodeName != permit.NodeName {
		return retry, r.abort(ctx, &m, "PersistedIdentityMismatch", false)
	}
	if permit.Action == protocol.UpgradeNodePool {
		return retry, r.reconcileProviderUpgrade(ctx, &m, permit)
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
	actionDecision := protocol.EvaluateMaintenanceAction(policy.Generation, policy.Spec.AllowedActions, permit.Action)
	if !actionDecision.Allowed {
		return retry, r.abort(ctx, &m, actionDecision.ReasonCode, false)
	}
	var upgradePolicy *protocol.UpgradePolicy
	if permit.Action == protocol.UpgradePackages {
		if policy.Spec.Upgrade == nil {
			return retry, r.abort(ctx, &m, "UpgradePlanMissing", false)
		}
		digest, digestErr := policy.Spec.Upgrade.Digest()
		if digestErr != nil || digest != permit.PlanDigest {
			return retry, r.abort(ctx, &m, "UpgradePlanMismatch", false)
		}
		if !policy.Spec.Upgrade.MatchesNodeOS(protocol.Node{OSImage: node.Status.NodeInfo.OSImage, Labels: node.Labels}) {
			return retry, r.abort(ctx, &m, "UpgradePlanOSIdentityMismatch", false)
		}
		if r.Upgrader == nil {
			return retry, r.rejectUnsupportedUpgrade(ctx, &m, permit, node.Status.NodeInfo.BootID)
		}
		upgradePolicy = policy.Spec.Upgrade
	}
	if permit.Action == protocol.UpgradeNodePool {
		if policy.Spec.ProviderUpgrade == nil {
			return retry, r.abort(ctx, &m, "UpgradePlanMissing", false)
		}
		digest, digestErr := policy.Spec.ProviderUpgrade.Digest()
		if digestErr != nil || digest != permit.PlanDigest {
			return retry, r.abort(ctx, &m, "UpgradePlanMismatch", false)
		}
		// Provider requests share the durable signed-intent journal and remain
		// disabled until the local provider adapter can recover ambiguous calls.
		return retry, r.rejectUnsupportedUpgrade(ctx, &m, permit, node.Status.NodeInfo.BootID)
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
		reason, reasonErr := r.slotBlockReason(ctx, m.Namespace)
		if reasonErr != nil {
			return retry, reasonErr
		}
		return retry, r.block(ctx, &m, phase, reason)
	}
	if !r.connected(ctx, m.Namespace) {
		if upgradePolicy != nil && (phase == "Preflighting" || phase == "Executing" || phase == "Rebooting") {
			return retry, r.interruptUpgrade(ctx, &m, permit, &node, *upgradePolicy, "ManagementDisconnected")
		}
		return retry, r.block(ctx, &m, phase, "ManagementDisconnected")
	}
	if upgradePolicy != nil {
		if phase == "Validating" && r.Kured != nil && (r.Kured.Enabled || m.Annotations[kuredLockReference] != "") && !permit.Fresh(r.now()) {
			return retry, r.abort(ctx, &m, "AuthorizationExpired", false)
		}
		ready, lockErr := r.ensureKuredLock(ctx, &m, phase)
		if lockErr != nil {
			if r.Logger != nil {
				r.Logger.WarnContext(ctx, "kured interlock blocked host maintenance", "operation_id", permit.OperationID, "error", lockErr.Error())
			}
			if phase == "Executing" || phase == "Rebooting" {
				return retry, r.interruptUpgrade(ctx, &m, permit, &node, *upgradePolicy, "KuredLockUnavailable")
			}
			return retry, r.block(ctx, &m, phase, "KuredLockUnavailable")
		}
		if !ready {
			return retry, nil
		}
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
	if m.Status.OriginalUnschedulable != nil && node.Status.NodeInfo.BootID != m.Status.OriginalBootID && !(upgradePolicy != nil && phase == "Rebooting") {
		return retry, r.abort(ctx, &m, "UnexpectedNodeReboot", false)
	}
	if m.Status.OriginalUnschedulable == nil && node.Spec.Unschedulable {
		return retry, r.block(ctx, &m, phase, "NodeAlreadyCordoned")
	}
	if m.Status.OriginalUnschedulable != nil && phase != "Preflighting" && (node.Annotations[execution.OwnerAnnotation] != string(m.UID) || !node.Spec.Unschedulable) {
		// The Cordoning phase may not have applied its persisted intent yet.
		if phase != "Cordoning" || node.Spec.Unschedulable || node.Annotations[execution.OwnerAnnotation] != "" {
			return retry, r.abort(ctx, &m, "CordonOwnershipChanged", false)
		}
	}
	var candidates []corev1.Pod
	result := safety.Pass()
	// The target is expected to be NotReady while the already-authorized reboot
	// Job waits for SSH to return. The receipt and post-reboot checks decide
	// recovery; all safety checks are rerun before a suspended Job starts.
	if !(upgradePolicy != nil && phase == "Rebooting") {
		candidates, result, err = r.Checker.Preflight(ctx, &node, &policy, m.Status.Evictions)
		if err != nil {
			return retry, err
		}
		if !result.Allowed {
			if upgradePolicy != nil && phase == "Executing" {
				return retry, r.interruptUpgrade(ctx, &m, permit, &node, *upgradePolicy, result.Reason)
			}
			return retry, r.block(ctx, &m, phase, result.Reason)
		}
	}
	switch phase {
	case "SafetyChecking":
		for i := range candidates {
			result, err = r.Checker.PDBBeforeCordon(ctx, &candidates[i])
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
		if upgradePolicy != nil {
			if err := r.initializeUpgradeCheckpoint(&m, permit, node.Status.NodeInfo.BootID); err != nil {
				return retry, r.abort(ctx, &m, "UpgradeCheckpointIdentityChanged", false)
			}
			jobName := execution.AnsibleJobReference(permit.OperationID, execution.EEPhasePreflight)
			if err := r.advanceUpgradeCheckpointState(&m, protocol.UpgradePreflighting, "PreflightIntentPersisted", func(checkpoint *protocol.UpgradeCheckpoint) {
				checkpoint.ExecutionReference = jobName
			}); err != nil {
				return retry, r.abort(ctx, &m, "UpgradeCheckpointTransitionInvalid", false)
			}
			return retry, r.transition(ctx, &m, "Preflighting", "HostIdentityPreflight")
		}
		return retry, r.transition(ctx, &m, "Cordoning", "CordonIntentPersisted")
	case "Preflighting":
		for i := range candidates {
			result, err = r.Checker.PDBBeforeCordon(ctx, &candidates[i])
			if err != nil {
				return retry, err
			}
			if !result.Allowed {
				return retry, r.block(ctx, &m, phase, result.Reason)
			}
		}
		if upgradePolicy == nil {
			return retry, r.abort(ctx, &m, "UpgradePlanMissing", false)
		}
		return retry, r.reconcileUpgradePreflight(ctx, &m, permit, &node, *upgradePolicy)
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
		if upgradePolicy != nil {
			if err = r.advanceUpgradeCheckpointState(&m, protocol.UpgradeDraining, "NodeCordoned", nil); err != nil {
				return retry, r.abort(ctx, &m, "UpgradeCheckpointTransitionInvalid", false)
			}
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
			if upgradePolicy != nil {
				jobName := execution.AnsibleJobReference(permit.OperationID, execution.EEPhaseApply)
				if err = r.advanceUpgradeCheckpointState(&m, protocol.UpgradeExecuting, "PackageApplyIntentPersisted", func(checkpoint *protocol.UpgradeCheckpoint) {
					checkpoint.ExecutionReference = jobName
				}); err != nil {
					return retry, r.abort(ctx, &m, "UpgradeCheckpointTransitionInvalid", false)
				}
				return retry, r.transition(ctx, &m, "Executing", "PackagesApplying")
			}
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
	case "Executing":
		if upgradePolicy == nil {
			return retry, r.abort(ctx, &m, "UpgradePlanMissing", false)
		}
		return retry, r.reconcileUpgradeJob(ctx, &m, permit, &node, *upgradePolicy, execution.EEPhaseApply)
	case "Rebooting":
		if upgradePolicy == nil {
			return retry, r.abort(ctx, &m, "UpgradePlanMissing", false)
		}
		return retry, r.reconcileUpgradeJob(ctx, &m, permit, &node, *upgradePolicy, execution.EEPhaseReboot)
	default:
		return retry, r.abort(ctx, &m, "UnsupportedPhase", false)
	}
}

func reconcileErrorClass(err error) string {
	switch {
	case apierrors.IsConflict(err):
		return "conflict"
	case apierrors.IsNotFound(err):
		return "not_found"
	case apierrors.IsTimeout(err), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "other"
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
	if err := r.release(ctx, m); err != nil {
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
