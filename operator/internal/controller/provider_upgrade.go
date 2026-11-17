package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/provider/gke"
)

func (r *Reconciler) reconcileProviderUpgrade(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit) error {
	if permit.Action != protocol.UpgradeNodePool || r.GKE == nil {
		return r.abort(ctx, m, "ProviderExecutorUnavailable", false)
	}
	var policy operations.MaintenancePolicy
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: permit.Policy.Name}, &policy); err != nil {
		if apierrors.IsNotFound(err) && m.Status.ProviderUpgradeCheckpoint != nil {
			return r.providerRecovery(ctx, m, "ProviderPolicyMissing")
		}
		return err
	}
	if string(policy.UID) != permit.Policy.UID || policy.Generation != permit.Policy.Generation {
		if m.Status.ProviderUpgradeCheckpoint != nil {
			return r.providerRecovery(ctx, m, "ProviderPolicyChanged")
		}
		return r.abort(ctx, m, "PolicyGenerationChanged", false)
	}
	plan := policy.Spec.ProviderUpgrade
	if plan == nil {
		return r.abort(ctx, m, "UpgradePlanMissing", false)
	}
	digest, err := plan.Digest()
	if err != nil || digest != permit.PlanDigest {
		return r.abort(ctx, m, "UpgradePlanMismatch", false)
	}
	ref, ok := plan.GKENodePool()
	if !ok {
		return r.abort(ctx, m, "ProviderResourceUnsupported", false)
	}

	cp := m.Status.ProviderUpgradeCheckpoint
	if cp == nil {
		var anchor corev1.Node
		if err = r.Reader.Get(ctx, types.NamespacedName{Name: permit.NodeName}, &anchor); err != nil {
			if apierrors.IsNotFound(err) {
				return r.abort(ctx, m, "NodeMissing", false)
			}
			return err
		}
		if string(anchor.UID) != permit.NodeUID || !providerPlanMatchesNode(*plan, ref, &anchor) {
			return r.abort(ctx, m, "ProviderTargetIdentityMismatch", false)
		}
		now := r.now()
		m.Status.ProviderUpgradeCheckpoint = &protocol.ProviderUpgradeCheckpoint{PlanDigest: digest, Resource: plan.Resource, TargetVersion: plan.TargetVersion, Phase: "Pending", Sequence: 1, UpdatedAt: metav1.NewTime(now)}
		if err = m.Status.ProviderUpgradeCheckpoint.Validate(); err != nil {
			return r.abort(ctx, m, "ProviderCheckpointInvalid", false)
		}
		return r.transition(ctx, m, "Pending", "ProviderUpgradeAccepted")
	}
	if err = cp.Validate(); err != nil || cp.PlanDigest != digest || cp.Resource != plan.Resource || cp.TargetVersion != plan.TargetVersion {
		return r.providerRecovery(ctx, m, "ProviderCheckpointIdentityMismatch")
	}
	if cp.Phase == "Succeeded" {
		m.Status.Outcome = "Succeeded"
		return r.transition(ctx, m, "Succeeded", "ProviderUpgradeAlreadyVerified")
	}
	if cp.Phase == "Cancelled" {
		m.Status.Outcome = "Cancelled"
		return r.transition(ctx, m, "Cancelled", "ProviderUpgradeCancelled")
	}
	if cp.Phase == "Pending" && !permit.Fresh(r.now()) {
		return r.abort(ctx, m, "AuthorizationExpired", false)
	}

	phase := m.Status.Phase
	if phase == "Blocked" {
		phase = m.Status.ResumePhase
	}
	if phase == "Pending" {
		return r.transition(ctx, m, "Validating", "ProviderAuthorizationValidated")
	}
	held, err := r.slot(ctx, m.UID, true)
	if err != nil {
		return err
	}
	if !held {
		return r.block(ctx, m, phase, "ClusterConcurrencyLimit")
	}
	if !r.connected(ctx, m.Namespace) && cp.Phase != "Submitting" && cp.Phase != "Updating" {
		return r.block(ctx, m, phase, "ManagementDisconnected")
	}
	if phase == "Validating" {
		return r.transition(ctx, m, "SafetyChecking", "ProviderSlotReserved")
	}

	switch cp.Phase {
	case "Pending":
		if phase != "SafetyChecking" {
			return r.block(ctx, m, "SafetyChecking", "ProviderCheckpointPhaseMismatch")
		}
		poolNodes, safeReason, err := r.providerPreflight(ctx, ref, plan, &policy)
		if err != nil {
			return err
		}
		if safeReason != "" {
			return r.block(ctx, m, phase, safeReason)
		}
		identityDigests, err := providerNodeIdentityDigests(poolNodes)
		if err != nil {
			return r.block(ctx, m, phase, "ProviderHostIdentityUnknown")
		}
		pool, err := r.GKE.GetNodePool(ctx, ref)
		if err != nil {
			return err
		}
		if pool.Version != plan.TargetVersion && !gkeUpgradeSettingsMatch(pool, plan) {
			return r.block(ctx, m, phase, "GKENodePoolUpgradeSettingsMismatch")
		}
		if err = r.ensureNoActiveGKEOperation(ctx, ref); errors.Is(err, errGKEOperationActive) {
			return r.block(ctx, m, phase, "GKENodePoolOperationInProgress")
		} else if err != nil {
			return err
		}
		m.Status.ProviderUpgradeCheckpoint.InitialVersion = pool.Version
		if pool.Version == plan.TargetVersion {
			if err = r.advanceProviderCheckpoint(m, "Verifying", "TargetVersionAlreadyPresent", func(c *protocol.ProviderUpgradeCheckpoint) {
				c.IntentAt = metav1.NewTime(r.now())
				c.InitialNodeIdentityDigests = identityDigests
			}); err != nil {
				return err
			}
			return r.transition(ctx, m, "VerifyingNode", "TargetVersionAlreadyPresent")
		}
		if pool.Status != "RUNNING" {
			return r.block(ctx, m, phase, "GKENodePoolNotStable")
		}
		// Intent is durable before the one external mutation. If the process dies in
		// the following narrow interval, list operations and adopt only an exact
		// resource match; absence is never treated as permission to retry.
		if err = r.advanceProviderCheckpoint(m, "Submitting", "GKEUpdateIntentPersisted", func(c *protocol.ProviderUpgradeCheckpoint) {
			c.IntentAt = metav1.NewTime(r.now())
			c.InitialNodeIdentityDigests = identityDigests
		}); err != nil {
			return err
		}
		if err = r.transition(ctx, m, "Executing", "GKEUpdateIntentPersisted"); err != nil {
			return err
		}
		// Repeat operation, policy, connectivity, and local safety checks at the
		// external mutation boundary using fresh API reads.
		current, err := r.authorizeGKEUpdateBoundary(ctx, m, permit, ref, plan, pool)
		if err != nil {
			return r.providerRecovery(ctx, m, "GKEUpdatePreconditionUnverified")
		}
		op, err := r.GKE.UpdateNodePool(ctx, ref, plan.TargetVersion, current.Config.ImageType, current.Etag)
		if err != nil {
			return err
		} // durable Submitting state is recovered by operation listing
		if !gkeOperationTargets(op, ref) {
			return r.providerRecovery(ctx, m, "GKEOperationTargetMismatch")
		}
		if err = r.advanceProviderCheckpoint(m, "Updating", "GKEOperationAccepted", func(c *protocol.ProviderUpgradeCheckpoint) { c.OperationName = op.Name }); err != nil {
			return err
		}
		return r.checkpoint(ctx, m, "GKEOperationAccepted", op.Name)

	case "Submitting":
		op, found, err := r.findSubmittedGKEOperation(ctx, ref, cp)
		if errors.Is(err, errMultipleProviderOperations) {
			return r.providerRecovery(ctx, m, "MultipleGKEOperationsMatchSubmissionIntent")
		}
		if err != nil {
			return err
		}
		if !found {
			if r.now().Sub(cp.IntentAt.Time) > 3*time.Minute {
				return r.providerRecovery(ctx, m, "GKEUpdateSubmissionAmbiguous")
			}
			return nil
		}
		if !gkeOperationTargets(op, ref) {
			return r.providerRecovery(ctx, m, "GKEOperationTargetMismatch")
		}
		if err = r.advanceProviderCheckpoint(m, "Updating", "GKEOperationRecovered", func(c *protocol.ProviderUpgradeCheckpoint) { c.OperationName = op.Name }); err != nil {
			return err
		}
		return r.checkpoint(ctx, m, "GKEOperationRecovered", op.Name)

	case "Updating":
		if cp.OperationName == "" {
			return r.providerRecovery(ctx, m, "GKEOperationIdentityMissing")
		}
		op, err := r.GKE.GetOperation(ctx, ref, cp.OperationName)
		if err != nil {
			return err
		}
		if !gkeOperationTargets(op, ref) {
			return r.providerRecovery(ctx, m, "GKEOperationTargetMismatch")
		}
		if op.Status != "DONE" {
			if cp.IntentAt.IsZero() || r.now().Sub(cp.IntentAt.Time) > plan.Timeout {
				return r.providerRecovery(ctx, m, "GKEUpgradeTimedOut")
			}
			if phase != "Executing" {
				return r.transition(ctx, m, "Executing", "GKEUpgradeRunning")
			}
			return nil
		}
		if op.Error != nil {
			return r.providerRecovery(ctx, m, "GKEUpgradeFailed:"+safeProviderReason(op.Error.Message))
		}
		if err = r.advanceProviderCheckpoint(m, "Verifying", "GKEOperationCompleted", nil); err != nil {
			return err
		}
		return r.transition(ctx, m, "VerifyingNode", "GKEOperationCompleted")

	case "Verifying":
		if phase == "VerifyingNode" {
			return r.verifyProviderNodes(ctx, m, ref, plan)
		}
		if phase == "VerifyingWorkloads" {
			return r.verifyProviderWorkloads(ctx, m, ref, plan)
		}
		return r.block(ctx, m, "VerifyingNode", "ProviderVerificationPhaseMismatch")
	case "RecoveryRequired":
		return nil
	default:
		return r.providerRecovery(ctx, m, "ProviderCheckpointPhaseUnsupported")
	}
}

func (r *Reconciler) providerPreflight(ctx context.Context, ref protocol.GKENodePoolReference, plan *protocol.ProviderNodeUpgradePlan, policy *operations.MaintenancePolicy) ([]corev1.Node, string, error) {
	var nodes corev1.NodeList
	if err := r.Reader.List(ctx, &nodes); err != nil {
		return nil, "", err
	}
	matched := make([]corev1.Node, 0)
	for i := range nodes.Items {
		n := &nodes.Items[i]
		if n.Labels["cloud.google.com/gke-nodepool"] != ref.NodePool {
			continue
		}
		if !providerPlanMatchesNode(*plan, ref, n) {
			return nil, "ProviderNodeIdentityUnknown", nil
		}
		matched = append(matched, *n)
	}
	if len(matched) == 0 {
		return nil, "ProviderNodePoolEmpty", nil
	}
	for i := range matched {
		n := &matched[i]
		if n.Spec.Unschedulable {
			return nil, "ProviderNodeAlreadyCordoned", nil
		}
		candidates, safe, err := r.Checker.Preflight(ctx, n, policy, nil)
		if err != nil {
			return nil, "", err
		}
		if !safe.Allowed {
			return nil, safe.Reason, nil
		}
		for j := range candidates {
			pdb, err := r.Checker.PDBBeforeCordon(ctx, &candidates[j])
			if err != nil {
				return nil, "", err
			}
			if !pdb.Allowed {
				return nil, pdb.Reason, nil
			}
		}
	}
	return matched, "", nil
}

func (r *Reconciler) verifyProviderNodes(ctx context.Context, m *operations.NodeMaintenance, ref protocol.GKENodePoolReference, plan *protocol.ProviderNodeUpgradePlan) error {
	pool, err := r.GKE.GetNodePool(ctx, ref)
	if err != nil {
		return err
	}
	if pool.Status == "ERROR" || pool.Status == "RUNNING_WITH_ERROR" {
		return r.providerRecovery(ctx, m, "GKENodePoolError:"+safeProviderReason(pool.StatusMessage))
	}
	if pool.Version != plan.TargetVersion || pool.Status != "RUNNING" {
		return r.waitOrRecoverProvider(ctx, m, plan, "GKENodePoolNotAtTarget")
	}
	nodes, reason, err := r.providerPoolNodes(ctx, ref, plan)
	if err != nil {
		return err
	}
	if reason != "" {
		return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeNodeReadiness:"+reason)
	}
	for i := range nodes {
		if nodes[i].Spec.Unschedulable {
			return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeNodeStillCordoned")
		}
		if nodes[i].Status.NodeInfo.KubeletVersion == "" || normalizeVersion(nodes[i].Status.NodeInfo.KubeletVersion) != normalizeVersion(plan.TargetVersion) {
			return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeVersionNotObserved")
		}
	}
	if cp := m.Status.ProviderUpgradeCheckpoint; cp != nil && cp.InitialVersion != plan.TargetVersion {
		if len(nodes) != len(cp.InitialNodeIdentityDigests) {
			return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeNodePoolSizeMismatch")
		}
		currentIdentities, identityErr := providerNodeIdentityDigests(nodes)
		if identityErr != nil {
			return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeHostIdentityUnknown")
		}
		old := make(map[string]struct{}, len(cp.InitialNodeIdentityDigests))
		for _, digest := range cp.InitialNodeIdentityDigests {
			old[digest] = struct{}{}
		}
		for _, digest := range currentIdentities {
			if _, existed := old[digest]; existed {
				return r.waitOrRecoverProvider(ctx, m, plan, "OldNodeIdentityStillPresentAfterGKEUpgrade")
			}
		}
	}
	return r.transition(ctx, m, "VerifyingWorkloads", "NodePoolVersionAndReadinessVerified")
}

// providerPoolNodes gathers the current pool membership and readiness evidence
// without imposing pre-disruption constraints such as an open PDB budget. It is
// used only after the provider operation has completed.
func (r *Reconciler) providerPoolNodes(ctx context.Context, ref protocol.GKENodePoolReference, plan *protocol.ProviderNodeUpgradePlan) ([]corev1.Node, string, error) {
	var all corev1.NodeList
	if err := r.Reader.List(ctx, &all); err != nil {
		return nil, "", err
	}
	nodes := make([]corev1.Node, 0)
	for i := range all.Items {
		node := &all.Items[i]
		if node.Labels["cloud.google.com/gke-nodepool"] != ref.NodePool {
			continue
		}
		if !providerPlanMatchesNode(*plan, ref, node) {
			return nil, "ProviderNodeIdentityUnknown", nil
		}
		ready, err := r.Checker.NodeReady(ctx, node)
		if err != nil {
			return nil, "", err
		}
		if !ready.Allowed {
			return nil, ready.Reason, nil
		}
		nodes = append(nodes, *node)
	}
	if len(nodes) == 0 || len(nodes) > protocol.MaxNodes {
		return nil, "ProviderNodePoolMembershipUnknown", nil
	}
	return nodes, "", nil
}

func (r *Reconciler) waitOrRecoverProvider(ctx context.Context, m *operations.NodeMaintenance, plan *protocol.ProviderNodeUpgradePlan, reason string) error {
	if cp := m.Status.ProviderUpgradeCheckpoint; cp != nil && !cp.IntentAt.IsZero() && r.now().Sub(cp.IntentAt.Time) > plan.Timeout {
		return r.providerRecovery(ctx, m, "PostUpgradeVerificationTimedOut:"+safeProviderReason(reason))
	}
	return nil
}

func providerNodeIdentityDigests(nodes []corev1.Node) ([]string, error) {
	if len(nodes) == 0 || len(nodes) > protocol.MaxNodes {
		return nil, errors.New("provider node set is empty or exceeds bound")
	}
	digests := make([]string, 0, len(nodes))
	seen := make(map[string]struct{}, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.UID == "" || n.Spec.ProviderID == "" || n.Status.NodeInfo.MachineID == "" || n.Status.NodeInfo.BootID == "" {
			return nil, errors.New("provider node host identity is incomplete")
		}
		h := sha256.Sum256([]byte(string(n.UID) + "\n" + n.Spec.ProviderID + "\n" + n.Status.NodeInfo.MachineID + "\n" + n.Status.NodeInfo.BootID))
		digest := hex.EncodeToString(h[:])
		if _, ok := seen[digest]; ok {
			return nil, errors.New("provider node identity is duplicated")
		}
		seen[digest] = struct{}{}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	return digests, nil
}

func (r *Reconciler) authorizeGKEUpdateBoundary(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, ref protocol.GKENodePoolReference, plan *protocol.ProviderNodeUpgradePlan, initial gke.NodePool) (gke.NodePool, error) {
	var currentOperation operations.NodeMaintenance
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: m.Name}, &currentOperation); err != nil {
		return gke.NodePool{}, err
	}
	if currentOperation.UID != m.UID || currentOperation.Status.Sequence != m.Status.Sequence || !currentOperation.DeletionTimestamp.IsZero() {
		return gke.NodePool{}, errors.New("provider operation changed before GKE update boundary")
	}
	if currentOperation.Annotations[protocol.CancellationAnnotation] != "" {
		return gke.NodePool{}, errors.New("provider cancellation arrived before GKE update boundary")
	}
	if !permit.Fresh(r.now()) || !r.connected(ctx, m.Namespace) {
		return gke.NodePool{}, errors.New("authorization or hub connection expired before GKE update boundary")
	}
	var policy operations.MaintenancePolicy
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: permit.Policy.Name}, &policy); err != nil {
		return gke.NodePool{}, err
	}
	if string(policy.UID) != permit.Policy.UID || policy.Generation != permit.Policy.Generation || policy.Spec.Suspended || policy.Spec.ProviderUpgrade == nil {
		return gke.NodePool{}, errors.New("GKE policy changed before provider update")
	}
	digest, err := policy.Spec.ProviderUpgrade.Digest()
	if err != nil || digest != permit.PlanDigest || policy.Spec.ProviderUpgrade.Resource != plan.Resource || policy.Spec.ProviderUpgrade.TargetVersion != plan.TargetVersion {
		return gke.NodePool{}, errors.New("GKE plan changed before provider update")
	}
	if _, reason, err := r.providerPreflight(ctx, ref, plan, &policy); err != nil {
		return gke.NodePool{}, err
	} else if reason != "" {
		return gke.NodePool{}, fmt.Errorf("GKE safety veto at update boundary: %s", reason)
	}
	current, err := r.GKE.GetNodePool(ctx, ref)
	if err != nil {
		return gke.NodePool{}, err
	}
	if current.Version != initial.Version || current.Etag != initial.Etag || current.Status != "RUNNING" || current.Config.ImageType == "" || !gkeUpgradeSettingsMatch(current, plan) {
		return gke.NodePool{}, errors.New("GKE node pool changed before provider update")
	}
	if err = r.ensureNoActiveGKEOperation(ctx, ref); err != nil {
		return gke.NodePool{}, fmt.Errorf("GKE operation safety check failed: %w", err)
	}
	return current, nil
}

func gkeUpgradeSettingsMatch(pool gke.NodePool, plan *protocol.ProviderNodeUpgradePlan) bool {
	if plan == nil || plan.MaxSurge != 1 || plan.MaxUnavailable != 0 {
		return false
	}
	strategy := strings.ToUpper(strings.TrimSpace(pool.UpgradeSettings.Strategy))
	// GKE documents UNSPECIFIED as SURGE. Accept an empty strategy field only
	// when the API returned the exact explicitly pinned disruption bounds.
	return (strategy == "" || strategy == "SURGE" || strategy == "NODE_POOL_UPDATE_STRATEGY_UNSPECIFIED") && pool.UpgradeSettings.MaxSurge == plan.MaxSurge && pool.UpgradeSettings.MaxUnavailable == plan.MaxUnavailable
}

func (r *Reconciler) ensureNoActiveGKEOperation(ctx context.Context, ref protocol.GKENodePoolReference) error {
	items, err := r.GKE.ListOperations(ctx, ref)
	if err != nil {
		return err
	}
	for _, op := range items {
		if gkeOperationTargets(op, ref) && op.Status != "DONE" {
			return errGKEOperationActive
		}
	}
	return nil
}

func (r *Reconciler) verifyProviderWorkloads(ctx context.Context, m *operations.NodeMaintenance, ref protocol.GKENodePoolReference, plan *protocol.ProviderNodeUpgradePlan) error {
	nodes, reason, err := r.providerPoolNodes(ctx, ref, plan)
	if err != nil {
		return err
	}
	if reason != "" {
		return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeWorkloadNodeReadiness:"+reason)
	}
	for i := range nodes {
		if nodes[i].Spec.Unschedulable {
			return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeNodeStillCordoned")
		}
	}
	_, clusterHealth, err := r.Checker.Cluster(ctx, m.Status.TargetNodeName, nil)
	if err != nil {
		return err
	}
	if !clusterHealth.Allowed {
		return r.waitOrRecoverProvider(ctx, m, plan, "PostUpgradeWorkloadHealth:"+clusterHealth.Reason)
	}
	m.Status.ProviderUpgradeCheckpoint.Phase = "Succeeded"
	m.Status.ProviderUpgradeCheckpoint.Sequence++
	m.Status.ProviderUpgradeCheckpoint.UpdatedAt = metav1.NewTime(r.now())
	m.Status.ProviderUpgradeCheckpoint.Reason = "NodePoolAndWorkloadsVerified"
	if err := m.Status.ProviderUpgradeCheckpoint.Validate(); err != nil {
		return r.providerRecovery(ctx, m, "ProviderCheckpointInvalid")
	}
	if m.Status.ProviderUpgradeCheckpoint.CancelRequested {
		m.Status.Outcome = "Cancelled"
		return r.transition(ctx, m, "Cancelled", "GKEUpgradeFinishedAfterCancellation")
	}
	m.Status.Outcome = "Succeeded"
	return r.transition(ctx, m, "Succeeded", "NodePoolAndWorkloadsVerified")
}

func (r *Reconciler) cancelProviderUpgrade(ctx context.Context, m *operations.NodeMaintenance) error {
	cp := m.Status.ProviderUpgradeCheckpoint
	if cp == nil {
		return r.abort(ctx, m, "CancelledByHub", true)
	}
	if cp.Phase == "Succeeded" || cp.Phase == "Cancelled" {
		return nil
	}
	if cp.Phase == "Pending" {
		cp.Phase, cp.Reason = "Cancelled", "CancelledBeforeProviderMutation"
		cp.Sequence++
		cp.UpdatedAt = metav1.NewTime(r.now())
		m.Status.Outcome = "Cancelled"
		return r.transition(ctx, m, "Cancelled", "CancelledBeforeProviderMutation")
	}
	if cp.CancelRequested {
		return nil
	}
	if !cp.CancelRequested {
		cp.CancelRequested = true
		cp.Sequence++
		cp.UpdatedAt = metav1.NewTime(r.now())
		cp.Reason = "CancellationRequested;ProviderOperationMustBeObservedToCompletion"
	}
	if err := cp.Validate(); err != nil {
		return r.providerRecovery(ctx, m, "ProviderCheckpointInvalid")
	}
	return r.checkpoint(ctx, m, cp.Reason, cp.OperationName)
}

func (r *Reconciler) findSubmittedGKEOperation(ctx context.Context, ref protocol.GKENodePoolReference, cp *protocol.ProviderUpgradeCheckpoint) (gke.Operation, bool, error) {
	if cp == nil || cp.IntentAt.IsZero() {
		return gke.Operation{}, false, nil
	}
	var matches []gke.Operation
	items, err := r.GKE.ListOperations(ctx, ref)
	if err != nil {
		return gke.Operation{}, false, err
	}
	for _, op := range items {
		if gkeOperationMatchesSubmissionIntent(op, ref, cp.IntentAt.Time, r.now()) {
			matches = append(matches, op)
		}
	}
	if len(matches) > 1 {
		return gke.Operation{}, false, errMultipleProviderOperations
	}
	if len(matches) == 1 {
		return matches[0], true, nil
	}
	return gke.Operation{}, false, nil
}

func (r *Reconciler) advanceProviderCheckpoint(m *operations.NodeMaintenance, phase, reason string, update func(*protocol.ProviderUpgradeCheckpoint)) error {
	if m.Status.ProviderUpgradeCheckpoint == nil {
		return errors.New("provider checkpoint missing")
	}
	next := *m.Status.ProviderUpgradeCheckpoint
	next.Phase, next.Reason = phase, reason
	next.Sequence++
	next.UpdatedAt = metav1.NewTime(r.now())
	if update != nil {
		update(&next)
	}
	if err := next.Validate(); err != nil {
		return err
	}
	m.Status.ProviderUpgradeCheckpoint = &next
	return nil
}

func (r *Reconciler) providerRecovery(ctx context.Context, m *operations.NodeMaintenance, reason string) error {
	if m == nil {
		return errors.New(reason)
	}
	if cp := m.Status.ProviderUpgradeCheckpoint; cp != nil {
		safeReason := safeProviderReason(reason)
		if cp.Phase != "RecoveryRequired" {
			cp.Phase = "RecoveryRequired"
			cp.Sequence++
			cp.UpdatedAt = metav1.NewTime(r.now())
		} else if cp.Reason != safeReason {
			cp.Sequence++
			cp.UpdatedAt = metav1.NewTime(r.now())
		}
		cp.Reason = safeReason
		m.Status.Outcome = "RecoveryRequired"
		m.Status.FailureReason = cp.Reason
	}
	return r.transition(ctx, m, "RecoveryRequired", safeProviderReason(reason))
}

func providerPlanMatchesNode(plan protocol.ProviderNodeUpgradePlan, ref protocol.GKENodePoolReference, n *corev1.Node) bool {
	return plan.MatchesInventory("gke", ref.Cluster, protocol.Node{Name: n.Name, UID: string(n.UID), ProviderID: n.Spec.ProviderID, Zone: n.Labels["topology.kubernetes.io/zone"], Labels: n.Labels})
}

func gkeOperationTargets(op gke.Operation, ref protocol.GKENodePoolReference) bool {
	if op.Name == "" || op.TargetLink == "" {
		return false
	}
	want := "projects/" + ref.Project + "/locations/" + ref.Location + "/clusters/" + ref.Cluster + "/nodePools/" + ref.NodePool
	if op.TargetLink == want {
		return true
	}
	u, err := url.Parse(op.TargetLink)
	if err != nil || u.Scheme != "https" || u.Host != "container.googleapis.com" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	path := strings.TrimPrefix(u.EscapedPath(), "/v1/")
	return path == want
}

func gkeOperationMatchesSubmissionIntent(op gke.Operation, ref protocol.GKENodePoolReference, intentAt, now time.Time) bool {
	if !gkeOperationTargets(op, ref) || strings.ToUpper(op.OperationType) != "UPGRADE_NODES" || intentAt.IsZero() {
		return false
	}
	started, err := time.Parse(time.RFC3339Nano, op.StartTime)
	if err != nil || started.After(now.Add(gkeSubmissionClockSkew)) {
		return false
	}
	return !started.Before(intentAt.Add(-gkeSubmissionClockSkew)) && !started.After(intentAt.Add(gkeSubmissionWindow))
}

func normalizeVersion(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

func safeProviderReason(reason string) string {
	reason = strings.TrimSpace(strings.ReplaceAll(reason, "\n", " "))
	if reason == "" {
		return "UnknownProviderOutcome"
	}
	if len(reason) > 112 {
		reason = reason[:112]
	}
	return reason
}

var errMultipleProviderOperations = errors.New("multiple GKE operations match submission intent")
var errGKEOperationActive = errors.New("another GKE operation is active for the node pool")

const (
	gkeSubmissionClockSkew = 5 * time.Second
	gkeSubmissionWindow    = 2 * time.Minute
)
