package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/execution"
)

func (r *Reconciler) reconcileUpgradePreflight(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, node *corev1.Node, policy protocol.UpgradePolicy) error {
	request, err := upgradeJobRequest(m, permit, node, policy, execution.EEPhasePreflight)
	if err != nil {
		return r.abort(ctx, m, "UpgradeTargetUnavailable", false)
	}
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint == nil || checkpoint.Phase != protocol.UpgradePreflighting || checkpoint.ExecutionReference != execution.AnsibleJobReference(permit.OperationID, execution.EEPhasePreflight) {
		return r.abort(ctx, m, "UpgradePreflightCheckpointMismatch", false)
	}
	observation, err := r.runUpgradeJob(ctx, m, permit, node, request)
	if err != nil {
		r.cancelPreparedJob(ctx, request, checkpoint.ExecutionReference)
		return r.failUpgradeJob(ctx, m, "Preflight", err)
	}
	switch observation.Phase {
	case "Prepared", "Running":
		return nil
	case "Blocked":
		return nil
	case "RecoveryRequired":
		r.cancelPreparedJob(ctx, request, checkpoint.ExecutionReference)
		return r.failUpgradeJob(ctx, m, "Preflight", errors.New(observation.Reason))
	case "Succeeded":
		if observation.Receipt == nil || observation.Receipt.MachineID == "" || observation.Receipt.BootIDBefore != checkpoint.BootID || observation.Receipt.BootIDAfter != checkpoint.BootID || !protocol.ValidKernelVersion(observation.Receipt.KernelVersion) || observation.Receipt.ExpectedKernelVersion != policy.ExpectedKernelVersion {
			return r.failUpgradeJob(ctx, m, "Preflight", execution.ErrExecutionReceipt)
		}
		evidence, err := upgradeReceiptEvidence(execution.EEPhasePreflight, observation)
		if err != nil {
			return r.failUpgradeJob(ctx, m, "Preflight", err)
		}
		if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeCordoning, "HostIdentityVerified", func(next *protocol.UpgradeCheckpoint) {
			next.MachineID = observation.Receipt.MachineID
			next.ExecutionReference = ""
			next.Receipts = append(next.Receipts, evidence)
		}); err != nil {
			return r.abort(ctx, m, "UpgradeCheckpointTransitionInvalid", false)
		}
		return r.transition(ctx, m, "Cordoning", "HostIdentityVerified")
	default:
		return r.failUpgradeJob(ctx, m, "Preflight", fmt.Errorf("unexpected Ansible preflight phase %q", observation.Phase))
	}
}

func (r *Reconciler) reconcileUpgradeJob(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, node *corev1.Node, policy protocol.UpgradePolicy, phase string) error {
	request, err := upgradeJobRequest(m, permit, node, policy, phase)
	if err != nil {
		return r.failUpgradeJob(ctx, m, phase, err)
	}
	checkpoint := m.Status.UpgradeCheckpoint
	wantPhase, checkpointPhase := "Executing", protocol.UpgradeExecuting
	if phase == execution.EEPhaseReboot {
		wantPhase, checkpointPhase = "Rebooting", protocol.UpgradeRebooting
	}
	if checkpoint == nil || checkpoint.Phase != checkpointPhase || checkpoint.ExecutionReference != execution.AnsibleJobReference(permit.OperationID, phase) {
		return r.abort(ctx, m, "UpgradeExecutionCheckpointMismatch", false)
	}
	if m.Status.Phase != wantPhase {
		return r.abort(ctx, m, "UpgradeExecutionPhaseMismatch", false)
	}
	observation, err := r.runUpgradeJob(ctx, m, permit, node, request)
	if err != nil {
		r.cancelPreparedJob(ctx, request, checkpoint.ExecutionReference)
		return r.failUpgradeJob(ctx, m, phase, err)
	}
	switch observation.Phase {
	case "Prepared", "Running":
		return nil
	case "Blocked":
		return nil
	case "RecoveryRequired":
		r.cancelPreparedJob(ctx, request, checkpoint.ExecutionReference)
		return r.failUpgradeJob(ctx, m, phase, errors.New(observation.Reason))
	case "Succeeded":
		if observation.Receipt == nil {
			return r.failUpgradeJob(ctx, m, phase, execution.ErrExecutionReceipt)
		}
		if phase == execution.EEPhaseApply {
			if observation.Receipt.Rebooted || observation.Receipt.BootIDBefore != checkpoint.BootID {
				return r.failUpgradeJob(ctx, m, phase, execution.ErrExecutionReceipt)
			}
			if !observation.Receipt.RebootRequired && policy.ExpectedKernelVersion != "" && observation.Receipt.KernelVersion != policy.ExpectedKernelVersion {
				return r.failUpgradeJob(ctx, m, phase, execution.ErrExecutionReceipt)
			}
			if observation.Receipt.RebootRequired {
				evidence, evidenceErr := upgradeReceiptEvidence(execution.EEPhaseApply, observation)
				if evidenceErr != nil {
					return r.failUpgradeJob(ctx, m, phase, evidenceErr)
				}
				jobName := execution.AnsibleJobReference(permit.OperationID, execution.EEPhaseReboot)
				if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeRebooting, "PackageVersionsVerified", func(next *protocol.UpgradeCheckpoint) {
					next.Outcome = "PackagesVerified"
					next.RebootRequested = true
					next.ExecutionReference = jobName
					next.Receipts = append(next.Receipts, evidence)
				}); err != nil {
					return r.failUpgradeJob(ctx, m, phase, fmt.Errorf("advance reboot checkpoint: %w", err))
				}
				return r.transition(ctx, m, "Rebooting", "PackageVersionsVerified")
			}
			evidence, evidenceErr := upgradeReceiptEvidence(execution.EEPhaseApply, observation)
			if evidenceErr != nil {
				return r.failUpgradeJob(ctx, m, phase, evidenceErr)
			}
			if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeVerifyingNode, "PackageVersionsVerified", func(next *protocol.UpgradeCheckpoint) {
				next.Outcome = "PackagesVerified"
				next.ExecutionReference = ""
				next.Receipts = append(next.Receipts, evidence)
			}); err != nil {
				return r.failUpgradeJob(ctx, m, phase, fmt.Errorf("advance verification checkpoint: %w", err))
			}
			m.Status.Outcome = "Succeeded"
			return r.transition(ctx, m, "VerifyingNode", "PackageVersionsVerified")
		}
		if !observation.Receipt.Rebooted || observation.Receipt.MachineID != checkpoint.MachineID || observation.Receipt.BootIDBefore != checkpoint.BootID || observation.Receipt.BootIDAfter == checkpoint.BootID || policy.ExpectedKernelVersion != "" && observation.Receipt.KernelVersion != policy.ExpectedKernelVersion {
			return r.failUpgradeJob(ctx, m, phase, execution.ErrExecutionReceipt)
		}
		evidence, evidenceErr := upgradeReceiptEvidence(execution.EEPhaseReboot, observation)
		if evidenceErr != nil {
			return r.failUpgradeJob(ctx, m, phase, evidenceErr)
		}
		newBootID := observation.Receipt.BootIDAfter
		if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeVerifyingNode, "RebootAndHostIdentityVerified", func(next *protocol.UpgradeCheckpoint) {
			next.BootID = newBootID
			next.Outcome = "PackagesAndRebootVerified"
			next.ExecutionReference = ""
			next.Receipts = append(next.Receipts, evidence)
		}); err != nil {
			return r.failUpgradeJob(ctx, m, phase, fmt.Errorf("advance post-reboot verification checkpoint: %w", err))
		}
		m.Status.Outcome = "Succeeded"
		return r.transition(ctx, m, "VerifyingNode", "RebootAndHostIdentityVerified")
	default:
		return r.failUpgradeJob(ctx, m, phase, fmt.Errorf("unexpected Ansible execution phase %q", observation.Phase))
	}
}

func upgradeReceiptEvidence(phase string, observation execution.AnsibleJobObservation) (protocol.UpgradeReceiptEvidence, error) {
	if observation.Receipt == nil || observation.ReceiptReference == "" || !protocol.ValidSHA256Digest(observation.ReceiptDigest) {
		return protocol.UpgradeReceiptEvidence{}, execution.ErrExecutionReceipt
	}
	receipt := observation.Receipt
	packages := make(map[string]string, len(receipt.Packages))
	for name, version := range receipt.Packages {
		packages[name] = version
	}
	var marker *protocol.ActionMarkerEvidence
	if receipt.ActionMarker != nil {
		copy := *receipt.ActionMarker
		marker = &copy
	}
	return protocol.UpgradeReceiptEvidence{
		Phase: phase, Reference: observation.ReceiptReference, Digest: observation.ReceiptDigest,
		MachineID: receipt.MachineID, BootIDBefore: receipt.BootIDBefore, BootIDAfter: receipt.BootIDAfter,
		KernelVersion: receipt.KernelVersion, ExpectedKernelVersion: receipt.ExpectedKernelVersion,
		Rebooted: receipt.Rebooted, RebootRequired: receipt.RebootRequired, Packages: packages, ActionMarker: marker,
		CompletedAt: metav1.NewTime(receipt.CompletedAt),
	}, nil
}

func (r *Reconciler) runUpgradeJob(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, node *corev1.Node, request execution.AnsibleJobRequest) (execution.AnsibleJobObservation, error) {
	if r.Upgrader == nil {
		return execution.AnsibleJobObservation{}, errors.New("upgrade executor unavailable")
	}
	name, err := r.Upgrader.Ensure(ctx, request)
	if err != nil {
		return execution.AnsibleJobObservation{}, err
	}
	if name != m.Status.UpgradeCheckpoint.ExecutionReference {
		return execution.AnsibleJobObservation{}, execution.ErrExecutionIdentity
	}
	observation, err := r.Upgrader.Observe(ctx, request, name)
	if err != nil {
		return observation, err
	}
	if observation.Phase != "Prepared" {
		return observation, nil
	}
	// The local operator checks the hub lease, policy, node identity, cordon
	// ownership, health and permit immediately before activating every Job.
	boundary := "Preflighting"
	if request.Phase == execution.EEPhaseApply {
		boundary = "Executing"
	} else if request.Phase == execution.EEPhaseReboot {
		boundary = "Rebooting"
	}
	fresh, err := r.authorizeBoundary(ctx, m, permit, boundary)
	if err != nil {
		r.cancelPreparedJob(ctx, request, name)
		return observation, err
	}
	if fresh == nil {
		// authorizeBoundary persisted a Blocked state. Keep this deterministic
		// suspended Job so the same operation can resume after safety returns.
		observation.Phase = "Blocked"
		observation.Reason = m.Status.Reason
		return observation, nil
	}
	if err = r.Upgrader.Start(ctx, request, name); err != nil {
		return observation, err
	}
	observation.Phase = "Running"
	return observation, nil
}

func (r *Reconciler) cancelPreparedJob(ctx context.Context, request execution.AnsibleJobRequest, reference string) {
	if r.Upgrader == nil || reference == "" {
		return
	}
	if err := r.Upgrader.Cancel(ctx, request, reference); err != nil && r.Logger != nil {
		r.Logger.ErrorContext(ctx, "failed to cancel interrupted Ansible Job", "operation_id", request.OperationID, "phase", request.Phase, "error", err.Error())
	}
}

func (r *Reconciler) failUpgradeJob(ctx context.Context, m *operations.NodeMaintenance, phase string, cause error) error {
	reason := "UpgradeExecutionAmbiguous"
	if classified := classifiedUpgradeFailure(cause); classified != "" {
		reason = classified
	} else if phase == "Preflight" || phase == execution.EEPhasePreflight {
		reason = "UpgradePreflightFailed"
	} else if cause != nil {
		reason = "UpgradeExecutionAmbiguous"
	}
	if m.Status.UpgradeCheckpoint != nil && (m.Status.UpgradeCheckpoint.Phase == protocol.UpgradePreflighting || m.Status.UpgradeCheckpoint.Phase == protocol.UpgradePending) {
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeFailed, reason, func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Failed"
			next.Reason = reason
		}); err != nil {
			return err
		}
	}
	if m.Status.UpgradeCheckpoint != nil && (m.Status.UpgradeCheckpoint.Phase == protocol.UpgradeExecuting || m.Status.UpgradeCheckpoint.Phase == protocol.UpgradeRebooting) {
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, reason, func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Ambiguous"
			next.Reason = reason
			next.InterruptedPhase = phase
		}); err != nil {
			return err
		}
	}
	m.Status.Outcome = "Failed"
	m.Status.FailureReason = reason
	return r.abort(ctx, m, reason, false)
}

func classifiedUpgradeFailure(cause error) string {
	if cause == nil {
		return ""
	}
	switch cause.Error() {
	case "SSHHostKeyVerificationFailed":
		return "UpgradeSSHHostKeyVerificationFailed"
	case "SSHAuthenticationFailed":
		return "UpgradeSSHAuthenticationFailed"
	case "SSHTransportUnavailable":
		return "UpgradeSSHTransportUnavailable"
	case "ExecutionTimedOutAmbiguous":
		return "UpgradeExecutionTimedOutAmbiguous"
	default:
		return ""
	}
}

func recoveryInspectionFailureReason(reason string) string {
	switch reason {
	case "SSHHostKeyVerificationFailed":
		return "UpgradeRecoverySSHHostKeyVerificationFailed"
	case "SSHAuthenticationFailed":
		return "UpgradeRecoverySSHAuthenticationFailed"
	case "SSHTransportUnavailable":
		return "UpgradeRecoverySSHTransportUnavailable"
	default:
		return "UpgradeRecoveryInspectionAmbiguous"
	}
}

func retryableRecoveryInspectionReason(reason string) bool {
	switch reason {
	case "UpgradeRecoverySSHHostKeyVerificationFailed", "UpgradeRecoverySSHAuthenticationFailed":
		return true
	default:
		return false
	}
}

const recoveryRetryAnnotation = "operations.kordex.local/recovery-retry"

func (r *Reconciler) checkpointCancelledDrain(m *operations.NodeMaintenance) error {
	checkpoint := m.Status.UpgradeCheckpoint
	// No mutating Job has been authorized at this boundary.
	if checkpoint.ExecutionReference != "" || checkpoint.InterruptedPhase != "" || checkpoint.RebootRequested {
		return errors.New("drain cancellation has unexpected execution evidence")
	}
	for _, receipt := range checkpoint.Receipts {
		if receipt.Phase != execution.EEPhasePreflight {
			return errors.New("drain cancellation has mutating receipt evidence")
		}
	}
	return r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "DrainCancelledBeforeApply", func(next *protocol.UpgradeCheckpoint) {
		next.Outcome = "CancelledBeforeApply"
	})
}

func (r *Reconciler) interruptUpgrade(ctx context.Context, m *operations.NodeMaintenance, permit protocol.MaintenancePermit, node *corev1.Node, policy protocol.UpgradePolicy, reason string) error {
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint == nil {
		return r.abort(ctx, m, reason, true)
	}
	phase := ""
	switch checkpoint.Phase {
	case protocol.UpgradePreflighting:
		phase = execution.EEPhasePreflight
	case protocol.UpgradeExecuting:
		phase = execution.EEPhaseApply
	case protocol.UpgradeRebooting:
		phase = execution.EEPhaseReboot
	}
	if phase != "" && r.Upgrader != nil {
		request, err := upgradeJobRequest(m, permit, node, policy, phase)
		if err == nil && checkpoint.ExecutionReference == execution.AnsibleJobReference(permit.OperationID, phase) {
			// A completed immutable receipt is authoritative even if the hub's
			// withdrawal raced with status delivery. Consume that evidence before
			// requesting cancellation; never start the next mutating phase here.
			observation, observeErr := r.Upgrader.Observe(ctx, request, checkpoint.ExecutionReference)
			if observeErr == nil && observation.Phase == "Succeeded" && observation.Receipt != nil {
				if receiptErr := r.acceptInterruptedUpgradeReceipt(ctx, m, phase, observation, policy, reason); receiptErr == nil {
					return nil
				} else if r.Logger != nil {
					r.Logger.ErrorContext(ctx, "completed upgrade receipt could not be committed; outcome remains fenced", "operation_id", permit.OperationID, "phase", phase, "error", receiptErr.Error())
				}
			}
			if err = r.Upgrader.Cancel(ctx, request, checkpoint.ExecutionReference); err != nil && r.Logger != nil {
				r.Logger.ErrorContext(ctx, "failed to cancel Ansible maintenance Job; outcome remains fenced", "operation_id", permit.OperationID, "phase", phase, "error", err.Error())
			}
		}
	}
	if checkpoint.Phase == protocol.UpgradeDraining {
		if err := r.checkpointCancelledDrain(m); err != nil {
			return err
		}
	} else if checkpoint.Phase == protocol.UpgradeExecuting || checkpoint.Phase == protocol.UpgradeRebooting {
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "UpgradeInterruptedAmbiguous", func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Ambiguous"
			next.Reason = reason
			next.InterruptedPhase = phase
		}); err != nil {
			return err
		}
	} else if checkpoint.Phase == protocol.UpgradePreflighting {
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeFailed, "UpgradePreflightInterrupted", func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Failed"
			next.Reason = reason
		}); err != nil {
			return err
		}
	}
	return r.abort(ctx, m, reason, true)
}

// acceptInterruptedUpgradeReceipt advances only from a cryptographically and
// structurally validated executor receipt. It deliberately does not authorize
// another package or reboot job after cancellation.
func (r *Reconciler) acceptInterruptedUpgradeReceipt(ctx context.Context, m *operations.NodeMaintenance, phase string, observation execution.AnsibleJobObservation, policy protocol.UpgradePolicy, cancelReason string) error {
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint == nil || observation.Receipt == nil {
		return execution.ErrExecutionReceipt
	}
	evidence, err := upgradeReceiptEvidence(phase, observation)
	if err != nil {
		return err
	}
	receipt := observation.Receipt
	if receipt.MachineID != checkpoint.MachineID && checkpoint.MachineID != "" || !protocol.ValidKernelVersion(receipt.KernelVersion) || receipt.ExpectedKernelVersion != policy.ExpectedKernelVersion {
		return execution.ErrExecutionReceipt
	}
	bootID := checkpoint.BootID
	outcome := "CancelledAfterVerifiedExecution"
	reason := "CancellationAfterVerifiedExecution"
	if phase == execution.EEPhaseApply {
		if receipt.BootIDBefore != checkpoint.BootID || receipt.BootIDAfter != checkpoint.BootID || receipt.Rebooted {
			return execution.ErrExecutionReceipt
		}
		if receipt.RebootRequired {
			// Cancellation withdraws the separately checkpointed reboot. Keep
			// the node cordoned because the new package state requires a reboot.
			if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "UpgradeRebootRequiredAfterCancellation", func(next *protocol.UpgradeCheckpoint) {
				next.MachineID = receipt.MachineID
				next.InterruptedPhase = execution.EEPhaseApply
				next.Outcome = "CancelledWithRebootDeferred"
				next.Reason = "UpgradeRebootRequiredAfterCancellation"
				next.Receipts = append(next.Receipts, evidence)
			}); err != nil {
				return err
			}
			m.Status.Outcome = "Cancelled"
			m.Status.FailureReason = cancelReason
			return r.transition(ctx, m, "RecoveryRequired", "UpgradeRebootRequiredAfterCancellation")
		}
		if policy.ExpectedKernelVersion != "" && receipt.KernelVersion != policy.ExpectedKernelVersion {
			return execution.ErrExecutionReceipt
		}
	} else if phase == execution.EEPhaseReboot {
		if !receipt.Rebooted || !receipt.RebootRequired || receipt.BootIDBefore != checkpoint.BootID || receipt.BootIDAfter == checkpoint.BootID || policy.ExpectedKernelVersion != "" && receipt.KernelVersion != policy.ExpectedKernelVersion {
			return execution.ErrExecutionReceipt
		}
		bootID = receipt.BootIDAfter
	} else {
		return execution.ErrExecutionReceipt
	}
	if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeVerifyingNode, reason, func(next *protocol.UpgradeCheckpoint) {
		next.MachineID = receipt.MachineID
		next.BootID = bootID
		next.ExecutionReference = ""
		next.Outcome = outcome
		next.Reason = reason
		next.Receipts = append(next.Receipts, evidence)
	}); err != nil {
		return err
	}
	m.Status.Outcome = "Cancelled"
	m.Status.FailureReason = cancelReason
	return r.transition(ctx, m, "VerifyingNode", reason)
}

func (r *Reconciler) interruptUnresolvedUpgrade(ctx context.Context, m *operations.NodeMaintenance, reason string) error {
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint != nil && (checkpoint.Phase == protocol.UpgradeExecuting || checkpoint.Phase == protocol.UpgradeRebooting) {
		interrupted := execution.EEPhaseApply
		if checkpoint.Phase == protocol.UpgradeRebooting {
			interrupted = execution.EEPhaseReboot
		}
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "UpgradeInterruptedAmbiguous", func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Ambiguous"
			next.Reason = reason
			next.InterruptedPhase = interrupted
		}); err != nil {
			return err
		}
	} else if checkpoint != nil && checkpoint.Phase == protocol.UpgradePreflighting {
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeFailed, "UpgradePreflightInterrupted", func(next *protocol.UpgradeCheckpoint) {
			next.Outcome = "Failed"
			next.Reason = reason
		}); err != nil {
			return err
		}
	}
	return r.abort(ctx, m, reason, true)
}

// reconcileAmbiguousUpgrade performs a fixed, read-only host inspection. It
// can resolve only exact package pins and stable machine identity; it never
// retries package mutation or reboot. Any mismatch remains intervention-only.
func (r *Reconciler) reconcileAmbiguousUpgrade(ctx context.Context, m *operations.NodeMaintenance, node *corev1.Node) error {
	checkpoint := m.Status.UpgradeCheckpoint
	if checkpoint == nil || r.Upgrader == nil {
		return r.recoveryWait(ctx, m, "UpgradeOutcomeAmbiguous")
	}
	if checkpoint.Outcome == "RecoveredWithRebootPending" || checkpoint.Outcome == "RebootNotObserved" || checkpoint.Outcome == "KernelVersionMismatch" {
		return r.recoveryWait(ctx, m, "UpgradeRebootRequiresOperatorIntervention")
	}
	if checkpoint.Phase == protocol.UpgradeExecuting || checkpoint.Phase == protocol.UpgradeRebooting {
		interrupted := execution.EEPhaseApply
		if checkpoint.Phase == protocol.UpgradeRebooting {
			interrupted = execution.EEPhaseReboot
		}
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "UpgradeInterruptedAmbiguous", func(next *protocol.UpgradeCheckpoint) {
			next.InterruptedPhase = interrupted
			next.Outcome = "Ambiguous"
		}); err != nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryCheckpointInvalid")
		}
		return r.transition(ctx, m, "RecoveryRequired", "UpgradeInterruptedAmbiguous")
	}
	if checkpoint.Phase != protocol.UpgradeRecoveryRequired {
		return r.recoveryWait(ctx, m, "UpgradeOutcomeAmbiguous")
	}
	var permit protocol.MaintenancePermit
	if json.Unmarshal([]byte(m.Spec.Authorization), &permit) != nil || permit.Action != protocol.UpgradePackages || permit.OperationID != m.Status.OperationID || permit.NodeName != m.Status.TargetNodeName || permit.NodeUID != m.Status.TargetNodeUID || permit.PlanDigest != checkpoint.PlanDigest {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryAuthorizationUnavailable")
	}
	var policy operations.MaintenancePolicy
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: m.Namespace, Name: permit.Policy.Name}, &policy); err != nil {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryPolicyUnavailable")
	}
	if string(policy.UID) != permit.Policy.UID || policy.Generation != permit.Policy.Generation || policy.Spec.Upgrade == nil {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryPolicyChanged")
	}
	digest, err := policy.Spec.Upgrade.Digest()
	if err != nil || digest != checkpoint.PlanDigest {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryPlanMismatch")
	}
	interrupted := checkpoint.InterruptedPhase
	if interrupted == "" {
		switch {
		case strings.HasSuffix(checkpoint.ExecutionReference, "-reboot"):
			interrupted = execution.EEPhaseReboot
		case strings.HasSuffix(checkpoint.ExecutionReference, "-apply"):
			interrupted = execution.EEPhaseApply
		default:
			return r.recoveryWait(ctx, m, "UpgradeInterruptedPhaseUnknown")
		}
	}
	if interrupted != execution.EEPhaseApply && interrupted != execution.EEPhaseReboot {
		return r.recoveryWait(ctx, m, "UpgradeInterruptedPhaseUnknown")
	}
	request, err := upgradeJobRequest(m, permit, node, *policy.Spec.Upgrade, execution.EEPhaseInspect)
	if err != nil {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionUnavailable")
	}
	trustDigest, err := r.Upgrader.RecoveryTrustDigest(ctx)
	if err != nil || !protocol.ValidSHA256Digest(trustDigest) {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryTrustUnavailable")
	}
	checkpoint = m.Status.UpgradeCheckpoint
	if checkpoint.RecoveryReference == "" {
		if node.Annotations[execution.OwnerAnnotation] != string(m.UID) || !node.Spec.Unschedulable {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryCordonOwnershipChanged")
		}
		request.RecoveryAttempt = 1
		request.RecoveryTrustDigest = trustDigest
		wantReference := execution.AnsibleInspectionAttemptReference(permit.OperationID, trustDigest, 1)
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "RecoveryInspectionIntentPersisted", func(next *protocol.UpgradeCheckpoint) {
			next.InterruptedPhase = interrupted
			next.RecoveryReference = wantReference
			next.RecoveryAttempt = 1
			next.RecoveryTrustDigest = trustDigest
		}); err != nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryCheckpointInvalid")
		}
		return r.transition(ctx, m, "RecoveryRequired", "UpgradeRecoveryInspectionPrepared")
	}
	transportRetryToken := m.Annotations[recoveryRetryAnnotation]
	trustRetry := trustDigest != checkpoint.RecoveryTrustDigest && retryableRecoveryInspectionReason(m.Status.Reason)
	transportRetry := trustDigest == checkpoint.RecoveryTrustDigest && m.Status.Reason == "UpgradeRecoverySSHTransportUnavailable" && protocol.ValidUUID(transportRetryToken) && transportRetryToken != checkpoint.RecoveryRetryToken
	if trustRetry || transportRetry {
		if checkpoint.RecoveryAttempt >= 100 {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionRetryLimit")
		}
		request.RecoveryAttempt = checkpoint.RecoveryAttempt + 1
		request.RecoveryTrustDigest = trustDigest
		request.RecoveryRetryToken = checkpoint.RecoveryRetryToken
		if transportRetry {
			request.RecoveryRetryToken = transportRetryToken
		}
		wantReference := execution.AnsibleInspectionAttemptReference(permit.OperationID, trustDigest, request.RecoveryAttempt)
		if wantReference == "" {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionUnavailable")
		}
		if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, "RecoveryTrustUpdatedInspectionIntentPersisted", func(next *protocol.UpgradeCheckpoint) {
			next.RecoveryReference = wantReference
			next.RecoveryAttempt = request.RecoveryAttempt
			next.RecoveryTrustDigest = trustDigest
			next.RecoveryRetryToken = request.RecoveryRetryToken
		}); err != nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryCheckpointInvalid")
		}
		return r.transition(ctx, m, "RecoveryRequired", "UpgradeRecoveryInspectionRetryPrepared")
	}
	request.RecoveryAttempt = checkpoint.RecoveryAttempt
	request.RecoveryTrustDigest = checkpoint.RecoveryTrustDigest
	request.RecoveryRetryToken = checkpoint.RecoveryRetryToken
	wantReference := execution.AnsibleInspectionAttemptReference(permit.OperationID, checkpoint.RecoveryTrustDigest, checkpoint.RecoveryAttempt)
	if checkpoint.RecoveryReference != wantReference || node.Annotations[execution.OwnerAnnotation] != string(m.UID) || !node.Spec.Unschedulable {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryIdentityMismatch")
	}
	name, err := r.Upgrader.Ensure(ctx, request)
	if err != nil || name != wantReference {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionUnavailable")
	}
	observation, err := r.Upgrader.Observe(ctx, request, name)
	if err != nil {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionUnavailable")
	}
	switch observation.Phase {
	case "Prepared":
		if err := r.Upgrader.Start(ctx, request, name); err != nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionUnavailable")
		}
		return r.transition(ctx, m, "RecoveryRequired", "UpgradeRecoveryInspectionRunning")
	case "Running":
		return nil
	case "RecoveryRequired":
		return r.recoveryWait(ctx, m, recoveryInspectionFailureReason(observation.Reason))
	case "Succeeded":
		if observation.Receipt == nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryReceiptUnavailable")
		}
		receipt := observation.Receipt
		if !validRecoveryInspectionReceipt(receipt, permit, *policy.Spec.Upgrade, checkpoint) {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryPackageEvidenceMismatch")
		}
		evidence, err := upgradeReceiptEvidence(execution.EEPhaseInspect, observation)
		if err != nil || receipt.MachineID != checkpoint.MachineID || receipt.BootIDBefore != receipt.BootIDAfter || receipt.Rebooted || node.Status.NodeInfo.BootID != receipt.BootIDAfter {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryHostEvidenceMismatch")
		}
		if outcome, reason := ambiguousInspectionIntervention(interrupted, receipt, checkpoint, policy.Spec.Upgrade.ExpectedKernelVersion); outcome != "" {
			return r.retainAmbiguousUpgradeForIntervention(ctx, m, evidence, outcome, reason)
		}
		outcome := "RecoveredByReadOnlyInspection"
		reason := "UpgradeRecoveryInspectionVerified"
		if receipt.RebootRequired && receipt.BootIDAfter == checkpoint.BootID {
			outcome = "RecoveredWithRebootPending"
			reason = "UpgradeRecoveryRebootStillRequired"
		}
		if m.Status.Outcome == "" {
			m.Status.Outcome = "Failed"
		}
		if m.Status.FailureReason == "" {
			m.Status.FailureReason = "UpgradeExecutionOutcomeWasAmbiguous"
		}
		if err = r.advanceUpgradeCheckpointState(m, protocol.UpgradeVerifyingNode, reason, func(next *protocol.UpgradeCheckpoint) {
			next.MachineID = receipt.MachineID
			next.BootID = receipt.BootIDAfter
			next.Outcome = outcome
			next.Reason = reason
			next.Receipts = append(next.Receipts, evidence)
		}); err != nil {
			return r.recoveryWait(ctx, m, "UpgradeRecoveryCheckpointInvalid")
		}
		return r.transition(ctx, m, "VerifyingNode", reason)
	default:
		return r.recoveryWait(ctx, m, "UpgradeRecoveryInspectionAmbiguous")
	}
}

func (r *Reconciler) retainAmbiguousUpgradeForIntervention(ctx context.Context, m *operations.NodeMaintenance, evidence protocol.UpgradeReceiptEvidence, outcome, reason string) error {
	if err := r.advanceUpgradeCheckpointState(m, protocol.UpgradeRecoveryRequired, reason, func(next *protocol.UpgradeCheckpoint) {
		next.Outcome = outcome
		next.Reason = reason
		next.Receipts = append(next.Receipts, evidence)
	}); err != nil {
		return r.recoveryWait(ctx, m, "UpgradeRecoveryCheckpointInvalid")
	}
	if m.Status.Outcome == "" {
		m.Status.Outcome = "Failed"
	}
	if m.Status.FailureReason == "" {
		m.Status.FailureReason = reason
	}
	return r.transition(ctx, m, "RecoveryRequired", reason)
}

func validRecoveryInspectionReceipt(receipt *execution.AnsibleReceipt, permit protocol.MaintenancePermit, policy protocol.UpgradePolicy, checkpoint *protocol.UpgradeCheckpoint) bool {
	if receipt == nil || checkpoint == nil || receipt.OperationID != permit.OperationID || receipt.PlanDigest != permit.PlanDigest || receipt.NodeUID != permit.NodeUID || receipt.OSFamily != policy.OSFamily || receipt.MachineID != checkpoint.MachineID || receipt.CompletedAt.IsZero() || !protocol.ValidUUID(receipt.BootIDBefore) || !protocol.ValidUUID(receipt.BootIDAfter) || receipt.BootIDBefore != receipt.BootIDAfter || receipt.Rebooted || !protocol.ValidKernelVersion(receipt.KernelVersion) || receipt.ExpectedKernelVersion != policy.ExpectedKernelVersion || len(receipt.Packages) != len(policy.Packages) || policy.Reboot == protocol.RebootNever && receipt.RebootRequired {
		return false
	}
	for _, pin := range policy.Packages {
		if receipt.Packages[pin.Name] != pin.Version {
			return false
		}
	}
	if policy.ActionMarkerVersion == 1 {
		marker := receipt.ActionMarker
		if marker == nil || marker.Validate() != nil || marker.OperationID != permit.OperationID || marker.ActionDigest != permit.PlanDigest || marker.NodeUID != permit.NodeUID || marker.MachineID != checkpoint.MachineID {
			return false
		}
		switch checkpoint.InterruptedPhase {
		case execution.EEPhaseApply:
			if marker.Phase != "apply-intent" && marker.Phase != "packages-verified" {
				return false
			}
			if marker.BootID != checkpoint.BootID || receipt.BootIDAfter != checkpoint.BootID {
				return false
			}
		case execution.EEPhaseReboot:
			if marker.Phase != "reboot-intent" && marker.Phase != "reboot-verified" {
				return false
			}
			if marker.Phase == "reboot-intent" && marker.BootID != checkpoint.BootID || marker.Phase == "reboot-verified" && marker.BootID != receipt.BootIDAfter {
				return false
			}
		default:
			return false
		}
	} else if receipt.ActionMarker != nil {
		return false
	}
	return true
}

// ambiguousInspectionIntervention prevents recovery when a read-only inspection
// finds that a reboot is still pending, even if a reboot phase changed boot ID.
func ambiguousInspectionIntervention(interrupted string, receipt *execution.AnsibleReceipt, checkpoint *protocol.UpgradeCheckpoint, expectedKernel string) (string, string) {
	if receipt == nil || checkpoint == nil {
		return "UpgradeOutcomeAmbiguous", "UpgradeRecoveryInspectionUnavailable"
	}
	if interrupted == execution.EEPhaseApply && receipt.BootIDAfter != checkpoint.BootID {
		return "UpgradeOutcomeAmbiguous", "UpgradeRecoveryUnexpectedReboot"
	}
	if interrupted == execution.EEPhaseReboot && receipt.BootIDAfter == checkpoint.BootID {
		return "RebootNotObserved", "UpgradeRebootNotObserved"
	}
	if interrupted != execution.EEPhaseApply && interrupted != execution.EEPhaseReboot {
		return "UpgradeOutcomeAmbiguous", "UpgradeInterruptedPhaseUnknown"
	}
	if receipt.RebootRequired {
		return "RecoveredWithRebootPending", "UpgradeRecoveryRebootStillRequired"
	}
	if expectedKernel != "" && receipt.KernelVersion != expectedKernel {
		return "KernelVersionMismatch", "UpgradeRecoveryKernelMismatch"
	}
	return "", ""
}

func upgradeJobRequest(m *operations.NodeMaintenance, permit protocol.MaintenancePermit, node *corev1.Node, policy protocol.UpgradePolicy, phase string) (execution.AnsibleJobRequest, error) {
	address := ""
	for _, candidate := range node.Status.Addresses {
		if candidate.Type == corev1.NodeInternalIP {
			address = candidate.Address
			break
		}
	}
	digest, err := policy.Digest()
	if err != nil || digest != permit.PlanDigest || address == "" {
		return execution.AnsibleJobRequest{}, errors.New("upgrade plan or node internal address unavailable")
	}
	request := execution.AnsibleJobRequest{
		OperationID: permit.OperationID,
		OwnerName:   m.Name,
		OwnerUID:    m.UID,
		NodeName:    permit.NodeName,
		NodeUID:     permit.NodeUID,
		Address:     address,
		PlanDigest:  permit.PlanDigest,
		Phase:       phase,
		Policy:      policy,
	}
	if phase == execution.EEPhaseReboot {
		checkpoint := m.Status.UpgradeCheckpoint
		request.RebootAuthorized = checkpoint != nil && checkpoint.PlanDigest == permit.PlanDigest && checkpoint.NodeUID == permit.NodeUID && checkpoint.Phase == protocol.UpgradeRebooting && checkpoint.Outcome == "PackagesVerified" && checkpoint.RebootRequested && verifiedApplyReceipt(checkpoint, permit.OperationID, policy)
		if !request.RebootAuthorized {
			return execution.AnsibleJobRequest{}, errors.New("reboot requires a verified package receipt bound to this signed plan and node")
		}
	}
	if phase != execution.EEPhasePreflight {
		if m.Status.UpgradeCheckpoint == nil {
			return execution.AnsibleJobRequest{}, errors.New("upgrade checkpoint unavailable")
		}
		request.MachineID = m.Status.UpgradeCheckpoint.MachineID
		request.BootID = m.Status.UpgradeCheckpoint.BootID
	}
	return request, nil
}

func hasVerifiedApplyReceipt(checkpoint *protocol.UpgradeCheckpoint) bool {
	if checkpoint == nil || checkpoint.MachineID == "" || checkpoint.BootID == "" || protocol.ValidateUpgradeCheckpoint(*checkpoint) != nil {
		return false
	}
	for _, receipt := range checkpoint.Receipts {
		if receipt.Phase == execution.EEPhaseApply && protocol.ValidSHA256Digest(receipt.Digest) && receipt.MachineID == checkpoint.MachineID && receipt.BootIDBefore == checkpoint.BootID && receipt.BootIDAfter == checkpoint.BootID && !receipt.Rebooted && receipt.RebootRequired && len(receipt.Packages) > 0 {
			return true
		}
	}
	return false
}

func verifiedApplyReceipt(checkpoint *protocol.UpgradeCheckpoint, operationID string, policy protocol.UpgradePolicy) bool {
	if !hasVerifiedApplyReceipt(checkpoint) {
		return false
	}
	for _, receipt := range checkpoint.Receipts {
		if receipt.Phase != execution.EEPhaseApply {
			continue
		}
		if receipt.ExpectedKernelVersion != policy.ExpectedKernelVersion || len(receipt.Packages) != len(policy.Packages) {
			return false
		}
		if policy.ActionMarkerVersion == 1 {
			marker := receipt.ActionMarker
			if marker == nil || marker.Validate() != nil || marker.OperationID != operationID || marker.ActionDigest != checkpoint.PlanDigest || marker.NodeUID != checkpoint.NodeUID || marker.MachineID != checkpoint.MachineID || marker.BootID != checkpoint.BootID || marker.Phase != "packages-verified" || marker.Sequence != 2 {
				return false
			}
		} else if receipt.ActionMarker != nil {
			return false
		}
		for _, pin := range policy.Packages {
			if receipt.Packages[pin.Name] != pin.Version {
				return false
			}
		}
		return true
	}
	return false
}
