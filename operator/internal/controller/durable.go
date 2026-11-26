package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
	"kordex.local/operator/internal/observability"
)

var ErrDuplicateOperation = errors.New("operation ID previously accepted by a different resource")

const Finalizer = protocol.OperationFinalizer

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}
func (r *Reconciler) transition(ctx context.Context, m *operations.NodeMaintenance, phase, reason string) error {
	return r.persist(ctx, m, phase, reason, "", false)
}
func (r *Reconciler) checkpoint(ctx context.Context, m *operations.NodeMaintenance, reason, resourceUID string) error {
	return r.persist(ctx, m, m.Status.Phase, reason, resourceUID, true)
}
func (r *Reconciler) persist(ctx context.Context, m *operations.NodeMaintenance, phase, reason, resourceUID string, force bool) error {
	previousPhase := m.Status.Phase
	previousReason := m.Status.Reason
	if len(m.Status.Events) >= 240 && phase != "RecoveryRequired" && !protocol.TerminalPhase(phase) && phase != "Uncordoning" {
		m.Status.Outcome = "Failed"
		m.Status.FailureReason = "AuditCapacityReached"
		phase = "RecoveryRequired"
		reason = "AuditCapacityReached"
		if m.Status.OriginalUnschedulable == nil {
			phase = "Failed"
		}
	}
	// Once the audit journal reaches its recovery threshold, preserve one
	// explicit capacity blocker instead of appending a new event for every
	// changing recovery diagnostic. Otherwise a long-lived RecoveryRequired
	// operation can exceed OperationReport's 256-event contract and become
	// impossible for the hub to acknowledge. Forced checkpoints still need to
	// persist their structured checkpoint even when the phase journal is frozen.
	if len(m.Status.Events) >= 240 && phase == "RecoveryRequired" {
		reason = "AuditCapacityReached"
	}
	if len(m.Status.Events) > 0 {
		last := m.Status.Events[len(m.Status.Events)-1]
		if last.Sequence != m.Status.Sequence || last.Phase != previousPhase || last.Reason != previousReason {
			return fmt.Errorf("operation status does not match its last durable phase event")
		}
	}
	if !protocol.CanAdvanceMaintenancePhase(previousPhase, phase, m.Status.ResumePhase) {
		return fmt.Errorf("invalid maintenance phase transition %q -> %q", previousPhase, phase)
	}
	if protocol.TerminalPhase(previousPhase) && phase == "RecoveryRequired" && reason != "TerminalRecoveryIncomplete" {
		return fmt.Errorf("terminal operation can re-enter recovery only for an owned cordon")
	}
	if previousPhase == phase && previousReason == reason {
		if !force {
			return nil
		}
		if len(m.Status.Events) >= 240 {
			return r.Client.Status().Update(ctx, m)
		}
	}
	if len(m.Status.Events) >= 256 {
		return fmt.Errorf("operation phase journal is full; refusing unrecorded transition")
	}
	if phase != "Blocked" {
		m.Status.ResumePhase = ""
	}
	transitionAt := r.now()
	if count := len(m.Status.Events); count > 0 {
		previousEventTime := m.Status.Events[count-1].Time.Time
		if transitionAt.Before(previousEventTime) {
			// Keep the durable audit chronology consistent when the host clock
			// steps backwards. Sequence remains authoritative; equal event times
			// are permitted by the shared report contract.
			transitionAt = previousEventTime
		}
	}
	m.Status.Sequence++
	m.Status.Phase = phase
	m.Status.Reason = reason
	m.Status.ObservedGeneration = m.Generation
	m.Status.Events = append(m.Status.Events, protocol.PhaseEvent{Sequence: m.Status.Sequence, Phase: phase, Reason: reason, ResourceUID: resourceUID, Time: metav1.NewTime(transitionAt)})

	condition := metav1.Condition{Type: "Progressing", Status: metav1.ConditionTrue, Reason: reason, ObservedGeneration: m.Generation, Message: phase, LastTransitionTime: metav1.NewTime(r.now())}
	if phase == "Blocked" || phase == "RecoveryRequired" || phase == "Failed" {
		condition.Status = metav1.ConditionFalse
	}
	if protocol.TerminalPhase(phase) {
		condition.Status = metav1.ConditionFalse
	}
	meta.SetStatusCondition(&m.Status.Conditions, condition)
	ready := metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: reason, Message: phase, ObservedGeneration: m.Generation, LastTransitionTime: metav1.NewTime(r.now())}
	if phase == "Succeeded" {
		ready.Status = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&m.Status.Conditions, ready)
	if err := r.Client.Status().Update(ctx, m); err != nil {
		return err
	}
	stateChanged := previousPhase != phase || previousReason != reason
	action := observability.ActionFromAuthorization(m.Spec.Authorization)
	if stateChanged {
		observability.RecordMaintenanceTransition(phase, reason)
		if phase == "Blocked" || phase == "RecoveryRequired" {
			observability.RecordMaintenanceBlocked(phase, reason)
		}
	}
	if previousPhase != phase {
		if phase == "RecoveryRequired" {
			observability.RecordMaintenanceRecoveryRequired(action)
		} else if protocol.TerminalPhase(phase) {
			seconds := transitionAt.Sub(m.Status.Events[0].Time.Time).Seconds()
			observability.RecordMaintenanceOutcome(action, phase, seconds)
		}
		if previousPhase == "Draining" && (phase == "Executing" || phase == "VerifyingNode" || phase == "VerifyingWorkloads") {
			if started, ok := latestPhaseTime(m.Status.Events[:len(m.Status.Events)-1], "Draining"); ok {
				observability.ObserveMaintenanceDrain(action, transitionAt.Sub(started).Seconds())
			}
		}
		if previousPhase == "Rebooting" && phase == "VerifyingNode" {
			if started, ok := latestPhaseTime(m.Status.Events[:len(m.Status.Events)-1], "Rebooting"); ok {
				observability.ObserveMaintenanceReboot(action, transitionAt.Sub(started).Seconds())
			}
		}
	}
	if previousPhase != phase && len(m.Status.Events) > 1 {
		previousEvent := m.Status.Events[len(m.Status.Events)-2]
		observability.ObserveMaintenancePhase(previousPhase, phase, transitionAt.Sub(previousEvent.Time.Time).Seconds())
	}
	if (previousPhase == "RecoveryRequired" || previousPhase == "VerifyingNode" || previousPhase == "VerifyingWorkloads" || previousPhase == "Uncordoning") && protocol.TerminalPhase(phase) {
		for _, event := range m.Status.Events {
			if event.Phase == "RecoveryRequired" {
				observability.ObserveRecoveryDuration(r.now().Sub(event.Time.Time).Seconds())
				break
			}
		}
	}
	if r.Logger != nil {
		r.Logger.InfoContext(ctx, "maintenance transition", "operation_id", m.Status.OperationID, "namespace", m.Namespace, "name", m.Name, "phase", phase, "reason", reason, "sequence", m.Status.Sequence)
	}
	return nil
}

func latestPhaseTime(events []protocol.PhaseEvent, phase string) (time.Time, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Phase == phase {
			return events[i].Time.Time, true
		}
	}
	return time.Time{}, false
}

func (r *Reconciler) receipt(ctx context.Context, m *operations.NodeMaintenance, p protocol.MaintenancePermit) error {
	name := "maintenance-op-" + p.OperationID
	var receipt corev1.ConfigMap
	err := r.Reader.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: name}, &receipt)
	if apierrors.IsNotFound(err) {
		immutable := true
		receipt = corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: protocol.SlotNamespace, Name: name}, Immutable: &immutable, Data: map[string]string{"maintenanceUID": string(m.UID), "digest": m.Spec.Command().Digest()}}
		if err = r.Client.Create(ctx, &receipt); err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}
	if receipt.Data["maintenanceUID"] != string(m.UID) || receipt.Data["digest"] != m.Spec.Command().Digest() {
		return ErrDuplicateOperation
	}
	return nil
}
func (r *Reconciler) slot(ctx context.Context, uid types.UID, acquire bool) (bool, error) {
	var lease coordinationv1.Lease
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
		return false, err
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if holder == string(uid) {
		return true, nil
	}
	if !acquire || holder != "" {
		return false, nil
	}
	value := string(uid)
	lease.Spec.HolderIdentity = &value
	now := metav1.NewMicroTime(r.now())
	lease.Spec.RenewTime = &now
	if err := r.Client.Update(ctx, &lease); err != nil {
		return false, err
	}
	return true, nil
}

// slotBlockReason distinguishes normal contention from a Lease whose operation
// record has disappeared. It is diagnostic only: stale reservations are never
// reclaimed automatically because the previous operation's outcome may be
// ambiguous.
func (r *Reconciler) slotBlockReason(ctx context.Context, namespace string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("maintenance namespace is required to inspect cluster reservation ownership")
	}
	var lease coordinationv1.Lease
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
		return "", err
	}
	holder := ""
	if lease.Spec.HolderIdentity != nil {
		holder = *lease.Spec.HolderIdentity
	}
	if holder == "" {
		// A concurrent release may have occurred after slot() observed the
		// Lease. Keep this attempt blocked; reconciliation will retry admission.
		return "ClusterConcurrencyLimit", nil
	}
	var operationsList operations.NodeMaintenanceList
	if err := r.Reader.List(ctx, &operationsList, client.InNamespace(namespace)); err != nil {
		return "", err
	}
	for i := range operationsList.Items {
		if string(operationsList.Items[i].UID) == holder {
			return "ClusterConcurrencyLimit", nil
		}
	}
	return "OrphanedClusterReservation", nil
}

func (r *Reconciler) release(ctx context.Context, m *operations.NodeMaintenance) error {
	// A deleted kured DaemonSet cannot retain our external lock. Terminal
	// cleanup must still release the independently owned local reservation.
	if err := r.releaseKuredLock(ctx, m); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	var lease coordinationv1.Lease
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // Absence confirms this operation has no local reservation.
		}
		return err
	}
	if lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == string(m.UID) {
		empty := ""
		lease.Spec.HolderIdentity = &empty
		if err := r.Client.Update(ctx, &lease); err != nil {
			return err
		}
	}
	return nil
}
func (r *Reconciler) connected(ctx context.Context, namespace string) bool {
	var lease coordinationv1.Lease
	if r.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: protocol.ConnectionLease}, &lease) != nil {
		return false
	}
	return lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity == r.ClusterID && lease.Spec.RenewTime != nil && r.now().Sub(lease.Spec.RenewTime.Time) < protocol.ConnectionTTL && !lease.Spec.RenewTime.After(r.now().Add(5*time.Second))
}
func removeFinalizer(m *operations.NodeMaintenance) {
	finalizers := m.Finalizers[:0]
	for _, v := range m.Finalizers {
		if v != Finalizer {
			finalizers = append(finalizers, v)
		}
	}
	m.Finalizers = finalizers
}
func hasFinalizer(m *operations.NodeMaintenance) bool {
	for _, v := range m.Finalizers {
		if v == Finalizer {
			return true
		}
	}
	return false
}
