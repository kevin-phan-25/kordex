package controller

import (
	"context"
	"errors"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

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
	if m.Status.Phase == phase && m.Status.Reason == reason && !force {
		return nil
	}
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
	if phase != "Blocked" {
		m.Status.ResumePhase = ""
	}
	transitionAt := r.now()
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
	if stateChanged {
		observability.RecordMaintenanceTransition(phase, reason)
		if phase == "Blocked" || phase == "RecoveryRequired" {
			observability.RecordMaintenanceBlocked(phase, reason)
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
func (r *Reconciler) release(ctx context.Context, m *operations.NodeMaintenance) error {
	if err := r.releaseKuredLock(ctx, m); err != nil {
		return err
	}
	var lease coordinationv1.Lease
	if err := r.Reader.Get(ctx, types.NamespacedName{Namespace: protocol.SlotNamespace, Name: protocol.SlotLease}, &lease); err != nil {
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
