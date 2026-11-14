package controller

import (
	"context"
	"reflect"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	operations "kordex.local/api/operations/v1alpha1"
)

type PolicyReconciler struct{ client.Client }

func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&operations.MaintenancePolicy{}).WithEventFilter(predicate.GenerationChangedPredicate{}).Complete(r)
}
func (r *PolicyReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var policy operations.MaintenancePolicy
	if err := r.Get(ctx, request.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	previous := policy.Status.DeepCopy()
	policy.Status.ObservedGeneration = policy.Generation
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "PolicyAccepted", Message: "Stateless worker drain drills only; cluster concurrency is one", ObservedGeneration: policy.Generation}
	if _, err := metav1.LabelSelectorAsSelector(&policy.Spec.NodeSelector); err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidSelector"
		condition.Message = "Invalid node selector"
	}
	if policy.Spec.Suspended {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "Suspended"
		condition.Message = "New disruptive actions are suspended"
	}
	meta.SetStatusCondition(&policy.Status.Conditions, condition)
	if reflect.DeepEqual(previous, &policy.Status) {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, r.Status().Update(ctx, &policy)
}

type CampaignReconciler struct{ client.Client }

func (r *CampaignReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&operations.MaintenanceCampaign{}).WithEventFilter(predicate.GenerationChangedPredicate{}).Complete(r)
}
func (r *CampaignReconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var campaign operations.MaintenanceCampaign
	if err := r.Get(ctx, request.NamespacedName, &campaign); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if campaign.Status.ObservedGeneration == campaign.Generation && meta.IsStatusConditionFalse(campaign.Status.Conditions, "Ready") {
		return ctrl.Result{}, nil
	}
	campaign.Status.ObservedGeneration = campaign.Generation
	meta.SetStatusCondition(&campaign.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "OrchestrationNotImplemented", Message: "Campaign scheduling is Phase 4; no operations are created", ObservedGeneration: campaign.Generation})
	return ctrl.Result{}, r.Status().Update(ctx, &campaign)
}
