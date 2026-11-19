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
	"kordex.local/api/protocol"
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
	condition := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "PolicyAccepted", Message: "Policy is valid; executor capability and live safety are checked independently before each operation", ObservedGeneration: policy.Generation}
	if decision := protocol.EvaluateMaintenanceTarget(policy.Spec.NodeSelector, nil); decision.ReasonCode == "InvalidNodeSelector" {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidSelector"
		condition.Message = "Invalid node selector"
	} else if decision := protocol.EvaluateProtectedNode(policy.Spec.ProtectedNodeSelector, map[string]string{}); decision.ReasonCode == "InvalidProtectedNodeSelector" {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidProtectedNodeSelector"
		condition.Message = "Invalid protected-node selector"
	} else if err := protocol.ValidateMaintenancePolicyActions(policy.Spec.AllowedActions); err != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "InvalidAllowedActions"
		condition.Message = "Policy must explicitly allow one or more supported operations"
	} else if protocol.EvaluateMaintenanceAction(policy.Generation, policy.Spec.AllowedActions, protocol.UpgradePackages).Allowed && policy.Spec.Upgrade == nil ||
		protocol.EvaluateMaintenanceAction(policy.Generation, policy.Spec.AllowedActions, protocol.UpgradeNodePool).Allowed && policy.Spec.ProviderUpgrade == nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "UpgradeActionPlanMismatch"
		condition.Message = "Every allowed upgrade action requires its matching local plan"
	}
	if policy.Spec.Upgrade != nil && policy.Spec.ProviderUpgrade != nil {
		condition.Status = metav1.ConditionFalse
		condition.Reason = "ConflictingUpgradePlans"
		condition.Message = "Configure either a self-managed or provider-native upgrade plan, not both"
	} else if policy.Spec.Upgrade != nil {
		if err := policy.Spec.Upgrade.Validate(); err != nil {
			condition.Status = metav1.ConditionFalse
			condition.Reason = "InvalidUpgradePlan"
			condition.Message = "Self-managed upgrade plan failed validation"
		}
	} else if policy.Spec.ProviderUpgrade != nil {
		if err := policy.Spec.ProviderUpgrade.Validate(); err != nil {
			condition.Status = metav1.ConditionFalse
			condition.Reason = "InvalidUpgradePlan"
			condition.Message = "Provider-native upgrade plan failed validation"
		}
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
	meta.SetStatusCondition(&campaign.Status.Conditions, metav1.Condition{Type: "Ready", Status: metav1.ConditionFalse, Reason: "HubOrchestrationRequired", Message: "Fleet campaigns run in the management plane; this resource never creates node operations", ObservedGeneration: campaign.Generation})
	return ctrl.Result{}, r.Status().Update(ctx, &campaign)
}
