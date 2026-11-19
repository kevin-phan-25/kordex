package controller

import (
	"context"
	"testing"

	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operations "kordex.local/api/operations/v1alpha1"
	"kordex.local/api/protocol"
)

func TestPolicyReconcilerRequiresExplicitActionsAndUpgradePlans(t *testing.T) {
	tests := []struct {
		name       string
		actions    []string
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{name: "missing actions", wantStatus: metav1.ConditionFalse, wantReason: "InvalidAllowedActions"},
		{name: "safe actions", actions: []string{protocol.ValidateOnly, protocol.DrainAndVerify}, wantStatus: metav1.ConditionTrue, wantReason: "PolicyAccepted"},
		{name: "invalid protected-node selector", actions: []string{protocol.ValidateOnly}, wantStatus: metav1.ConditionFalse, wantReason: "InvalidProtectedNodeSelector"},
		{name: "upgrade action without plan", actions: []string{protocol.UpgradePackages}, wantStatus: metav1.ConditionFalse, wantReason: "UpgradeActionPlanMismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := operations.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			policy := &operations.MaintenancePolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "policy", UID: types.UID("policy-uid"), Generation: 1},
				Spec:       operations.MaintenancePolicySpec{NodeSelector: metav1.LabelSelector{}, AllowedActions: test.actions},
			}
			if test.name == "invalid protected-node selector" {
				policy.Spec.ProtectedNodeSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "pool", Operator: "Unknown"}}}
			}
			kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&operations.MaintenancePolicy{}).WithObjects(policy).Build()
			reconciler := &PolicyReconciler{Client: kubeClient}
			if _, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(policy)}); err != nil {
				t.Fatal(err)
			}
			var observed operations.MaintenancePolicy
			if err := kubeClient.Get(context.Background(), client.ObjectKeyFromObject(policy), &observed); err != nil {
				t.Fatal(err)
			}
			ready := apiMeta.FindStatusCondition(observed.Status.Conditions, "Ready")
			if ready == nil || ready.Status != test.wantStatus || ready.Reason != test.wantReason {
				t.Fatalf("unexpected Ready condition: %+v", ready)
			}
		})
	}
}
