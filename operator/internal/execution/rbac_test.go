package execution

import (
	"context"
	"errors"
	"slices"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestVerifyHostExecutionRBACRequiresEveryEffectivePermission(t *testing.T) {
	client := fake.NewClientset()
	var reviewed []authorizationv1.ResourceAttributes
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, *request.Spec.ResourceAttributes)
		request.Status.Allowed = true
		return true, request, nil
	})
	missing, err := VerifyHostExecutionRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system", "upgrade-ssh", "known-hosts")
	if err != nil || len(missing) != 0 {
		t.Fatalf("all allowed reviews should enable the executor, missing=%v err=%v", missing, err)
	}
	if got := len(client.Actions()); got != len(hostExecutionPermissions("kordex-system", "upgrade-ssh", "known-hosts")) {
		t.Fatalf("performed %d permission reviews, want %d", got, len(hostExecutionPermissions("kordex-system", "upgrade-ssh", "known-hosts")))
	}
	want := []authorizationv1.ResourceAttributes{
		{Namespace: "kordex-system", Verb: "get", Resource: "secrets", Name: "upgrade-ssh"},
		{Namespace: "kordex-system", Verb: "get", Resource: "configmaps", Name: "known-hosts"},
		{Namespace: "kordex-operations-ledger", Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Name: "kordex-maintenance-cluster-slot"},
		{Namespace: "kordex-system", Verb: "create", Group: "networking.k8s.io", Resource: "networkpolicies"},
	}
	for _, expected := range want {
		found := false
		for _, actual := range reviewed {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("required permission was not reviewed: %+v", expected)
		}
	}
}

func TestVerifyHostExecutionRBACFailsClosedOnDeniedOrIndeterminateReview(t *testing.T) {
	for _, test := range []struct {
		name   string
		status authorizationv1.SubjectAccessReviewStatus
	}{
		{name: "denied", status: authorizationv1.SubjectAccessReviewStatus{Denied: true}},
		{name: "not evaluated", status: authorizationv1.SubjectAccessReviewStatus{Reason: "no opinion"}},
		{name: "evaluation error", status: authorizationv1.SubjectAccessReviewStatus{Allowed: true, EvaluationError: "policy backend unavailable"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fake.NewClientset()
			first := true
			client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
				request := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
				if first {
					request.Status = test.status
					first = false
				} else {
					request.Status.Allowed = true
				}
				return true, request, nil
			})
			missing, err := VerifyHostExecutionRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system", "upgrade-ssh", "known-hosts")
			if err != nil || len(missing) != 1 {
				t.Fatalf("non-allow review must disable capability, missing=%v err=%v", missing, err)
			}
		})
	}
}

func TestVerifyHostExecutionRBACReportsReviewRequestFailure(t *testing.T) {
	client := fake.NewClientset()
	client.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("authorization API unavailable")
	})
	_, err := VerifyHostExecutionRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system", "upgrade-ssh", "known-hosts")
	if err == nil {
		t.Fatal("authorization API failure must disable host execution")
	}
}

func TestVerifyHostExecutionRBACRejectsInvalidProbeNames(t *testing.T) {
	client := fake.NewClientset()
	_, err := VerifyHostExecutionRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "../kordex", "upgrade-ssh", "known-hosts")
	if err == nil {
		t.Fatal("invalid probe namespace accepted")
	}
	if len(client.Actions()) != 0 {
		t.Fatal("invalid probe identity reached the authorization API")
	}
	_, err = VerifyHostExecutionRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system", "not a secret", "known-hosts")
	if err == nil || len(client.Actions()) != 0 {
		t.Fatal("invalid resource identity reached the authorization API")
	}
}

func TestVerifyNodeMaintenanceRBACRequiresDrainAndRecoveryPermissions(t *testing.T) {
	client := fake.NewClientset()
	var reviewed []authorizationv1.ResourceAttributes
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, *request.Spec.ResourceAttributes)
		request.Status.Allowed = true
		return true, request, nil
	})
	missing, err := VerifyNodeMaintenanceRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system")
	if err != nil || len(missing) != 0 {
		t.Fatalf("all allowed reviews should enable node maintenance, missing=%v err=%v", missing, err)
	}
	if got := len(reviewed); got != len(nodeMaintenancePermissions("kordex-system")) {
		t.Fatalf("reviewed %d permissions, want %d", got, len(nodeMaintenancePermissions("kordex-system")))
	}
	want := []authorizationv1.ResourceAttributes{
		{Verb: "patch", Resource: "nodes"},
		{Verb: "create", Resource: "pods", Subresource: "eviction"},
		{Verb: "list", Resource: "persistentvolumes"},
		{Verb: "get", Resource: "services"},
		{Verb: "get", Resource: "namespaces", Name: "kube-system"},
		{Verb: "list", Group: "ceph.rook.io", Resource: "cephclusters"},
		{Verb: "list", Group: "longhorn.io", Resource: "volumes"},
		{Namespace: "kordex-system", Verb: "update", Group: "operations.kordex.local", Resource: "nodemaintenances", Subresource: "status"},
		{Namespace: "kordex-system", Verb: "watch", Group: "operations.kordex.local", Resource: "maintenancepolicies"},
		{Namespace: "kordex-system", Verb: "list", Group: "operations.kordex.local", Resource: "maintenancecampaigns"},
		{Namespace: "kordex-system", Verb: "get", Group: "coordination.k8s.io", Resource: "leases", Name: "kordex-hub-connection"},
		{Namespace: "kordex-operations-ledger", Verb: "update", Group: "coordination.k8s.io", Resource: "leases", Name: "kordex-maintenance-cluster-slot"},
		{Namespace: "kordex-operations-ledger", Verb: "create", Resource: "configmaps"},
	}
	for _, expected := range want {
		if !slices.Contains(reviewed, expected) {
			t.Errorf("required permission was not reviewed: %+v", expected)
		}
	}
}

func TestVerifyNodeMaintenanceRBACFailsClosedOnDeniedReview(t *testing.T) {
	client := fake.NewClientset()
	denied := false
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		if !denied {
			request.Status.Denied = true
			denied = true
		} else {
			request.Status.Allowed = true
		}
		return true, request, nil
	})
	missing, err := VerifyNodeMaintenanceRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "kordex-system")
	if err != nil || len(missing) != 1 {
		t.Fatalf("denied permission must be reported and disable capability, missing=%v err=%v", missing, err)
	}
}

func TestVerifyNodeMaintenanceRBACRequiresReviewClient(t *testing.T) {
	if _, err := VerifyNodeMaintenanceRBAC(context.Background(), nil, "kordex-system"); err == nil {
		t.Fatal("missing review client must not report node-maintenance readiness")
	}
}

func TestVerifyNodeMaintenanceRBACUsesConfiguredNamespaceAndRejectsInvalidNamespace(t *testing.T) {
	client := fake.NewClientset()
	var reviewed []authorizationv1.ResourceAttributes
	client.PrependReactor("create", "selfsubjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		request := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		reviewed = append(reviewed, *request.Spec.ResourceAttributes)
		request.Status.Allowed = true
		return true, request, nil
	})
	if _, err := VerifyNodeMaintenanceRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "ops-system"); err != nil {
		t.Fatal(err)
	}
	want := authorizationv1.ResourceAttributes{Namespace: "ops-system", Verb: "get", Group: "operations.kordex.local", Resource: "nodemaintenances"}
	if !slices.Contains(reviewed, want) {
		t.Fatalf("configured namespace was not used in review: %+v", reviewed)
	}
	before := len(client.Actions())
	if _, err := VerifyNodeMaintenanceRBAC(context.Background(), client.AuthorizationV1().SelfSubjectAccessReviews(), "../invalid"); err == nil {
		t.Fatal("invalid namespace accepted")
	}
	if len(client.Actions()) != before {
		t.Fatal("invalid namespace reached the authorization API")
	}
}
