package safety

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPDBBeforeCordonDefersOnlyWhenStorageAdapterOwnsTheDecision(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "database", Labels: map[string]string{"app": "database"}}}
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "database", Generation: 1},
		Spec:       policyv1.PodDisruptionBudgetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "database"}}},
		Status:     policyv1.PodDisruptionBudgetStatus{ObservedGeneration: 1, DisruptionsAllowed: 0},
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := policyv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pdb).Build()
	checker := &Checker{Reader: reader, Storage: deferringPDBStorage{deferPDB: true}}

	if result, err := checker.PDBBeforeCordon(context.Background(), pod); err != nil || !result.Allowed {
		t.Fatalf("managed pre-cordon PDB decision should be deferred: result=%+v err=%v", result, err)
	}
	if result, err := checker.PDB(context.Background(), pod); err != nil || result.Allowed || result.Reason != "PDBBlocked" {
		t.Fatalf("strict eviction gate must still block: result=%+v err=%v", result, err)
	}

	checker.Storage = deferringPDBStorage{}
	if result, err := checker.PDBBeforeCordon(context.Background(), pod); err != nil || result.Allowed || result.Reason != "PDBBlocked" {
		t.Fatalf("ordinary PDB must remain enforced: result=%+v err=%v", result, err)
	}
}

type deferringPDBStorage struct{ deferPDB bool }

func (deferringPDBStorage) Check(context.Context, *corev1.Node, []corev1.Pod) (Result, error) {
	return Pass(), nil
}

func (s deferringPDBStorage) DeferPDBUntilCordon(context.Context, *corev1.Pod, *policyv1.PodDisruptionBudget) (bool, error) {
	return s.deferPDB, nil
}
