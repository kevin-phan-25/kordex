package controller

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	operations "kordex.local/api/operations/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestSummarizeActiveRecoveryAge(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	started := func(age time.Duration) *metav1.Time {
		value := metav1.NewTime(now.Add(-age))
		return &value
	}
	future := metav1.NewTime(now.Add(time.Second))
	items := []operations.NodeMaintenance{
		{Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired", RecoveryStartedAt: started(5 * time.Minute)}},
		{Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired", RecoveryStartedAt: started(time.Minute)}},
		{Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired"}},
		{Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired", RecoveryStartedAt: &future}},
		{Status: operations.NodeMaintenanceStatus{Phase: "Succeeded", RecoveryStartedAt: started(time.Hour)}},
	}

	active, invalid, oldest := summarizeActiveRecoveryAge(items, now)
	if active != 4 || invalid != 2 || oldest != 300 {
		t.Fatalf("summary = (active %d, invalid %d, oldest %.0fs); want (4, 2, 300s)", active, invalid, oldest)
	}
}

func TestRecoveryAgePublisherRefreshReadsConfiguredNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := operations.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	started := metav1.NewTime(now.Add(-2 * time.Minute))
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "kordex-system"}, Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired", RecoveryStartedAt: &started}},
		&operations.NodeMaintenance{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "another-namespace"}, Status: operations.NodeMaintenanceStatus{Phase: "RecoveryRequired", RecoveryStartedAt: &started}},
	).Build()
	publisher := RecoveryAgePublisher{Reader: reader, Namespace: "kordex-system", Now: func() time.Time { return now }}
	if err := publisher.refresh(context.Background()); err != nil {
		t.Fatalf("refresh recovery age snapshot: %v", err)
	}
}
