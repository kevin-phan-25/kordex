package controller

import (
	"context"
	"testing"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCapabilityPublisherWritesOnlyConfiguredExecutorFlags(t *testing.T) {
	lease := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: OperatorCapabilitiesLease, Namespace: "kordex-system"}}
	client := fake.NewClientset(lease)
	publisher := CapabilityPublisher{Leases: client.CoordinationV1().Leases("kordex-system"), HostUpgrades: true}
	if err := publisher.publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := client.CoordinationV1().Leases("kordex-system").Get(context.Background(), OperatorCapabilitiesLease, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Annotations["operations.kordex.local/host-upgrades"] != "true" || got.Annotations["operations.kordex.local/gke-node-pool-upgrade"] != "false" {
		t.Fatalf("unexpected published capabilities: %#v", got.Annotations)
	}
	if got.Spec.RenewTime == nil || got.Spec.LeaseDurationSeconds == nil || *got.Spec.LeaseDurationSeconds != 45 {
		t.Fatalf("missing short-lived capability lease: %+v", got.Spec)
	}
}
