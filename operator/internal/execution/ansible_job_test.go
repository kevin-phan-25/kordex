package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"kordex.local/api/protocol"
)

func TestCancelledAnsibleJobCannotBeRecreated(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	executor := &AnsibleJobExecutor{
		Client:              client,
		Namespace:           "kordex-system",
		ServiceAccount:      "kordex-upgrade-runner",
		SSHUser:             "kordex",
		SSHCredentialSecret: "kordex-ssh",
		KnownHostsConfigMap: "kordex-known-hosts",
	}
	policy := protocol.UpgradePolicy{
		SchemaVersion:        1,
		ID:                   "debian-test",
		OSFamily:             "debian",
		ExecutionBackend:     "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v1",
		ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64),
		CollectionsDigest:    strings.Repeat("c", 64),
		Packages:             []protocol.PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}},
		Channel:              "stable",
		Reboot:               protocol.RebootNever,
		ExecutionTimeout:     time.Minute,
		RebootTimeout:        time.Minute,
		VerificationTimeout:  time.Minute,
		MaxAttempts:          1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatalf("digest policy: %v", err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58",
		OwnerName:   "op-2e15e264-6bc4-4574-8e13-11a135b90e58",
		OwnerUID:    types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"),
		NodeName:    "worker-01",
		NodeUID:     "00c85ae4-f827-42c8-b43b-b1b0085b1781",
		Address:     "10.0.0.10",
		PlanDigest:  digest,
		Phase:       EEPhasePreflight,
		Policy:      policy,
	}
	jobName, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatalf("ensure job: %v", err)
	}
	if err := executor.Cancel(ctx, request, jobName); err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	if _, err := executor.Ensure(ctx, request); !errors.Is(err, ErrExecutionCancelled) {
		t.Fatalf("Ensure after cancellation error = %v, want ErrExecutionCancelled", err)
	}
	observation, err := executor.Observe(ctx, request, jobName)
	if err != nil {
		t.Fatalf("observe cancelled operation: %v", err)
	}
	if observation.Phase != "RecoveryRequired" || observation.Outcome != "Ambiguous" {
		t.Fatalf("cancelled observation = phase %q outcome %q, want RecoveryRequired/Ambiguous", observation.Phase, observation.Outcome)
	}
	if _, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, jobName, metav1.GetOptions{}); err == nil {
		t.Fatal("cancelled Job still exists")
	}
	if _, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, jobName+"-cancelled", metav1.GetOptions{}); err != nil {
		t.Fatalf("read durable cancellation tombstone: %v", err)
	}
}
