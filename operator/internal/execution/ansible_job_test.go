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
		Client:                       client,
		Namespace:                    "kordex-system",
		ServiceAccount:               "kordex-upgrade-runner",
		SSHUser:                      "kordex",
		SSHCredentialSecret:          "kordex-ssh",
		KnownHostsConfigMap:          "kordex-known-hosts",
		AllowedExecutionEnvironments: []string{"registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64)},
	}
	policy := protocol.UpgradePolicy{
		SchemaVersion:        1,
		ID:                   "debian-test",
		OSFamily:             "debian",
		ExecutionBackend:     "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v2",
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

func TestAnsibleJobRequestsRequirePreflightIdentityForMutatingPhases(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}}, ExpectedKernelVersion: "6.1.0-1-generic", Channel: "stable", Reboot: protocol.RebootRequired,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerName: "op-2e15e264-6bc4-4574-8e13-11a135b90e58",
		OwnerUID: types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"), NodeName: "worker-01",
		NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781", Address: "10.0.0.10", PlanDigest: digest, Policy: policy,
	}
	request.Phase = EEPhasePreflight
	if err := validateEERequest(request); err != nil {
		t.Fatalf("valid preflight request rejected: %v", err)
	}
	request.Phase = EEPhaseApply
	request.MachineID = strings.Repeat("d", 32)
	request.BootID = "33333333-3333-4333-8333-333333333333"
	if err := validateEERequest(request); err != nil {
		t.Fatalf("valid package apply request rejected: %v", err)
	}
	request.Phase = EEPhaseReboot
	request.RebootAuthorized = true
	if err := validateEERequest(request); err != nil {
		t.Fatalf("valid separately authorized reboot request rejected: %v", err)
	}
	policy.Reboot = protocol.RebootNever
	policy.Packages = []protocol.PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}}
	policy.ExpectedKernelVersion = ""
	request.Policy = policy
	request.PlanDigest, err = policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEERequest(request); err == nil {
		t.Fatal("reboot phase accepted when policy prohibits reboot")
	}
	request.Phase = EEPhaseInspect
	request.RebootAuthorized = false
	if err := validateEERequest(request); err != nil {
		t.Fatalf("read-only recovery inspection request rejected: %v", err)
	}
	request.RebootAuthorized = true
	if err := validateEERequest(request); err == nil {
		t.Fatal("read-only recovery inspection accepted reboot authorization")
	}
}

func TestReadOnlyInspectionReceiptMayObserveChangedBootID(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}}, ExpectedKernelVersion: "6.1.0-1-generic", Channel: "stable", Reboot: protocol.RebootRequired,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781",
		PlanDigest: digest, Phase: EEPhaseInspect, Policy: policy,
		MachineID: strings.Repeat("d", 32), BootID: "33333333-3333-4333-8333-333333333333",
	}
	receipt := &AnsibleReceipt{
		OperationID: request.OperationID, PlanDigest: digest, NodeUID: request.NodeUID, MachineID: request.MachineID,
		BootIDBefore: "44444444-4444-4444-8444-444444444444", BootIDAfter: "44444444-4444-4444-8444-444444444444",
		OSFamily: "debian", KernelVersion: "6.1.0-1-generic", ExpectedKernelVersion: "6.1.0-1-generic", RebootRequired: true, Packages: map[string]string{"linux-image-generic": "6.1.0-1"}, CompletedAt: time.Now().UTC(),
	}
	if err := validateReceipt(request, receipt, time.Time{}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("read-only inspection could not report a rebooted host: %v", err)
	}
}

func TestRebootReceiptMustReportExpectedRunningKernel(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "kernel-plan", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}}, ExpectedKernelVersion: "6.1.0-1-generic",
		Channel: "stable", Reboot: protocol.RebootRequired, ExecutionTimeout: time.Minute, RebootTimeout: time.Minute,
		VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781",
		PlanDigest: digest, Phase: EEPhaseReboot, Policy: policy, MachineID: strings.Repeat("d", 32),
		BootID: "33333333-3333-4333-8333-333333333333",
	}
	receipt := &AnsibleReceipt{
		OperationID: request.OperationID, PlanDigest: digest, NodeUID: request.NodeUID, MachineID: request.MachineID,
		BootIDBefore: request.BootID, BootIDAfter: "44444444-4444-4444-8444-444444444444", OSFamily: "debian",
		KernelVersion: policy.ExpectedKernelVersion, ExpectedKernelVersion: policy.ExpectedKernelVersion, Rebooted: true,
		RebootRequired: true, Packages: map[string]string{"linux-image-generic": "6.1.0-1"}, CompletedAt: time.Now().UTC(),
	}
	if err := validateReceipt(request, receipt, time.Time{}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("receipt with expected running kernel rejected: %v", err)
	}
	receipt.KernelVersion = "6.0.0-old-generic"
	if err := validateReceipt(request, receipt, time.Time{}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("reboot receipt accepted a kernel different from the signed expected version")
	}
}

func TestAnsibleJobIsPreparedBeforeItCanRun(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	executor := &AnsibleJobExecutor{Client: client, Namespace: "kordex-system", ServiceAccount: "kordex-upgrade-runner", SSHUser: "kordex", SSHCredentialSecret: "kordex-ssh", KnownHostsConfigMap: "kordex-known-hosts", AllowedExecutionEnvironments: []string{"registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64)}, ImagePullSecrets: []string{"registry-auth"}}
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerName: "op-2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerUID: types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"), NodeName: "worker-01", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781", Address: "10.0.0.10", PlanDigest: digest, Phase: EEPhasePreflight, Policy: policy}
	unapproved := request
	unapproved.Policy.ExecutionEnvironment = "registry.example/untrusted/ee@sha256:" + strings.Repeat("d", 64)
	unapproved.PlanDigest, err = unapproved.Policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Ensure(ctx, unapproved); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("unapproved digest-pinned image was accepted: %v", err)
	}
	if _, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, eeJobName(unapproved.OperationID, unapproved.Phase)+"-request", metav1.GetOptions{}); err == nil {
		t.Fatal("unapproved image created an immutable execution request")
	}
	name, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || job.Spec.Suspend == nil || !*job.Spec.Suspend {
		t.Fatal("Ansible EE job was not durably prepared in suspended state")
	}
	if len(job.Spec.Template.Spec.ImagePullSecrets) != 1 || job.Spec.Template.Spec.ImagePullSecrets[0].Name != "registry-auth" {
		t.Fatalf("private registry pull secret not configured on Job: %+v", job.Spec.Template.Spec.ImagePullSecrets)
	}
	originalSecret := job.Spec.Template.Spec.Volumes[1].Secret.SecretName
	job.Spec.Template.Spec.Volumes[1].Secret.SecretName = "attacker-controlled-ssh"
	job, err = client.BatchV1().Jobs(executor.Namespace).Update(ctx, job, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("mutate test Job SSH secret: %v", err)
	}
	if err = executor.Start(ctx, request, name); !errors.Is(err, ErrExecutionIdentity) {
		t.Fatalf("activated Job after SSH credential volume changed: %v", err)
	}
	if _, err = executor.Ensure(ctx, request); !errors.Is(err, ErrExecutionIdentity) {
		t.Fatalf("adopted Job with changed SSH credential volume: %v", err)
	}
	job.Spec.Template.Spec.Volumes[1].Secret.SecretName = originalSecret
	job, err = client.BatchV1().Jobs(executor.Namespace).Update(ctx, job, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("restore test Job SSH secret: %v", err)
	}
	if err := executor.Start(ctx, request, name); err != nil {
		t.Fatal(err)
	}
	if err := executor.Start(ctx, request, name); err != nil {
		t.Fatalf("idempotent start failed: %v", err)
	}
	job, err = client.BatchV1().Jobs(executor.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || job.Spec.Suspend == nil || *job.Spec.Suspend {
		t.Fatal("prepared Ansible EE job did not start")
	}
	if _, err := executor.Ensure(ctx, request); err != nil {
		t.Fatalf("reconciling existing execution attempted a duplicate: %v", err)
	}
	if err := client.BatchV1().Jobs(executor.Namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Ensure(ctx, request); !errors.Is(err, ErrExecutionNotFound) {
		t.Fatalf("missing previously requested job error = %v, want ErrExecutionNotFound", err)
	}
}

func TestAnsibleExecutorRequiresExactDigestAllowlist(t *testing.T) {
	base := &AnsibleJobExecutor{
		Client: fake.NewSimpleClientset(), Namespace: "kordex-system", ServiceAccount: "kordex-upgrade-runner",
		SSHUser: "kordex", SSHCredentialSecret: "kordex-ssh", KnownHostsConfigMap: "kordex-known-hosts",
	}
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("executor without image allowlist validated: %v", err)
	}
	base.AllowedExecutionEnvironments = []string{"registry.example/kordex/ee:latest"}
	if err := base.Validate(); err == nil {
		t.Fatal("tag-only image allowlist validated")
	}
	base.AllowedExecutionEnvironments = []string{"registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64)}
	base.ImagePullSecrets = []string{"not valid"}
	if err := base.Validate(); err == nil {
		t.Fatal("invalid image pull secret name validated")
	}
	base.ImagePullSecrets = nil
	if err := base.Validate(); err != nil {
		t.Fatalf("valid exact image digest allowlist rejected: %v", err)
	}
}

func TestReceiptSurvivesJobRemovalAndOperatorRestart(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset()
	executor := &AnsibleJobExecutor{Client: client, Namespace: "kordex-system", ServiceAccount: "kordex-upgrade-runner", SSHUser: "kordex", SSHCredentialSecret: "kordex-ssh", KnownHostsConfigMap: "kordex-known-hosts", AllowedExecutionEnvironments: []string{"registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64)}}
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.1.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerName: "op-2e15e264-6bc4-4574-8e13-11a135b90e58",
		OwnerUID: types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"), NodeName: "worker-01", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781",
		Address: "10.0.0.10", PlanDigest: digest, Phase: EEPhasePreflight, Policy: policy,
	}
	receipt := &AnsibleReceipt{
		OperationID: request.OperationID, PlanDigest: request.PlanDigest, NodeUID: request.NodeUID,
		MachineID: strings.Repeat("d", 32), BootIDBefore: "33333333-3333-4333-8333-333333333333",
		BootIDAfter: "33333333-3333-4333-8333-333333333333", OSFamily: "debian", KernelVersion: "6.1.0-1-generic", CompletedAt: time.Now().UTC(),
	}
	name, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatalf("prepare EE request: %v", err)
	}
	if err := client.BatchV1().Jobs(executor.Namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("remove completed Job: %v", err)
	}
	if _, err := executor.persistReceipt(ctx, request, name, receipt); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if recoveredName, err := executor.Ensure(ctx, request); err != nil || recoveredName != name {
		t.Fatalf("Ensure did not recover the durable receipt: name=%q err=%v", recoveredName, err)
	}
	observation, err := executor.Observe(ctx, request, name)
	if err != nil {
		t.Fatalf("observe after Job removal: %v", err)
	}
	if observation.Phase != "Succeeded" || observation.Receipt == nil || observation.Receipt.MachineID != receipt.MachineID {
		t.Fatalf("durable receipt was not recovered after Job removal: %+v", observation)
	}
}
