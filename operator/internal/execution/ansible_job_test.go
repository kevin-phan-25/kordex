package execution

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"kordex.local/api/protocol"
)

func TestRecoveryInspectionRetriesUseImmutableTrustSnapshots(t *testing.T) {
	ctx := context.Background()
	knownHosts := "worker-01 ssh-ed25519 AAAAinitial"
	privateKey := []byte("initial-private-key")
	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kordex-system", Name: "kordex-known-hosts"}, Data: map[string]string{"known_hosts": knownHosts}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "kordex-system", Name: "kordex-ssh"}, Data: map[string][]byte{"id_ed25519": privateKey}},
	)
	executor := &AnsibleJobExecutor{Client: client, Namespace: "kordex-system", ServiceAccount: "kordex-upgrade-runner", SSHUser: "kordex", SSHCredentialSecret: "kordex-ssh", KnownHostsConfigMap: "kordex-known-hosts", AllowedExecutionEnvironments: []string{"registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64)}}
	policy := protocol.UpgradePolicy{SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1, PlaybookCatalogID: "kordex.os-upgrade.debian.v2", ExecutionEnvironment: executor.AllowedExecutionEnvironments[0], PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64), Packages: []protocol.PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}}, Channel: "stable", Reboot: protocol.RebootNever, ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1}
	planDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	trustDigest := func(hosts string, key []byte) string { return recoveryInputDigest(hosts, key) }
	request := AnsibleJobRequest{OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerName: "op-2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerUID: types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"), NodeName: "worker-01", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781", Address: "10.0.0.10", MachineID: strings.Repeat("d", 32), BootID: "9c89fa16-3838-4b38-9c4f-415a5de14904", PlanDigest: planDigest, Phase: EEPhaseInspect, RecoveryAttempt: 1, RecoveryTrustDigest: trustDigest(knownHosts, privateKey), Policy: policy}
	firstReference, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatalf("ensure initial recovery inspection: %v", err)
	}
	if firstReference != AnsibleInspectionReference(request.OperationID, request.RecoveryTrustDigest) {
		t.Fatalf("initial inspection reference = %q", firstReference)
	}
	firstJob, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, firstReference, metav1.GetOptions{})
	if err != nil || executor.verifyEEJobIdentity(firstJob, request) != nil {
		t.Fatalf("initial inspection Job identity was not pinned: job=%v err=%v", firstJob, err)
	}
	firstSnapshotName := recoveryKnownHostsSnapshotName(firstReference)
	firstSnapshot, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, firstSnapshotName, metav1.GetOptions{})
	if err != nil || firstSnapshot.Immutable == nil || !*firstSnapshot.Immutable || firstSnapshot.Data["known_hosts"] != knownHosts {
		t.Fatalf("initial known-hosts snapshot is not immutable and exact: snapshot=%v err=%v", firstSnapshot, err)
	}
	updatedKnownHosts := "worker-01 ssh-ed25519 AAAArotated"
	source, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, executor.KnownHostsConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source.Data["known_hosts"] = updatedKnownHosts
	if _, err := client.CoreV1().ConfigMaps(executor.Namespace).Update(ctx, source, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	privateKey = []byte("rotated-private-key")
	ssh, err := client.CoreV1().Secrets(executor.Namespace).Get(ctx, executor.SSHCredentialSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ssh.Data["id_ed25519"] = privateKey
	if _, err := client.CoreV1().Secrets(executor.Namespace).Update(ctx, ssh, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if observedReference, err := executor.Ensure(ctx, request); err != nil || observedReference != firstReference {
		t.Fatalf("trust rotation mutated or replaced the persisted attempt: reference=%q err=%v", observedReference, err)
	}
	request.RecoveryAttempt = 2
	request.RecoveryTrustDigest = trustDigest(updatedKnownHosts, privateKey)
	secondReference, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatalf("ensure corrected-trust recovery inspection: %v", err)
	}
	if secondReference == firstReference {
		t.Fatal("corrected trust reused the failed inspection identity")
	}
	secondJob, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, secondReference, metav1.GetOptions{})
	if err != nil || secondJob.Annotations[eeTrustAnnotation] != request.RecoveryTrustDigest || secondJob.Spec.Template.Spec.Volumes[1].Secret.SecretName != executor.SSHCredentialSecret {
		t.Fatalf("retry identity did not bind updated SSH inputs: job=%v err=%v", secondJob, err)
	}
	secondSnapshot, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, recoveryKnownHostsSnapshotName(secondReference), metav1.GetOptions{})
	if err != nil || secondSnapshot.Data["known_hosts"] != updatedKnownHosts || secondSnapshot.Immutable == nil || !*secondSnapshot.Immutable {
		t.Fatalf("retry did not use a new immutable trust snapshot: snapshot=%v err=%v", secondSnapshot, err)
	}
	firstSnapshotAfter, err := client.CoreV1().ConfigMaps(executor.Namespace).Get(ctx, firstSnapshotName, metav1.GetOptions{})
	if err != nil || firstSnapshotAfter.Data["known_hosts"] != knownHosts {
		t.Fatalf("retry rewrote the prior trust snapshot: snapshot=%v err=%v", firstSnapshotAfter, err)
	}
	if _, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, firstReference, metav1.GetOptions{}); err != nil {
		t.Fatalf("retry removed the prior inspection Job: %v", err)
	}
}

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
		SchemaVersion:    1,
		ID:               "debian-test",
		OSFamily:         "debian",
		ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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

func TestEEFailureReasonUsesOnlyKnownStructuredCodes(t *testing.T) {
	if got := eeFailureReason("other log\nKORDEX_EE_ERROR=SSHHostKeyVerificationFailed\n"); got != "SSHHostKeyVerificationFailed" {
		t.Fatalf("host key failure reason = %q", got)
	}
	if got := eeFailureReason("KORDEX_EE_ERROR=ExecutionInterruptedAmbiguous"); got != "ExecutionInterruptedAmbiguous" {
		t.Fatalf("termination interruption reason = %q", got)
	}
	if got := eeFailureReason("KORDEX_EE_ERROR=arbitrary user supplied text"); got != "ExecutionJobFailed" {
		t.Fatalf("unrecognized failure text was exposed as reason %q", got)
	}
}

func TestFailedJobReasonReadsContainerTerminationMessage(t *testing.T) {
	ctx := context.Background()
	client := fake.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kordex-system", Labels: map[string]string{eeJobLabel: "job-1"}},
		Status: corev1.PodStatus{Phase: corev1.PodFailed, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "ansible-ee", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Message: "KORDEX_EE_ERROR=SSHHostKeyVerificationFailed"}},
		}}},
	})
	executor := &AnsibleJobExecutor{Client: client, Namespace: "kordex-system"}
	if got := executor.failedJobReason(ctx, "job-1"); got != "SSHHostKeyVerificationFailed" {
		t.Fatalf("failed job reason = %q", got)
	}
}

func TestMarkedApplyReceiptRequiresHostMarkerBoundToPlan(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781",
		MachineID: strings.Repeat("d", 32), BootID: "33333333-3333-4333-8333-333333333333", PlanDigest: digest,
		Phase: EEPhaseApply, Policy: policy,
	}
	receipt := &AnsibleReceipt{
		OperationID: request.OperationID, PlanDigest: digest, NodeUID: request.NodeUID, MachineID: request.MachineID,
		BootIDBefore: request.BootID, BootIDAfter: request.BootID, OSFamily: "debian", KernelVersion: "6.1.0-1-generic",
		Packages: map[string]string{"curl": "8.1.0-1"}, CompletedAt: time.Now().UTC(),
		ActionMarker: &protocol.ActionMarkerEvidence{
			Version: 1, OperationID: request.OperationID, ActionDigest: digest, NodeUID: request.NodeUID,
			MachineID: request.MachineID, BootID: request.BootID, Phase: "packages-verified", Sequence: 2, SHA256: strings.Repeat("e", 64),
		},
	}
	if err := validateReceipt(request, receipt, time.Time{}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("valid marked apply receipt rejected: %v", err)
	}
	receipt.ActionMarker.ActionDigest = strings.Repeat("f", 64)
	if err := validateReceipt(request, receipt, time.Time{}, time.Now().Add(time.Minute)); err == nil {
		t.Fatal("receipt marker for another plan was accepted")
	}
}

func TestAnsibleJobRequestsRequirePreflightIdentityForMutatingPhases(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
	for _, address := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1", "::", "::ffff:127.0.0.1", "::ffff:169.254.169.254"} {
		request.Address = address
		if err := validateEERequest(request); err == nil {
			t.Errorf("unsafe target address %q was accepted", address)
		}
	}
	request.Address = "fd12:3456:789a::10"
	if err := validateEERequest(request); err != nil {
		t.Fatalf("valid IPv6 ULA node address rejected: %v", err)
	}
	request.Address = "10.0.0.10"
	request.NodeName = "worker-01\nansible_host=192.0.2.1"
	if err := validateEERequest(request); err == nil {
		t.Fatal("node name with inventory syntax was accepted")
	}
	request.NodeName = "worker-01"
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

func TestValidateEERequestAcceptsRHELFixedCatalog(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "rhel-stable", OSFamily: "rhel", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
		PlaybookCatalogID: "kordex.os-upgrade.rhel.v1", ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest: strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages:              []protocol.PackagePin{{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4"}},
		ExpectedKernelVersion: "5.14.0-427.13.1.el9_4.x86_64", Channel: "stable", Reboot: protocol.RebootIfNeeded,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := AnsibleJobRequest{
		OperationID: "2e15e264-6bc4-4574-8e13-11a135b90e58", OwnerName: "op-2e15e264-6bc4-4574-8e13-11a135b90e58",
		OwnerUID: types.UID("b9fdd230-06be-4a45-8b7e-88e5fa25669e"), NodeName: "worker-01",
		NodeUID: "00c85ae4-f827-42c8-b43b-b1b0085b1781", Address: "10.0.0.10", PlanDigest: digest, Policy: policy, Phase: EEPhasePreflight,
	}
	if err := validateEERequest(request); err != nil {
		t.Fatalf("valid RHEL preflight rejected: %v", err)
	}
	request.Policy.PlaybookCatalogID = "kordex.os-upgrade.debian.v2"
	if err := validateEERequest(request); err == nil {
		t.Fatal("RHEL plan with Debian catalog was accepted")
	}
}

func TestReadOnlyInspectionReceiptMayObserveChangedBootID(t *testing.T) {
	policy := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
		SchemaVersion: 1, ID: "kernel-plan", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
		ActionMarker: &protocol.ActionMarkerEvidence{Version: 1, OperationID: request.OperationID, ActionDigest: digest, NodeUID: request.NodeUID,
			MachineID: request.MachineID, BootID: "44444444-4444-4444-8444-444444444444", Phase: "reboot-verified", Sequence: 4, SHA256: strings.Repeat("f", 64)},
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
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
	broadPolicy := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: executor.Namespace, Name: "namespace-egress"}, Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{}, Egress: []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{{}}}},
	}}
	if _, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Create(ctx, broadPolicy, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create broad overlapping policy fixture: %v", err)
	}
	if _, err := executor.Ensure(ctx, request); err == nil || !strings.Contains(err.Error(), "also allows egress") {
		t.Fatalf("EE job was accepted alongside a broad egress policy: %v", err)
	}
	if _, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Get(ctx, eeNetworkPolicyName(eeJobName(request.OperationID, request.Phase)), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("created target policy despite overlapping allow policy: %v", err)
	}
	if err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Delete(ctx, broadPolicy.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("remove broad policy fixture: %v", err)
	}
	unrelatedPolicy := broadPolicy.DeepCopy()
	unrelatedPolicy.Name = "other-pods-egress"
	unrelatedPolicy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}
	if _, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Create(ctx, unrelatedPolicy, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create unrelated egress policy fixture: %v", err)
	}
	name, err := executor.Ensure(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	job, err := client.BatchV1().Jobs(executor.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || job.Spec.Suspend == nil || !*job.Spec.Suspend {
		t.Fatal("Ansible EE job was not durably prepared in suspended state")
	}
	networkPolicy, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Get(ctx, eeNetworkPolicyName(name), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read prepared Ansible EE network policy: %v", err)
	}
	if networkPolicy.Spec.PodSelector.MatchLabels[eeJobLabel] != name || len(networkPolicy.Spec.PolicyTypes) != 2 || networkPolicy.Spec.PolicyTypes[0] != "Ingress" || networkPolicy.Spec.PolicyTypes[1] != "Egress" || len(networkPolicy.Spec.Ingress) != 0 || len(networkPolicy.Spec.Egress) != 1 {
		t.Fatalf("Ansible EE policy is not isolated to the execution pod: %+v", networkPolicy.Spec)
	}
	egress := networkPolicy.Spec.Egress[0]
	if len(egress.To) != 1 || egress.To[0].IPBlock == nil || egress.To[0].IPBlock.CIDR != "10.0.0.10/32" || len(egress.Ports) != 1 || egress.Ports[0].Port == nil || egress.Ports[0].Port.IntValue() != 22 || egress.Ports[0].Protocol == nil || *egress.Ports[0].Protocol != corev1.ProtocolTCP {
		t.Fatalf("Ansible EE egress is not limited to target SSH: %+v", egress)
	}
	activePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: executor.Namespace, Name: name + "-pod", Labels: map[string]string{eeJobLabel: name}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if _, err := client.CoreV1().Pods(executor.Namespace).Create(ctx, activePod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create active EE pod fixture: %v", err)
	}
	executor.removeEgressNetworkPolicyWhenIdle(ctx, request, name)
	if _, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Get(ctx, eeNetworkPolicyName(name), metav1.GetOptions{}); err != nil {
		t.Fatalf("active EE pod lost its egress policy: %v", err)
	}
	if err := client.CoreV1().Pods(executor.Namespace).Delete(ctx, activePod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete active EE pod fixture: %v", err)
	}
	if len(job.Spec.Template.Spec.ImagePullSecrets) != 1 || job.Spec.Template.Spec.ImagePullSecrets[0].Name != "registry-auth" {
		t.Fatalf("private registry pull secret not configured on Job: %+v", job.Spec.Template.Spec.ImagePullSecrets)
	}
	jobPod := job.Spec.Template.Spec
	if jobPod.HostNetwork || jobPod.HostPID || jobPod.HostIPC || jobPod.ShareProcessNamespace == nil || *jobPod.ShareProcessNamespace || jobPod.EnableServiceLinks == nil || *jobPod.EnableServiceLinks || jobPod.DNSPolicy != corev1.DNSClusterFirst {
		t.Fatalf("Ansible EE Job has unexpected host/network namespace settings: %+v", jobPod)
	}
	if jobPod.AutomountServiceAccountToken == nil || *jobPod.AutomountServiceAccountToken {
		t.Fatal("Ansible EE Job can receive a Kubernetes service account token")
	}
	if job.Spec.Template.Spec.Containers[0].TerminationMessagePolicy != corev1.TerminationMessageFallbackToLogsOnError {
		t.Fatal("failed EE container is not configured to expose its structured error code")
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
	networkPolicy.Spec.Egress[0].To = []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}}}
	if _, err = client.NetworkingV1().NetworkPolicies(executor.Namespace).Update(ctx, networkPolicy, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("mutate test egress policy: %v", err)
	}
	if err = executor.Start(ctx, request, name); !errors.Is(err, ErrExecutionIdentity) {
		t.Fatalf("activated Job after egress policy widened: %v", err)
	}
	networkPolicy.Spec.Egress[0] = egress
	if _, err = client.NetworkingV1().NetworkPolicies(executor.Namespace).Update(ctx, networkPolicy, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("restore test egress policy: %v", err)
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
		SchemaVersion: 1, ID: "debian-test", OSFamily: "debian", ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
	if _, err := client.NetworkingV1().NetworkPolicies(executor.Namespace).Get(ctx, eeNetworkPolicyName(name), metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("idle completed execution retained egress policy: %v", err)
	}
}
