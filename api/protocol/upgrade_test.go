package protocol

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func validUpgradePolicyForTest() UpgradePolicy {
	return UpgradePolicy{
		SchemaVersion:        1,
		ID:                   "debian-stable",
		OSFamily:             "debian",
		ExecutionBackend:     "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64),
		CollectionsDigest:    strings.Repeat("c", 64),
		Packages:             []PackagePin{{Name: "openssh-server", Version: "1.2.3-1"}},
		Channel:              "stable",
		Reboot:               RebootNever,
		ExecutionTimeout:     time.Minute,
		RebootTimeout:        time.Minute,
		VerificationTimeout:  time.Minute,
		MaxAttempts:          1,
	}
}

func TestUpgradePolicyRejectsUnsupportedCatalogBehavior(t *testing.T) {
	cases := []struct {
		name   string
		change func(*UpgradePolicy)
	}{
		{name: "RHEL catalog not installed", change: func(p *UpgradePolicy) { p.OSFamily = "rhel"; p.PlaybookCatalogID = "kordex.os-upgrade.rhel.v1" }},
		{name: "previous catalog version lacks recovery inspection contract", change: func(p *UpgradePolicy) { p.PlaybookCatalogID = "kordex.os-upgrade.debian.v1" }},
		{name: "pre hooks not installed", change: func(p *UpgradePolicy) { p.PreHooks = []string{"kordex.health-check.v1"} }},
		{name: "post hooks not installed", change: func(p *UpgradePolicy) { p.PostHooks = []string{"kordex.health-check.v1"} }},
		{name: "local retries not implemented", change: func(p *UpgradePolicy) { p.MaxAttempts = 2 }},
		{name: "package names must use Debian canonical lowercase", change: func(p *UpgradePolicy) { p.Packages[0].Name = "OpenSSH-Server" }},
		{name: "kernel package requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-image-generic"; p.Reboot = RebootIfNeeded }},
		{name: "expected kernel requires a kernel package", change: func(p *UpgradePolicy) { p.ExpectedKernelVersion = "6.1.0-1-generic" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := validUpgradePolicyForTest()
			tc.change(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("Validate() accepted unsupported executor behavior")
			}
		})
	}
}

func TestUpgradePolicyDigestIsStableAcrossPackageOrder(t *testing.T) {
	first := validUpgradePolicyForTest()
	first.Packages = append(first.Packages, PackagePin{Name: "curl", Version: "8.1.0-1"})
	second := first
	second.Packages = append([]PackagePin(nil), first.Packages...)
	second.Packages[0], second.Packages[1] = second.Packages[1], second.Packages[0]

	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatalf("digest first policy: %v", err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatalf("digest reordered policy: %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("package order changed digest: %s != %s", firstDigest, secondDigest)
	}
}

func TestUpgradePolicyDigestMatchesAnsibleEECanonicalization(t *testing.T) {
	policy := UpgradePolicy{
		SchemaVersion:         1,
		ID:                    "debian-test",
		OSFamily:              "debian",
		ExecutionBackend:      "ansible-ee",
		PlaybookCatalogID:     "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment:  "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:        strings.Repeat("b", 64),
		CollectionsDigest:     strings.Repeat("c", 64),
		Packages:              []PackagePin{{Name: "linux-image-generic", Version: "6.1.0-1"}},
		ExpectedKernelVersion: "6.1.0-1-generic",
		Channel:               "stable",
		Reboot:                RebootIfNeeded,
		ExecutionTimeout:      time.Minute,
		RebootTimeout:         time.Minute,
		VerificationTimeout:   time.Minute,
		MaxAttempts:           1,
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const pythonDigest = "7b16ebdd2b5d8e7f71938534ed7ae3c77f5d227fca6a4a8ce95d6d05b1fee4d3"
	if digest != pythonDigest {
		t.Fatalf("Go policy digest %s differs from the EE canonical digest %s", digest, pythonDigest)
	}
}

func TestGKEProviderPlanPinsDisruptionSettingsIntoDigest(t *testing.T) {
	plan := ProviderNodeUpgradePlan{
		SchemaVersion: 2, Provider: "gke",
		Resource:      "projects/test-project/locations/us-central1-a/clusters/test-cluster/nodePools/default-pool",
		TargetVersion: "1.36.5-gke.100", MaxSurge: 1, Timeout: 30 * time.Minute,
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatalf("valid GKE plan rejected: %v", err)
	}
	legacy := plan
	legacy.SchemaVersion = 1
	if _, err := legacy.Digest(); err == nil {
		t.Fatal("legacy provider plan schema without disruption binding was accepted")
	}
	changed := plan
	changed.MaxUnavailable = 1
	if _, err := changed.Digest(); err == nil {
		t.Fatal("GKE plan with unavailable nodes was accepted")
	}
	changed = plan
	changed.MaxSurge = 2
	if _, err := changed.Digest(); err == nil {
		t.Fatal("GKE plan with parallel surge above the supported bound was accepted")
	}
	if digest == "" {
		t.Fatal("GKE plan digest is empty")
	}
	unsupported := plan
	unsupported.Provider = "eks"
	if _, err := unsupported.Digest(); err == nil {
		t.Fatal("provider without an installed adapter was accepted as executable")
	}
}

func TestInterruptedRebootRecoveryRequiresInspectionEvidenceForBootChange(t *testing.T) {
	now := time.Now().UTC()
	previous := UpgradeCheckpoint{
		PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", MachineID: strings.Repeat("d", 32),
		BootID: "33333333-3333-4333-8333-333333333333", Phase: UpgradeRecoveryRequired, Sequence: 8, RebootRequested: true,
		InterruptedPhase: "reboot", RecoveryReference: "kordex-ee-op-inspect", Outcome: "Ambiguous", UpdatedAt: metav1.NewTime(now),
	}
	next := previous
	next.Phase = UpgradeVerifyingNode
	next.Sequence++
	next.BootID = "44444444-4444-4444-8444-444444444444"
	next.UpdatedAt = metav1.NewTime(now.Add(time.Second))
	next.Receipts = []UpgradeReceiptEvidence{{
		Phase: "inspect", Reference: "kordex-ee-op-inspect-receipt", Digest: strings.Repeat("c", 64),
		MachineID: previous.MachineID, BootIDBefore: next.BootID, BootIDAfter: next.BootID,
		Packages: map[string]string{"openssh-server": "1.2.3-1"}, CompletedAt: metav1.NewTime(now.Add(time.Second)),
	}}
	if err := ValidateUpgradeCheckpointAdvance(previous, next); err != nil {
		t.Fatalf("valid interrupted reboot inspection rejected: %v", err)
	}
	withoutInspection := next.DeepCopy()
	withoutInspection.Receipts = nil
	if err := ValidateUpgradeCheckpointAdvance(previous, *withoutInspection); err == nil {
		t.Fatal("boot change accepted without a durable inspection receipt")
	}
	wrongPhase := previous
	wrongPhase.InterruptedPhase = "apply"
	nextForApply := *next.DeepCopy()
	nextForApply.InterruptedPhase = "apply"
	if err := ValidateUpgradeCheckpointAdvance(wrongPhase, nextForApply); err == nil {
		t.Fatal("unexpected boot change accepted after an interrupted package apply")
	}
	unchangedBoot := *next.DeepCopy()
	unchangedBoot.BootID = previous.BootID
	unchangedBoot.Receipts[0].BootIDBefore = previous.BootID
	unchangedBoot.Receipts[0].BootIDAfter = previous.BootID
	if err := ValidateUpgradeCheckpointAdvance(previous, unchangedBoot); err == nil {
		t.Fatal("interrupted reboot accepted without changed boot identity")
	}
	pendingReboot := *next.DeepCopy()
	pendingReboot.BootID = previous.BootID
	pendingReboot.Receipts[0].BootIDBefore = previous.BootID
	pendingReboot.Receipts[0].BootIDAfter = previous.BootID
	pendingReboot.Receipts[0].RebootRequired = true
	pendingReboot.InterruptedPhase = "apply"
	applyCheckpoint := previous
	applyCheckpoint.InterruptedPhase = "apply"
	applyCheckpoint.RebootRequested = false
	if err := ValidateUpgradeCheckpointAdvance(applyCheckpoint, pendingReboot); err == nil {
		t.Fatal("recovery accepted package state that still requires reboot")
	}
}

func TestOperationCheckpointAdvanceRejectsReceiptRewriteAndRegression(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	base := UpgradeCheckpoint{PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", BootID: "33333333-3333-4333-8333-333333333333", Phase: UpgradePending, Sequence: 1, UpdatedAt: now}
	preflight := base
	preflight.Phase, preflight.Sequence, preflight.UpdatedAt = UpgradePreflighting, 2, metav1.NewTime(now.Add(time.Second))
	previous := OperationReport{UpgradeCheckpoint: &base}
	next := OperationReport{UpgradeCheckpoint: &preflight}
	if err := ValidateOperationCheckpointAdvance(previous, next); err != nil {
		t.Fatalf("valid checkpoint advance rejected: %v", err)
	}
	missedReports := base
	missedReports.Phase = UpgradeExecuting
	missedReports.Sequence = 5
	missedReports.UpdatedAt = metav1.NewTime(now.Add(4 * time.Second))
	if err := ValidateOperationCheckpointAdvance(previous, OperationReport{UpgradeCheckpoint: &missedReports}); err != nil {
		t.Fatalf("forward-reachable checkpoint after missed agent reports rejected: %v", err)
	}
	regression := preflight
	regression.Phase, regression.Sequence, regression.UpdatedAt = UpgradePending, 3, metav1.NewTime(now.Add(2*time.Second))
	if err := ValidateOperationCheckpointAdvance(next, OperationReport{UpgradeCheckpoint: &regression}); err == nil {
		t.Fatal("checkpoint phase regression accepted")
	}

	withReceipt := preflight
	withReceipt.Phase, withReceipt.Sequence, withReceipt.UpdatedAt = UpgradeCordoning, 3, metav1.NewTime(now.Add(2*time.Second))
	withReceipt.MachineID = strings.Repeat("d", 32)
	withReceipt.Receipts = []UpgradeReceiptEvidence{{
		Phase: "preflight", Reference: "kordex-ee-op-preflight-receipt", Digest: strings.Repeat("b", 64),
		MachineID: withReceipt.MachineID, BootIDBefore: base.BootID, BootIDAfter: base.BootID,
		CompletedAt: metav1.NewTime(now.Add(2 * time.Second)),
	}}
	if err := ValidateOperationCheckpointAdvance(next, OperationReport{UpgradeCheckpoint: &withReceipt}); err != nil {
		t.Fatalf("valid receipt addition rejected: %v", err)
	}
	rewritten := withReceipt.DeepCopy()
	rewritten.Receipts[0].Digest = strings.Repeat("c", 64)
	rewritten.Sequence++
	rewritten.Phase, rewritten.UpdatedAt = UpgradeDraining, metav1.NewTime(now.Add(3*time.Second))
	if err := ValidateOperationCheckpointAdvance(OperationReport{UpgradeCheckpoint: &withReceipt}, OperationReport{UpgradeCheckpoint: rewritten}); err == nil {
		t.Fatal("previously reported immutable receipt was rewritten")
	}
}

func TestProviderCheckpointAdvanceFencesIdentityAndEvidence(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	base := ProviderUpgradeCheckpoint{PlanDigest: strings.Repeat("a", 64), Resource: "projects/p/locations/us-central1/clusters/c/nodePools/pool", TargetVersion: "1.37.1-gke.1", Phase: "Pending", Sequence: 1, UpdatedAt: now}
	next := base
	next.Phase, next.Sequence, next.UpdatedAt = "Submitting", 2, metav1.NewTime(now.Add(time.Second))
	next.InitialVersion = "1.36.4-gke.1"
	next.InitialNodeIdentityDigests = []string{strings.Repeat("b", 64)}
	next.IntentAt = metav1.NewTime(now.Add(time.Second))
	if err := ValidateProviderUpgradeCheckpointAdvance(base, next); err != nil {
		t.Fatalf("valid provider checkpoint advance rejected: %v", err)
	}
	missedReport := next
	missedReport.Phase = "Updating"
	missedReport.Sequence = 4
	missedReport.OperationName = "projects/p/locations/us-central1/operations/op-1"
	missedReport.UpdatedAt = metav1.NewTime(now.Add(3 * time.Second))
	if err := ValidateProviderUpgradeCheckpointAdvance(base, missedReport); err != nil {
		t.Fatalf("forward-reachable provider checkpoint after missed report rejected: %v", err)
	}
	mutated := next
	mutated.Sequence++
	mutated.UpdatedAt = metav1.NewTime(now.Add(2 * time.Second))
	mutated.InitialNodeIdentityDigests = []string{strings.Repeat("c", 64)}
	if err := ValidateProviderUpgradeCheckpointAdvance(next, mutated); err == nil {
		t.Fatal("provider initial node identity evidence rewrite accepted")
	}
	regression := next
	regression.Sequence++
	regression.UpdatedAt = metav1.NewTime(now.Add(2 * time.Second))
	regression.Phase = "Pending"
	if err := ValidateProviderUpgradeCheckpointAdvance(next, regression); err == nil {
		t.Fatal("provider checkpoint phase regression accepted")
	}
}
