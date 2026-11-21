package protocol

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGeneratedOfflineUpgradePolicyContract(t *testing.T) {
	directory := os.Getenv("KORDEX_GENERATED_OFFLINE_POLICY_DIR")
	if directory == "" {
		t.Skip("set KORDEX_GENERATED_OFFLINE_POLICY_DIR to generated offline policy fixtures")
	}
	for _, name := range []string{"maintenance-policy.json", "rhel-policy.json", "offline-artifact-policy.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(directory + string(os.PathSeparator) + name)
			if err != nil {
				t.Fatal(err)
			}
			var object struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Spec       struct {
					Upgrade UpgradePolicy `json:"upgrade"`
				} `json:"spec"`
			}
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatalf("decode generated MaintenancePolicy: %v", err)
			}
			if object.APIVersion != "operations.kordex.local/v1alpha1" || object.Kind != "MaintenancePolicy" {
				t.Fatalf("generated policy identity = %s/%s", object.APIVersion, object.Kind)
			}
			if err := object.Spec.Upgrade.Validate(); err != nil {
				t.Fatalf("generated upgrade plan failed the production protocol validator: %v", err)
			}
			if _, err := object.Spec.Upgrade.Digest(); err != nil {
				t.Fatalf("generated upgrade plan has no canonical digest: %v", err)
			}
		})
	}
}

func validUpgradePolicyForTest() UpgradePolicy {
	return UpgradePolicy{
		SchemaVersion:    1,
		ID:               "debian-stable",
		OSFamily:         "debian",
		OSID:             "ubuntu",
		OSMajor:          "24",
		OSMinor:          "04",
		ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
		{name: "RHEL family cannot use Debian catalog", change: func(p *UpgradePolicy) { p.OSFamily = "rhel" }},
		{name: "previous catalog version lacks recovery inspection contract", change: func(p *UpgradePolicy) { p.PlaybookCatalogID = "kordex.os-upgrade.debian.v1" }},
		{name: "pre hooks not installed", change: func(p *UpgradePolicy) { p.PreHooks = []string{"kordex.health-check.v1"} }},
		{name: "post hooks not installed", change: func(p *UpgradePolicy) { p.PostHooks = []string{"kordex.health-check.v1"} }},
		{name: "local retries not implemented", change: func(p *UpgradePolicy) { p.MaxAttempts = 2 }},
		{name: "package names must use Debian canonical lowercase", change: func(p *UpgradePolicy) { p.Packages[0].Name = "OpenSSH-Server" }},
		{name: "package names cannot contain invalid Debian characters", change: func(p *UpgradePolicy) { p.Packages[0].Name = "openssh_server" }},
		{name: "package versions cannot contain invalid Debian characters", change: func(p *UpgradePolicy) { p.Packages[0].Version = "1.2.3^vendor1" }},
		{name: "kernel package requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-image-generic"; p.Reboot = RebootIfNeeded }},
		{name: "kernel metapackage requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-generic"; p.Reboot = RebootIfNeeded }},
		{name: "multiarch kernel package requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-image-amd64:amd64"; p.Reboot = RebootIfNeeded }},
		{name: "kernel headers package requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-headers-generic"; p.Reboot = RebootIfNeeded }},
		{name: "signed kernel metapackage requires exact expected running version", change: func(p *UpgradePolicy) { p.Packages[0].Name = "linux-signed-amd64"; p.Reboot = RebootIfNeeded }},
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

func TestUpgradePolicyBindsDebianStablePointAndRHELMinor(t *testing.T) {
	debian := validUpgradePolicyForTest()
	debian.OSID, debian.OSMajor, debian.OSMinor = "debian", "13", ""
	debian.OSPointRelease = "13.8"
	if err := debian.Validate(); err != nil {
		t.Fatalf("Debian 13.8 policy rejected: %v", err)
	}
	missing := debian
	missing.OSPointRelease = ""
	if err := missing.Validate(); err == nil {
		t.Fatal("Debian 13 policy without a selected point release was accepted")
	}

	rhel := validUpgradePolicyForTest()
	rhel.OSFamily, rhel.OSID, rhel.OSMajor, rhel.OSMinor, rhel.OSPointRelease = "rhel", "rhel", "9", "9", "9.9"
	rhel.PlaybookCatalogID = "kordex.os-upgrade.rhel.v1"
	if err := rhel.Validate(); err != nil {
		t.Fatalf("RHEL 9.9 policy rejected: %v", err)
	}
	rhel.OSPointRelease = "9.8"
	if err := rhel.Validate(); err == nil {
		t.Fatal("RHEL point release differing from its selected minor was accepted")
	}
}

func TestUpgradePolicyAcceptsRHELFixedCatalog(t *testing.T) {
	policy := validUpgradePolicyForTest()
	policy.ID = "rhel-stable"
	policy.OSFamily = "rhel"
	policy.OSID = "rhel"
	policy.OSMajor = "9"
	policy.OSMinor = "8"
	policy.OSPointRelease = "9.8"
	policy.PlaybookCatalogID = "kordex.os-upgrade.rhel.v1"
	policy.Packages = []PackagePin{{Name: "openssl-libs", Version: "1:3.0.7-27.el9_4"}}
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid RHEL policy rejected: %v", err)
	}
	policy.Packages = []PackagePin{{Name: "kernel-core", Version: "5.14.0-427.13.1.el9_4"}}
	policy.Reboot = RebootIfNeeded
	policy.ExpectedKernelVersion = "5.14.0-427.13.1.el9_4.x86_64"
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid RHEL kernel policy rejected: %v", err)
	}
	policy.PlaybookCatalogID = "kordex.os-upgrade.debian.v2"
	if err := policy.Validate(); err == nil {
		t.Fatal("RHEL policy with Debian catalog was accepted")
	}
}

func TestRHELPackagePinsRequireCompleteRPMRelease(t *testing.T) {
	policy := validUpgradePolicyForTest()
	policy.ID = "rhel-stable"
	policy.OSFamily = "rhel"
	policy.OSID = "rhel"
	policy.OSMajor = "9"
	policy.OSMinor = "8"
	policy.OSPointRelease = "9.8"
	policy.PlaybookCatalogID = "kordex.os-upgrade.rhel.v1"
	for _, version := range []string{"3.0.7", "1:3.0.7", "3.0.7-", "1::3.0.7-27.el9"} {
		t.Run(version, func(t *testing.T) {
			candidate := policy.DeepCopy()
			candidate.Packages = []PackagePin{{Name: "openssl-libs", Version: version}}
			if err := candidate.Validate(); err == nil {
				t.Fatalf("RHEL package version %q was accepted without a complete EVR", version)
			}
		})
	}
	for _, version := range []string{"3.0.7-27.el9_4", "1:3.0.7-27.el9_4"} {
		t.Run("accept-"+version, func(t *testing.T) {
			candidate := policy.DeepCopy()
			candidate.Packages = []PackagePin{{Name: "openssl-libs", Version: version}}
			if err := candidate.Validate(); err != nil {
				t.Fatalf("complete RPM EVR %q rejected: %v", version, err)
			}
		})
	}
}

func TestUpgradePolicyMatchesOnlyKnownMutableOSFamilies(t *testing.T) {
	cases := []struct {
		name    string
		family  string
		image   string
		osLabel string
		want    bool
	}{
		{name: "Ubuntu 24.04 host", family: "debian", image: "Ubuntu 24.04.1 LTS", want: true},
		{name: "Ubuntu 22.04 is unlisted", family: "debian", image: "Ubuntu 22.04.5 LTS", want: false},
		{name: "Debian 13 Trixie host", family: "debian", image: "Debian GNU/Linux 13 (trixie)", want: true},
		{name: "Debian 12 is obsolete", family: "debian", image: "Debian GNU/Linux 12 (bookworm)", want: false},
		{name: "RHEL 9.8 minimum host", family: "rhel", image: "Red Hat Enterprise Linux 9.8", want: true},
		{name: "RHEL 9.9 current host", family: "rhel", image: "Red Hat Enterprise Linux 9.9 (Plow)", want: true},
		{name: "RHEL 9.7 below floor", family: "rhel", image: "Red Hat Enterprise Linux 9.7", want: false},
		{name: "Rocky is not RHEL evidence", family: "rhel", image: "Rocky Linux 9.9", want: false},
		{name: "Alma is not RHEL evidence", family: "rhel", image: "AlmaLinux 9.9", want: false},
		{name: "Amazon Linux 2023 host", family: "rhel", image: "Amazon Linux 2023.7.20251020", want: true},
		{name: "Amazon Linux 2 is not qualified", family: "rhel", image: "Amazon Linux 2", want: false},
		{name: "Amazon Linux preview release is not qualified", family: "rhel", image: "Amazon Linux 2027 Preview", want: false},
		{name: "CentOS is unsupported", family: "rhel", image: "CentOS Stream 9", want: false},
		{name: "Oracle Linux is unsupported", family: "rhel", image: "Oracle Linux Server 9.5", want: false},
		{name: "Fedora is unsupported", family: "rhel", image: "Fedora Linux 42", want: false},
		{name: "wrong family", family: "debian", image: "Rocky Linux 9.5", want: false},
		{name: "GKE COS", family: "debian", image: "Container-Optimized OS from Google", want: false},
		{name: "CoreOS derivative", family: "rhel", image: "Red Hat Enterprise Linux CoreOS", want: false},
		{name: "unknown image", family: "debian", image: "", want: false},
		{name: "Windows label", family: "debian", image: "Ubuntu 24.04", osLabel: "windows", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := UpgradePolicy{OSFamily: tc.family, OSMajor: "24", OSMinor: "04", OSID: "ubuntu"}
			if tc.family == "rhel" {
				policy.OSID, policy.OSMajor, policy.OSMinor = "rhel", "9", "8"
			}
			switch tc.image {
			case "Debian GNU/Linux 13 (trixie)", "Debian GNU/Linux 12 (bookworm)":
				policy.OSID, policy.OSMajor, policy.OSMinor = "debian", strings.Fields(tc.image)[2], ""
			case "Red Hat Enterprise Linux 9.9 (Plow)":
				policy.OSMinor = "9"
			case "Amazon Linux 2023.7.20251020":
				policy.OSID, policy.OSMajor, policy.OSMinor = "amzn", "2023", ""
			}
			node := Node{OSImage: tc.image, Labels: map[string]string{"kubernetes.io/os": tc.osLabel}}
			if got := policy.MatchesNodeOS(node); got != tc.want {
				t.Fatalf("MatchesNodeOS(%q, %q)=%t, want %t", tc.family, tc.image, got, tc.want)
			}
		})
	}
}

func TestUpgradePolicyOSReleaseAllowlist(t *testing.T) {
	cases := []struct {
		id, major, minor, family string
		want                     bool
	}{
		{"ubuntu", "24", "04", "debian", true},
		{"ubuntu", "22", "04", "debian", false},
		{"debian", "12", "", "debian", false},
		{"debian", "13", "", "debian", true},
		{"rhel", "9", "8", "rhel", true},
		{"rhel", "9", "9", "rhel", true},
		{"rhel", "9", "7", "rhel", false},
		{"rocky", "9", "9", "rhel", false},
		{"almalinux", "9", "9", "rhel", false},
		{"amzn", "2023", "", "rhel", true},
		{"amzn", "2", "", "rhel", false},
		{"centos", "9", "", "rhel", false},
		{"oracle", "9", "5", "rhel", false},
		{"fedora", "42", "", "rhel", false},
	}
	for _, tc := range cases {
		t.Run(tc.id+"-"+tc.major+"."+tc.minor, func(t *testing.T) {
			policy := validUpgradePolicyForTest()
			policy.OSID, policy.OSMajor, policy.OSMinor, policy.OSFamily = tc.id, tc.major, tc.minor, tc.family
			if tc.id == "debian" && tc.major == "13" {
				policy.OSPointRelease = "13.8"
			}
			if tc.family == "rhel" {
				policy.PlaybookCatalogID = "kordex.os-upgrade.rhel.v1"
				if tc.id == "rhel" {
					policy.OSPointRelease = "9." + tc.minor
				}
				policy.Packages = []PackagePin{{Name: "openssl-libs", Version: "1:3.0.7-1.el9"}}
			}
			err := policy.Validate()
			if (err == nil) != tc.want {
				t.Fatalf("Validate() error = %v, want accepted=%t", err, tc.want)
			}
		})
	}
}

func TestUpgradePolicyAcceptsDebianMultiarchPackageName(t *testing.T) {
	policy := validUpgradePolicyForTest()
	policy.Packages[0].Name = "libc6:amd64"
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid Debian multiarch package name rejected: %v", err)
	}
}

func TestUpgradePolicyAcceptsDebianEpochVersion(t *testing.T) {
	policy := validUpgradePolicyForTest()
	policy.Packages[0].Name = "libc6:amd64"
	policy.Packages[0].Version = "2:2.36-9"
	if err := policy.Validate(); err != nil {
		t.Fatalf("valid Debian epoch version rejected: %v", err)
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

func TestUpgradePolicyDigestBindsNormalizedOSIdentity(t *testing.T) {
	policy := validUpgradePolicyForTest()
	first, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	policy.OSID, policy.OSMajor, policy.OSMinor = "debian", "13", ""
	policy.OSPointRelease = "13.8"
	second, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changing the normalized OS identity did not change the signed plan digest")
	}
}

func TestUpgradePolicyRequiresActionMarkerVersionOne(t *testing.T) {
	marked := validUpgradePolicyForTest()
	if _, err := marked.Digest(); err != nil {
		t.Fatalf("marker-enabled upgrade policy rejected: %v", err)
	}
	for _, version := range []int{0, 2} {
		invalid := marked
		invalid.ActionMarkerVersion = version
		if err := invalid.Validate(); err == nil {
			t.Fatalf("action marker version %d was accepted", version)
		}
	}
}

func TestOfflineArtifactPolicyRequiresAndBindsPackageDigests(t *testing.T) {
	policy := validUpgradePolicyForTest()
	policy.SchemaVersion = 2
	policy.ArtifactMode = "OfflineArtifacts"
	policy.Packages[0].ArtifactSHA256 = strings.Repeat("d", 64)
	firstDigest, err := policy.Digest()
	if err != nil {
		t.Fatalf("valid offline artifact policy rejected: %v", err)
	}
	changedArtifact := policy
	changedArtifact.Packages = append([]PackagePin(nil), policy.Packages...)
	changedArtifact.Packages[0].ArtifactSHA256 = strings.Repeat("e", 64)
	secondDigest, err := changedArtifact.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("offline artifact digest was not bound into the upgrade plan")
	}

	missingDigest := policy
	missingDigest.Packages = append([]PackagePin(nil), policy.Packages...)
	missingDigest.Packages[0].ArtifactSHA256 = ""
	if err := missingDigest.Validate(); err == nil {
		t.Fatal("offline policy without package artifact digest was accepted")
	}
	legacyWithArtifact := validUpgradePolicyForTest()
	legacyWithArtifact.Packages[0].ArtifactSHA256 = strings.Repeat("d", 64)
	if err := legacyWithArtifact.Validate(); err == nil {
		t.Fatal("repository-backed schema v1 policy accepted an unbound artifact digest")
	}
}

func TestUpgradePolicyDigestMatchesAnsibleEECanonicalization(t *testing.T) {
	policy := UpgradePolicy{
		SchemaVersion:    1,
		ID:               "debian-test",
		OSFamily:         "debian",
		OSID:             "ubuntu",
		OSMajor:          "24",
		OSMinor:          "04",
		ExecutionBackend: "ansible-ee", ActionMarkerVersion: 1,
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
	const pythonDigest = "1ad972c1cfc0681edf80294551d0902f0088177cc2b3ecf31336ed92480188a1"
	if digest != pythonDigest {
		t.Fatalf("Go policy digest %s differs from the EE canonical digest %s", digest, pythonDigest)
	}
	offline := UpgradePolicy{
		SchemaVersion: 2, ID: "offline-test", OSFamily: "debian", OSID: "ubuntu", OSMajor: "24", OSMinor: "04", ExecutionBackend: "ansible-ee",
		ActionMarkerVersion: 1, ArtifactMode: "OfflineArtifacts", PlaybookCatalogID: "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment: "registry.example/kordex/ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []PackagePin{{Name: "openssh-server", Version: "1.2.3-1", ArtifactSHA256: strings.Repeat("d", 64)}},
		Channel:  "stable", Reboot: RebootNever, ExecutionTimeout: time.Minute, RebootTimeout: time.Minute,
		VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	offlineDigest, err := offline.Digest()
	if err != nil {
		t.Fatal(err)
	}
	const pythonOfflineDigest = "b1e50563c39630695bf824faf28a46a436a0638c21a18d3ed498125ff561a986"
	if offlineDigest != pythonOfflineDigest {
		t.Fatalf("Go offline policy digest %s differs from the EE canonical digest %s", offlineDigest, pythonOfflineDigest)
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
		InterruptedPhase: "reboot", RecoveryReference: "kordex-ee-op-inspect", RecoveryAttempt: 1, RecoveryTrustDigest: strings.Repeat("b", 64), Outcome: "Ambiguous", UpdatedAt: metav1.NewTime(now),
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

func TestRecoveryInspectionRetryRequiresNewReferenceAndUUIDTokenWhenTrustIsUnchanged(t *testing.T) {
	now := metav1.NewTime(time.Now().UTC())
	previous := UpgradeCheckpoint{
		PlanDigest: strings.Repeat("a", 64), NodeUID: "node-uid", MachineID: strings.Repeat("d", 32),
		BootID: "33333333-3333-4333-8333-333333333333", Phase: UpgradeRecoveryRequired, Sequence: 3,
		InterruptedPhase: "apply", RecoveryReference: "inspection-attempt-1", RecoveryAttempt: 1,
		RecoveryTrustDigest: strings.Repeat("b", 64), UpdatedAt: now,
	}
	next := previous
	next.Sequence++
	next.UpdatedAt = metav1.NewTime(now.Add(time.Second))
	next.RecoveryReference = "inspection-attempt-2"
	next.RecoveryAttempt = 2
	next.RecoveryRetryToken = "11111111-2222-4333-8444-555555555555"
	if err := ValidateUpgradeCheckpointAdvance(previous, next); err != nil {
		t.Fatalf("valid operator-authorized same-trust retry rejected: %v", err)
	}
	reused := next
	reused.Sequence++
	reused.UpdatedAt = metav1.NewTime(now.Add(2 * time.Second))
	reused.RecoveryReference = "inspection-attempt-3"
	reused.RecoveryAttempt = 3
	if err := ValidateUpgradeCheckpointAdvance(next, reused); err == nil {
		t.Fatal("same retry token authorized a second same-trust inspection")
	}
	invalid := next
	invalid.RecoveryRetryToken = "not-a-uuid"
	if err := ValidateUpgradeCheckpoint(invalid); err == nil {
		t.Fatal("invalid recovery retry token was accepted")
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
