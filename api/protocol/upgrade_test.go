package protocol

import (
	"strings"
	"testing"
	"time"
)

func validUpgradePolicyForTest() UpgradePolicy {
	return UpgradePolicy{
		SchemaVersion:        1,
		ID:                   "debian-stable",
		OSFamily:             "debian",
		ExecutionBackend:     "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v1",
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
		{name: "pre hooks not installed", change: func(p *UpgradePolicy) { p.PreHooks = []string{"kordex.health-check.v1"} }},
		{name: "post hooks not installed", change: func(p *UpgradePolicy) { p.PostHooks = []string{"kordex.health-check.v1"} }},
		{name: "local retries not implemented", change: func(p *UpgradePolicy) { p.MaxAttempts = 2 }},
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
