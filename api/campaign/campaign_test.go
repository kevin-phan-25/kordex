package campaign

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
)

func testSpec() Spec {
	return Spec{Name: "test", Action: protocol.ValidateOnly, Policies: []PolicyBinding{{ClusterID: "00000000-0000-4000-8000-000000000001", Policy: protocol.PolicyReference{Name: "safe", UID: "uid", Generation: 1}}}, Windows: []Window{{Start: time.Now().UTC(), End: time.Now().UTC().Add(time.Hour), TimeZone: "UTC"}}}
}
func TestDefaultsAndSafetyValidation(t *testing.T) {
	s, err := testSpec().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if s.ApprovalMode != "AllStages" || s.Limits.Cluster != 1 || !s.Failure.Breached(1, 1, 1) || s.Retry.Allows("AuthorizationExpired", 1) {
		t.Fatal("unsafe defaults")
	}
	for _, mutate := range []func(*Spec){func(s *Spec) { s.Action = protocol.DrainAndVerify; s.ApprovalMode = "None" }, func(s *Spec) { s.Retry.Reasons = []string{"StorageDegraded"} }, func(s *Spec) { s.Limits.Cluster = 2 }, func(s *Spec) { s.RecoveryAction = "IgnorePDB" }} {
		bad := s
		mutate(&bad)
		if _, err := bad.Normalize(); err == nil {
			t.Fatal("unsafe spec accepted")
		}
	}
}

func TestUpgradeCampaignRequiresExactPlanDigest(t *testing.T) {
	plan := protocol.UpgradePolicy{
		SchemaVersion: 1, ID: "ubuntu-workers", OSFamily: "debian", ExecutionBackend: "ansible-ee",
		PlaybookCatalogID:    "kordex.os-upgrade.debian.v2",
		ExecutionEnvironment: "registry.example.com/kordex/ansible-ee@sha256:" + strings.Repeat("a", 64),
		PlaybookDigest:       strings.Repeat("b", 64), CollectionsDigest: strings.Repeat("c", 64),
		Packages: []protocol.PackagePin{{Name: "curl", Version: "8.5.0-1"}}, Channel: "stable", Reboot: protocol.RebootNever,
		ExecutionTimeout: time.Minute, RebootTimeout: time.Minute, VerificationTimeout: time.Minute, MaxAttempts: 1,
	}
	digest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	spec := testSpec()
	spec.Action = protocol.UpgradePackages
	if _, err = spec.Normalize(); err == nil {
		t.Fatal("upgrade campaign without an immutable plan digest was accepted")
	}
	spec.Policies[0].PlanDigest = digest
	if _, err = spec.Normalize(); err != nil {
		t.Fatalf("campaign with exact plan digest was rejected: %v", err)
	}
}
func TestDSTAndWindowBoundaries(t *testing.T) {
	parse := func(s string) time.Time {
		v, e := time.Parse(time.RFC3339, s)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	for _, tc := range []struct {
		start, end string
		valid      bool
	}{
		{"2026-03-08T01:30:00-05:00", "2026-03-08T03:30:00-04:00", true},
		{"2026-03-08T02:30:00-05:00", "2026-03-08T04:00:00-04:00", false},
		{"2026-11-01T01:15:00-04:00", "2026-11-01T01:45:00-04:00", true},
		{"2026-11-01T01:15:00-05:00", "2026-11-01T01:45:00-05:00", true},
	} {
		w := Window{parse(tc.start), parse(tc.end), "America/New_York"}
		if (w.Validate() == nil) != tc.valid {
			t.Fatalf("DST validation: %+v", tc)
		}
		if tc.valid {
			s := Spec{Windows: []Window{w}}
			if _, ok := s.CurrentWindow(w.Start); !ok {
				t.Fatal("start excluded")
			}
			if _, ok := s.CurrentWindow(w.End); ok {
				t.Fatal("end included")
			}
		}
	}
}
func TestDeterministic4000NodePlan(t *testing.T) {
	s, e := testSpec().Normalize()
	if e != nil {
		t.Fatal(e)
	}
	input := make([]Target, 4000)
	for i := range input {
		input[i] = Target{ClusterID: fmt.Sprintf("cluster-%03d", i%100), SiteID: fmt.Sprintf("site-%d", i%4), Node: protocol.Node{UID: fmt.Sprintf("node-%05d", i)}}
	}
	planned, digest, e := Plan(input, s)
	if e != nil {
		t.Fatal(e)
	}
	if len(planned) != 4000 || planned[0].SiteID == planned[1].SiteID || planned[26].Stage != 3 {
		t.Fatal("unbalanced or incorrect stages")
	}
	for i, j := 0, len(input)-1; i < j; i, j = i+1, j-1 {
		input[i], input[j] = input[j], input[i]
	}
	_, again, e := Plan(input, s)
	if e != nil || digest != again {
		t.Fatal("snapshot order nondeterministic")
	}
	s.Selection.Canaries = []NodeReference{{ClusterID: planned[3999].ClusterID, NodeUID: planned[3999].Node.UID}}
	explicit, _, e := Plan(input, s)
	if e != nil || explicit[0].Node.UID != planned[3999].Node.UID {
		t.Fatal("explicit canary ignored")
	}
}

func TestTopologyCanarySelectsOneTargetPerDomain(t *testing.T) {
	spec := testSpec()
	spec.Selection.CanaryTopologyKey = "topology.kubernetes.io/zone"
	normalized, err := spec.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Stages[0].Count != 0 {
		t.Fatal("topology canary count should be derived from the resolved target domains")
	}
	input := []Target{
		{ClusterID: "cluster-a", SiteID: "site-a", Node: protocol.Node{UID: "a1", Zone: "us-central1-a"}},
		{ClusterID: "cluster-a", SiteID: "site-a", Node: protocol.Node{UID: "a2", Zone: "us-central1-a"}},
		{ClusterID: "cluster-a", SiteID: "site-a", Node: protocol.Node{UID: "b1", Zone: "us-central1-b"}},
		{ClusterID: "cluster-a", SiteID: "site-a", Node: protocol.Node{UID: "b2", Zone: "us-central1-b"}},
	}
	planned, _, err := Plan(input, normalized)
	if err != nil {
		t.Fatal(err)
	}
	if planned[0].Stage != 0 || planned[1].Stage != 0 || planned[2].Stage == 0 {
		t.Fatalf("expected two topology canaries followed by later stages: %+v", planned)
	}
	if planned[0].Node.Zone == planned[1].Node.Zone {
		t.Fatalf("canaries share one topology domain: %q", planned[0].Node.Zone)
	}

	tooSmall := normalized
	tooSmall.Stages = append([]Stage(nil), normalized.Stages...)
	tooSmall.Stages[0].Count = 1
	if _, _, err := Plan(input, tooSmall); err == nil {
		t.Fatal("canary stage smaller than topology-domain count was accepted")
	}

	unknown := append([]Target(nil), input...)
	unknown[3].Node.Zone = ""
	if _, _, err := Plan(unknown, normalized); err == nil {
		t.Fatal("missing topology evidence was accepted")
	}
}

func TestTopologyCanariesRejectProviderPoolWideActions(t *testing.T) {
	spec := testSpec()
	spec.Action = protocol.UpgradeNodePool
	spec.Policies[0].PlanDigest = strings.Repeat("a", 64)
	spec.Selection.CanaryTopologyKey = "topology.kubernetes.io/zone"
	if _, err := spec.Normalize(); err == nil {
		t.Fatal("node-pool operation was allowed to claim a single-zone canary")
	}
}

func TestFailureAndRetryBoundaries(t *testing.T) {
	p := FailurePolicy{MaxFailedAttempts: 2, MaxFailurePercent: 25, MinimumSamples: 4, MaxConsecutiveFailures: 1}
	if p.Breached(1, 4, 1) || !p.Breached(2, 4, 1) || !p.Breached(2, 10, 2) {
		t.Fatal("threshold boundaries")
	}
	r := RetryPolicy{MaxRetries: 2, Reasons: []string{"PDBBlocked"}}
	if !r.Allows("PDBBlocked", 2) || r.Allows("PDBBlocked", 3) || r.Allows("QuorumLost", 1) {
		t.Fatal("retry bounds")
	}
}

func TestPlannerRejectsUnnormalizedStages(t *testing.T) {
	if _, _, e := Plan([]Target{{Node: protocol.Node{UID: "node"}}}, Spec{}); e == nil {
		t.Fatal("unnormalized stages accepted")
	}
}
