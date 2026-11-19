package main

import (
	"testing"
	"time"

	"kordex.local/api/campaign"
	"kordex.local/api/protocol"
)

func TestSyntheticValidateOnlyReportMatchesDurableActionContract(t *testing.T) {
	now := time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC)
	report := syntheticValidateOnlyReport("22222222-2222-4222-8222-222222222222", now)
	if !report.ValidateForAction(protocol.ValidateOnly) {
		t.Fatal("synthetic ValidateOnly report does not satisfy the operation contract")
	}
	if report.ValidateForAction(protocol.DrainAndVerify) {
		t.Fatal("synthetic ValidateOnly report was accepted as a drain")
	}
	for i := range report.Events {
		if i > 0 && report.Events[i].Time.Before(&report.Events[i-1].Time) {
			t.Fatalf("event %d precedes the prior event", i)
		}
	}
}

func TestSyntheticStagesFitRequestedNodeCount(t *testing.T) {
	for _, test := range []struct {
		nodes int
		want  []int
	}{
		{nodes: 3, want: []int{1, 1, 1, 0}},
		{nodes: 4, want: []int{1, 2, 1, 0}},
		{nodes: 26, want: []int{1, 5, 20, 0}},
		{nodes: 40, want: []int{1, 5, 20, 0}},
	} {
		stages, err := syntheticStages(test.nodes)
		if err != nil {
			t.Fatalf("syntheticStages(%d): %v", test.nodes, err)
		}
		if len(stages) != len(test.want) {
			t.Fatalf("syntheticStages(%d) returned %d stages", test.nodes, len(stages))
		}
		var assigned int
		for i := range stages {
			if stages[i].Count != test.want[i] {
				t.Errorf("syntheticStages(%d)[%d].Count=%d, want %d", test.nodes, i, stages[i].Count, test.want[i])
			}
			assigned += stages[i].Count
		}
		if assigned > test.nodes {
			t.Errorf("syntheticStages(%d) assigns %d explicit nodes", test.nodes, assigned)
		}
		targets := make([]campaign.Target, test.nodes)
		for i := range targets {
			targets[i] = campaign.Target{
				ClusterID:  "22222222-2222-4222-8222-222222222222",
				ClusterUID: "cluster-uid",
				FleetID:    "33333333-3333-4333-8333-333333333333",
				SiteID:     "44444444-4444-4444-8444-444444444444",
				Node:       protocol.Node{Name: "worker", UID: "node-" + string(rune('a'+i))},
			}
		}
		if _, _, err := campaign.Plan(targets, campaign.Spec{Action: protocol.ValidateOnly, Stages: stages}); err != nil {
			t.Errorf("campaign planner rejected %d-node synthetic stages: %v", test.nodes, err)
		}
	}
	if _, err := syntheticStages(2); err == nil {
		t.Fatal("two nodes were accepted without enough nodes for all required rollout stages")
	}
}
