// Package campaign owns campaign contracts and deterministic rollout decisions.
package campaign

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"

	"kordex.local/api/protocol"
)

const Version = "1"
const MaxTargets = 10000
const UpgradeFleet = "UpgradeFleet"

var stageNames = [...]string{"Canary", "SmallBatch", "Expanded", "Remaining"}

type Selection struct {
	ClusterIDs   []string        `json:"clusterIds"`
	FleetIDs     []string        `json:"fleetIds"`
	SiteIDs      []string        `json:"siteIds"`
	NodeSelector string          `json:"nodeSelector"`
	Canaries     []NodeReference `json:"canaries"`
	// CanaryTopologyKey selects one automatic canary target per observed
	// site/cluster/topology value. Empty preserves the normal site/cluster spread.
	CanaryTopologyKey string `json:"canaryTopologyKey,omitempty"`
}
type NodeReference struct {
	ClusterID string `json:"clusterId"`
	NodeUID   string `json:"nodeUid"`
}
type PolicyBinding struct {
	ClusterID  string                   `json:"clusterId"`
	Policy     protocol.PolicyReference `json:"policy"`
	PlanDigest string                   `json:"planDigest,omitempty"`
}
type Window struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	TimeZone string    `json:"timeZone"`
}
type Stage struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	BatchSize int    `json:"batchSize"`
}
type Limits struct {
	Organization          int `json:"organization"`
	Fleet                 int `json:"fleet"`
	Site                  int `json:"site"`
	Cluster               int `json:"cluster"`
	Node                  int `json:"node"`
	MaxUnavailablePerSite int `json:"maxUnavailablePerSite"`
}

func DefaultLimits() Limits { return Limits{1, 1, 1, 1, 1, 1} }
func (l Limits) Validate() error {
	if l.Organization < 1 || l.Organization > 1000 || l.Fleet < 1 || l.Fleet > 1000 || l.Site < 1 || l.Site > 1000 || l.Cluster != 1 || l.Node != 1 || l.MaxUnavailablePerSite < 1 || l.MaxUnavailablePerSite > 1000 {
		return fmt.Errorf("invalid concurrency limits; cluster and node limits must be one")
	}
	return nil
}

type RetryPolicy struct {
	MaxRetries     int      `json:"maxRetries"`
	BackoffSeconds int      `json:"backoffSeconds"`
	Reasons        []string `json:"reasons"`
}
type FailurePolicy struct {
	MaxFailedAttempts      int `json:"maxFailedAttempts"`
	MaxFailurePercent      int `json:"maxFailurePercent"`
	MinimumSamples         int `json:"minimumSamples"`
	MaxConsecutiveFailures int `json:"maxConsecutiveFailures"`
}
type Spec struct {
	Name                 string          `json:"name"`
	Action               string          `json:"action"`
	Selection            Selection       `json:"selection"`
	Policies             []PolicyBinding `json:"policies"`
	Windows              []Window        `json:"windows"`
	Stages               []Stage         `json:"stages"`
	Limits               Limits          `json:"limits"`
	ApprovalMode         string          `json:"approvalMode"`
	Retry                RetryPolicy     `json:"retry"`
	Failure              FailurePolicy   `json:"failure"`
	MinimumWindowSeconds int             `json:"minimumWindowSeconds"`
	RecoveryAction       string          `json:"recoveryAction"`
}

func (s Spec) Normalize() (Spec, error) {
	s.Selection.ClusterIDs = slices.Clone(s.Selection.ClusterIDs)
	s.Selection.FleetIDs = slices.Clone(s.Selection.FleetIDs)
	s.Selection.SiteIDs = slices.Clone(s.Selection.SiteIDs)
	s.Selection.Canaries = slices.Clone(s.Selection.Canaries)
	s.Policies = slices.Clone(s.Policies)
	s.Windows = slices.Clone(s.Windows)
	s.Stages = slices.Clone(s.Stages)
	s.Retry.Reasons = slices.Clone(s.Retry.Reasons)

	if s.Selection.ClusterIDs == nil {
		s.Selection.ClusterIDs = []string{}
	}
	if s.Selection.FleetIDs == nil {
		s.Selection.FleetIDs = []string{}
	}
	if s.Selection.SiteIDs == nil {
		s.Selection.SiteIDs = []string{}
	}
	if s.Selection.Canaries == nil {
		s.Selection.Canaries = []NodeReference{}
	}

	if strings.TrimSpace(s.Name) != s.Name || s.Name == "" || len(s.Name) > 128 {
		return s, fmt.Errorf("invalid campaign name")
	}
	if s.Action != protocol.ValidateOnly && s.Action != protocol.DrainAndVerify && s.Action != protocol.UpgradePackages && s.Action != protocol.UpgradeNodePool && s.Action != UpgradeFleet {
		return s, fmt.Errorf("unsupported action")
	}
	if len(s.Selection.ClusterIDs) > 500 || len(s.Selection.FleetIDs) > 500 || len(s.Selection.SiteIDs) > 500 || len(s.Selection.NodeSelector) > 2048 {
		return s, fmt.Errorf("selection too large")
	}
	for _, list := range [][]string{s.Selection.ClusterIDs, s.Selection.FleetIDs, s.Selection.SiteIDs} {
		seen := map[string]bool{}
		for _, id := range list {
			if !protocol.ValidUUID(id) || seen[id] {
				return s, fmt.Errorf("invalid or duplicate target scope")
			}
			seen[id] = true
		}
		sort.Strings(list)
	}
	if _, err := labels.Parse(s.Selection.NodeSelector); err != nil {
		return s, fmt.Errorf("invalid node selector")
	}
	if s.Selection.CanaryTopologyKey != "" && len(validation.IsQualifiedName(s.Selection.CanaryTopologyKey)) != 0 {
		return s, fmt.Errorf("invalid canary topology label key")
	}
	if len(s.Policies) == 0 || len(s.Policies) > 500 {
		return s, fmt.Errorf("one policy binding per selected cluster is required")
	}
	seen := map[string]bool{}
	for _, binding := range s.Policies {
		action := s.Action
		if action == UpgradeFleet {
			// Fleet campaigns resolve a concrete executor and digest from each
			// target node's fresh local catalog. An optional digest still pins one
			// exact plan for callers that need a deliberately constrained rollout.
			if binding.PlanDigest == "" {
				action = protocol.ValidateOnly
			} else {
				action = protocol.UpgradePackages
			}
		}
		request := protocol.MaintenanceRequest{OperationID: "00000000-0000-4000-8000-000000000001", NodeName: "validation", NodeUID: "validation", Policy: binding.Policy, Action: action, PlanDigest: binding.PlanDigest}
		if !protocol.ValidUUID(binding.ClusterID) || seen[binding.ClusterID] || request.Validate() != nil {
			return s, fmt.Errorf("invalid or duplicate policy binding")
		}
		seen[binding.ClusterID] = true
	}
	sort.Slice(s.Policies, func(i, j int) bool { return s.Policies[i].ClusterID < s.Policies[j].ClusterID })
	if len(s.Stages) == 0 {
		canaryCount := 1
		if s.Selection.CanaryTopologyKey != "" {
			canaryCount = 0 // Plan derives the canary count from observed topology domains.
		}
		s.Stages = []Stage{{"Canary", canaryCount, 1}, {"SmallBatch", 5, 2}, {"Expanded", 20, 5}, {"Remaining", 0, 10}}
	}
	if len(s.Stages) != 4 {
		return s, fmt.Errorf("exactly four rollout stages required")
	}
	for i, stage := range s.Stages {
		derivedCanaryCount := i == 0 && s.Selection.CanaryTopologyKey != "" && stage.Count == 0
		if stage.Name != stageNames[i] || stage.BatchSize < 1 || stage.BatchSize > 1000 || stage.Count < 0 || stage.Count > MaxTargets || (i < 3 && stage.Count == 0 && !derivedCanaryCount) || (i == 3 && stage.Count != 0) {
			return s, fmt.Errorf("invalid rollout stage")
		}
	}
	if s.Selection.CanaryTopologyKey != "" && s.Action == protocol.UpgradeNodePool {
		return s, fmt.Errorf("topology canaries are unsupported for provider node-pool actions")
	}
	if s.Stages[0].Count > 0 && len(s.Selection.Canaries) > s.Stages[0].Count {
		return s, fmt.Errorf("too many explicit canaries")
	}
	canaries := map[string]bool{}
	for _, node := range s.Selection.Canaries {
		key := node.ClusterID + "/" + node.NodeUID
		if !protocol.ValidUUID(node.ClusterID) || node.NodeUID == "" || len(node.NodeUID) > 128 || canaries[key] {
			return s, fmt.Errorf("invalid explicit canary")
		}
		canaries[key] = true
	}
	if s.Limits == (Limits{}) {
		s.Limits = DefaultLimits()
	}
	if err := s.Limits.Validate(); err != nil {
		return s, err
	}
	if s.ApprovalMode == "" {
		s.ApprovalMode = "AllStages"
	}
	if s.ApprovalMode != "AllStages" && s.ApprovalMode != "BeforeStart" && s.ApprovalMode != "None" {
		return s, fmt.Errorf("invalid approval mode")
	}
	if s.Action == protocol.DrainAndVerify && s.ApprovalMode == "None" {
		return s, fmt.Errorf("disruptive campaigns require independent approval")
	}
	if (s.Action == protocol.UpgradePackages || s.Action == protocol.UpgradeNodePool || s.Action == UpgradeFleet) && s.ApprovalMode == "None" {
		return s, fmt.Errorf("upgrade campaigns require independent approval")
	}
	if s.Retry.BackoffSeconds == 0 {
		s.Retry.BackoffSeconds = 30
	}
	if s.Retry.MaxRetries < 0 || s.Retry.MaxRetries > 5 || s.Retry.BackoffSeconds < 1 || s.Retry.BackoffSeconds > 3600 {
		return s, fmt.Errorf("invalid retry policy")
	}
	allowed := map[string]bool{"AuthorizationExpired": true, "AuthorizationExpiredBeforeDelivery": true, "APIServerHealthUnknown": true, "NodeHeartbeatStale": true, "ManagementDisconnected": true, "PDBBlocked": true, "EvictionPDBBlocked": true, "WorkloadRecoveryPending": true}
	if len(s.Retry.Reasons) == 0 {
		if s.Action == protocol.UpgradePackages || s.Action == protocol.UpgradeNodePool || s.Action == UpgradeFleet {
			s.Retry.Reasons = []string{"AuthorizationExpiredBeforeDelivery"}
		} else {
			s.Retry.Reasons = []string{"AuthorizationExpired", "AuthorizationExpiredBeforeDelivery"}
		}
	}
	reasonSeen := map[string]bool{}
	for _, reason := range s.Retry.Reasons {
		if !allowed[reason] || reasonSeen[reason] {
			return s, fmt.Errorf("unsafe or duplicate retry reason")
		}
		if (s.Action == protocol.UpgradePackages || s.Action == protocol.UpgradeNodePool || s.Action == UpgradeFleet) && reason != "AuthorizationExpiredBeforeDelivery" {
			return s, fmt.Errorf("upgrade campaigns may retry only operations that expired before delivery")
		}
		reasonSeen[reason] = true
	}
	sort.Strings(s.Retry.Reasons)
	if s.Failure.MinimumSamples == 0 {
		s.Failure.MinimumSamples = 1
	}
	if s.Failure.MaxFailedAttempts < 0 || s.Failure.MaxFailedAttempts > 1000 || s.Failure.MaxFailurePercent < 0 || s.Failure.MaxFailurePercent > 100 || s.Failure.MinimumSamples < 1 || s.Failure.MinimumSamples > 10000 || s.Failure.MaxConsecutiveFailures < 0 || s.Failure.MaxConsecutiveFailures > 1000 {
		return s, fmt.Errorf("invalid failure thresholds")
	}
	if s.MinimumWindowSeconds == 0 {
		s.MinimumWindowSeconds = 60
	}
	if s.MinimumWindowSeconds < 30 || s.MinimumWindowSeconds > 900 {
		return s, fmt.Errorf("invalid minimum window remainder")
	}
	if s.RecoveryAction == "" {
		s.RecoveryAction = "LocalVerifiedRecovery"
	}
	if s.RecoveryAction != "LocalVerifiedRecovery" {
		return s, fmt.Errorf("unsupported recovery action")
	}
	if len(s.Windows) == 0 || len(s.Windows) > 64 {
		return s, fmt.Errorf("one to 64 explicit maintenance windows required")
	}
	sort.Slice(s.Windows, func(i, j int) bool { return s.Windows[i].Start.Before(s.Windows[j].Start) })
	for i, w := range s.Windows {
		if err := w.Validate(); err != nil {
			return s, err
		}
		if i > 0 && w.Start.Before(s.Windows[i-1].End) {
			return s, fmt.Errorf("maintenance windows overlap")
		}
	}
	return s, nil
}
func (s Spec) NeedsApproval(stage int) bool {
	return s.ApprovalMode == "AllStages" || (s.ApprovalMode == "BeforeStart" && stage == 0)
}
func (p RetryPolicy) Allows(reason string, failures int) bool {
	if failures > p.MaxRetries {
		return false
	}
	for _, v := range p.Reasons {
		if v == reason {
			return true
		}
	}
	return false
}
func (p FailurePolicy) Breached(failed, completed, consecutive int) bool {
	return failed > p.MaxFailedAttempts || (completed >= p.MinimumSamples && failed*100 > p.MaxFailurePercent*completed) || (p.MaxConsecutiveFailures > 0 && consecutive > p.MaxConsecutiveFailures)
}
func Terminal(phase string) bool {
	return phase == "Succeeded" || phase == "Failed" || phase == "Cancelled" || phase == "CompletedWithFailures"
}
