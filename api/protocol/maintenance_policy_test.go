package protocol

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMaintenancePolicyActionAllowlistFailsClosed(t *testing.T) {
	valid := []string{ValidateOnly, DrainAndVerify, UpgradePackages, UpgradeNodePool}
	if err := ValidateMaintenancePolicyActions(valid); err != nil {
		t.Fatal(err)
	}
	for _, action := range valid {
		if !MaintenancePolicyAllows(valid, action) {
			t.Errorf("allowlist rejected configured action %q", action)
		}
	}
	for _, actions := range [][]string{
		nil,
		{},
		{ValidateOnly, ValidateOnly},
		{ValidateOnly, "hostCommand"},
		{ValidateOnly, DrainAndVerify, UpgradePackages, UpgradeNodePool, "unknown"},
	} {
		if err := ValidateMaintenancePolicyActions(actions); err == nil {
			t.Errorf("accepted invalid allowlist %q", actions)
		}
		if MaintenancePolicyAllows(actions, ValidateOnly) {
			t.Errorf("invalid allowlist granted ValidateOnly: %q", actions)
		}
	}
	if MaintenancePolicyAllows([]string{ValidateOnly}, DrainAndVerify) {
		t.Fatal("allowlist granted an unconfigured disruptive action")
	}
}

func TestMaintenanceTargetPolicyEvaluationIsDeterministic(t *testing.T) {
	tests := []struct {
		name       string
		selector   metav1.LabelSelector
		labels     map[string]string
		allowed    bool
		reasonCode string
	}{
		{name: "match labels", selector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "workers"}}, labels: map[string]string{"pool": "workers"}, allowed: true, reasonCode: "PolicySelectorMatched"},
		{name: "match expressions", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "pool", Operator: metav1.LabelSelectorOpIn, Values: []string{"workers", "batch"}}}}, labels: map[string]string{"pool": "workers"}, allowed: true, reasonCode: "PolicySelectorMatched"},
		{name: "empty selector follows Kubernetes semantics", selector: metav1.LabelSelector{}, labels: map[string]string{}, allowed: true, reasonCode: "PolicySelectorMatched"},
		{name: "mismatch", selector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "workers"}}, labels: map[string]string{"pool": "control-plane"}, reasonCode: "PolicySelectorMismatch"},
		{name: "invalid selector", selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "pool", Operator: "Unknown"}}}, labels: map[string]string{"pool": "workers"}, reasonCode: "InvalidNodeSelector"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := EvaluateMaintenanceTarget(test.selector, test.labels)
			if decision.Allowed != test.allowed || decision.ReasonCode != test.reasonCode {
				t.Fatalf("decision=%+v, want allowed=%t reason=%s", decision, test.allowed, test.reasonCode)
			}
			if decision.Explanation == "" || decision.CorrectiveActions == nil {
				t.Fatalf("decision lacks actionable detail: %+v", decision)
			}
			if test.allowed && len(decision.CorrectiveActions) != 0 {
				t.Fatalf("allowed decision has corrective actions: %+v", decision)
			}
			if !test.allowed && len(decision.CorrectiveActions) == 0 {
				t.Fatalf("denied decision lacks a corrective action: %+v", decision)
			}
		})
	}
}

func TestProtectedNodePolicyFailsClosed(t *testing.T) {
	protected := &metav1.LabelSelector{MatchLabels: map[string]string{"maintenance": "forbidden"}}
	invalid := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "maintenance", Operator: "Unknown"}}}
	empty := &metav1.LabelSelector{}
	tests := []struct {
		name       string
		selector   *metav1.LabelSelector
		labels     map[string]string
		allowed    bool
		reasonCode string
	}{
		{name: "not configured", labels: map[string]string{"maintenance": "forbidden"}, allowed: true, reasonCode: "NoProtectedNodeSelector"},
		{name: "matching node denied", selector: protected, labels: map[string]string{"maintenance": "forbidden"}, reasonCode: "ProtectedNode"},
		{name: "nonmatching node allowed", selector: protected, labels: map[string]string{"maintenance": "allowed"}, allowed: true, reasonCode: "ProtectedNodeSelectorClear"},
		{name: "unknown labels denied", selector: protected, reasonCode: "ProtectedNodeLabelsUnknown"},
		{name: "empty selector protects all", selector: empty, labels: map[string]string{}, reasonCode: "ProtectedNode"},
		{name: "invalid selector denied", selector: invalid, labels: map[string]string{}, reasonCode: "InvalidProtectedNodeSelector"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := EvaluateProtectedNode(test.selector, test.labels)
			if decision.Allowed != test.allowed || decision.ReasonCode != test.reasonCode {
				t.Fatalf("decision=%+v, want allowed=%t reason=%s", decision, test.allowed, test.reasonCode)
			}
			if decision.Explanation == "" || decision.CorrectiveActions == nil {
				t.Fatalf("decision lacks actionable detail: %+v", decision)
			}
			if test.allowed && len(decision.CorrectiveActions) != 0 || !test.allowed && len(decision.CorrectiveActions) == 0 {
				t.Fatalf("corrective actions do not match decision: %+v", decision)
			}
		})
	}
}

func TestMaintenanceActionEvaluationCarriesPolicyVersionAndCorrectiveDetail(t *testing.T) {
	tests := []struct {
		name       string
		generation int64
		actions    []string
		action     string
		allowed    bool
		reason     string
	}{
		{name: "explicitly allowed", generation: 7, actions: []string{ValidateOnly, DrainAndVerify}, action: DrainAndVerify, allowed: true, reason: "PolicyActionAllowed"},
		{name: "supported action omitted", generation: 7, actions: []string{ValidateOnly}, action: DrainAndVerify, reason: "PolicyActionNotAllowed"},
		{name: "empty allowlist", generation: 7, action: ValidateOnly, reason: "InvalidAllowedActions"},
		{name: "unknown action", generation: 7, actions: []string{ValidateOnly}, action: "RunShell", reason: "UnknownMaintenanceAction"},
		{name: "missing policy version", actions: []string{ValidateOnly}, action: ValidateOnly, reason: "PolicyGenerationInvalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := EvaluateMaintenanceAction(test.generation, test.actions, test.action)
			if decision.Allowed != test.allowed || decision.ReasonCode != test.reason || decision.PolicyGeneration != test.generation || decision.Action != test.action {
				t.Fatalf("decision=%+v, want allowed=%t reason=%s generation=%d action=%s", decision, test.allowed, test.reason, test.generation, test.action)
			}
			if decision.Explanation == "" || decision.AllowedActions == nil || decision.CorrectiveActions == nil {
				t.Fatalf("decision lacks evaluated state or human-readable detail: %+v", decision)
			}
			if test.allowed && len(decision.CorrectiveActions) != 0 || !test.allowed && len(decision.CorrectiveActions) == 0 {
				t.Fatalf("corrective action detail does not match decision: %+v", decision)
			}
		})
	}
}
