package protocol

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var maintenancePolicyActions = map[string]struct{}{
	ValidateOnly:    {},
	DrainAndVerify:  {},
	UpgradePackages: {},
	UpgradeNodePool: {},
}

// ValidateMaintenancePolicyActions validates the operation allowlist shared by
// the hub catalog and the cluster-local operator. An empty list intentionally
// grants no operation, including validation-only requests.
func ValidateMaintenancePolicyActions(actions []string) error {
	if len(actions) == 0 || len(actions) > len(maintenancePolicyActions) {
		return fmt.Errorf("maintenance policy must allow one to %d known actions", len(maintenancePolicyActions))
	}
	seen := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		if _, ok := maintenancePolicyActions[action]; !ok {
			return fmt.Errorf("maintenance policy contains an unknown action")
		}
		if _, duplicate := seen[action]; duplicate {
			return fmt.Errorf("maintenance policy contains a duplicate action")
		}
		seen[action] = struct{}{}
	}
	return nil
}

// MaintenanceActionPolicyDecision records the result and the policy version
// evaluated. It deliberately covers the action allowlist only; target
// selection and live operational safety are separate policy decisions.
type MaintenanceActionPolicyDecision struct {
	Allowed           bool
	ReasonCode        string
	Explanation       string
	PolicyGeneration  int64
	Action            string
	AllowedActions    []string
	CorrectiveActions []string
}

func EvaluateMaintenanceAction(policyGeneration int64, actions []string, action string) MaintenanceActionPolicyDecision {
	decision := MaintenanceActionPolicyDecision{
		PolicyGeneration:  policyGeneration,
		Action:            action,
		AllowedActions:    append([]string{}, actions...),
		CorrectiveActions: []string{},
	}
	if policyGeneration < 1 {
		decision.ReasonCode = "PolicyGenerationInvalid"
		decision.Explanation = "The maintenance policy has no valid generation to authorize this action."
		decision.CorrectiveActions = []string{"Read the current policy generation and issue a permit bound to it."}
		return decision
	}
	if err := ValidateMaintenancePolicyActions(actions); err != nil {
		decision.ReasonCode = "InvalidAllowedActions"
		decision.Explanation = "The maintenance policy action allowlist is empty or malformed."
		decision.CorrectiveActions = []string{"Configure one or more unique supported actions in a new policy generation."}
		return decision
	}
	if !MaintenanceActionKnown(action) {
		decision.ReasonCode = "UnknownMaintenanceAction"
		decision.Explanation = "The requested maintenance action is not supported by this protocol."
		decision.CorrectiveActions = []string{"Request a supported action."}
		return decision
	}
	for _, allowed := range actions {
		if allowed == action {
			decision.Allowed = true
			decision.ReasonCode = "PolicyActionAllowed"
			decision.Explanation = "The current maintenance policy explicitly allows the requested action."
			return decision
		}
	}
	decision.ReasonCode = "PolicyActionNotAllowed"
	decision.Explanation = "The current maintenance policy does not allow the requested action."
	decision.CorrectiveActions = []string{"Select an allowed action or approve a new policy generation that explicitly allows this action."}
	return decision
}

func MaintenanceActionKnown(action string) bool {
	_, ok := maintenancePolicyActions[action]
	return ok
}

func MaintenancePolicyAllows(actions []string, action string) bool {
	return EvaluateMaintenanceAction(1, actions, action).Allowed
}

// MaintenanceTargetPolicyDecision is the deterministic result of applying a
// maintenance policy's Kubernetes label selector to one node. Runtime health,
// storage, quorum, authorization, and policy generation remain independent
// checks at their respective layers.
type MaintenanceTargetPolicyDecision struct {
	Allowed           bool
	ReasonCode        string
	Explanation       string
	CorrectiveActions []string
}

// EvaluateMaintenanceTarget is shared by central admission and the local
// operator so that the same LabelSelector has the same target semantics at
// both authorization boundaries.
func EvaluateMaintenanceTarget(selector metav1.LabelSelector, nodeLabels map[string]string) MaintenanceTargetPolicyDecision {
	compiled, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return MaintenanceTargetPolicyDecision{
			ReasonCode:        "InvalidNodeSelector",
			Explanation:       "The maintenance policy contains an invalid Kubernetes node selector.",
			CorrectiveActions: []string{"Correct the policy selector and publish a new policy generation."},
		}
	}
	if !compiled.Matches(labels.Set(nodeLabels)) {
		return MaintenanceTargetPolicyDecision{
			ReasonCode:        "PolicySelectorMismatch",
			Explanation:       "The target node labels do not satisfy the maintenance policy selector.",
			CorrectiveActions: []string{"Select an eligible node or update the policy through a new approved policy generation."},
		}
	}
	return MaintenanceTargetPolicyDecision{
		Allowed:           true,
		ReasonCode:        "PolicySelectorMatched",
		Explanation:       "The target node labels satisfy the maintenance policy selector.",
		CorrectiveActions: []string{},
	}
}

// EvaluateProtectedNode applies the policy's administrative maintenance veto.
// A nil selector disables the veto. A configured selector with missing label
// evidence fails closed; an empty configured selector matches every node under
// Kubernetes LabelSelector semantics.
func EvaluateProtectedNode(selector *metav1.LabelSelector, nodeLabels map[string]string) MaintenanceTargetPolicyDecision {
	if selector == nil {
		return MaintenanceTargetPolicyDecision{
			Allowed: true, ReasonCode: "NoProtectedNodeSelector",
			Explanation:       "The maintenance policy does not configure protected nodes.",
			CorrectiveActions: []string{},
		}
	}
	compiled, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return MaintenanceTargetPolicyDecision{
			ReasonCode:        "InvalidProtectedNodeSelector",
			Explanation:       "The maintenance policy contains an invalid protected-node selector.",
			CorrectiveActions: []string{"Correct the protected-node selector and publish a new policy generation."},
		}
	}
	if nodeLabels == nil {
		return MaintenanceTargetPolicyDecision{
			ReasonCode:        "ProtectedNodeLabelsUnknown",
			Explanation:       "Node labels are unavailable, so the protected-node policy cannot be evaluated safely.",
			CorrectiveActions: []string{"Refresh the target node inventory and retry after labels are available."},
		}
	}
	if compiled.Matches(labels.Set(nodeLabels)) {
		return MaintenanceTargetPolicyDecision{
			ReasonCode:        "ProtectedNode",
			Explanation:       "The target node matches the policy's administrative maintenance protection selector.",
			CorrectiveActions: []string{"Choose an unprotected node or have an administrator publish a new policy generation after reviewing the protection."},
		}
	}
	return MaintenanceTargetPolicyDecision{
		Allowed: true, ReasonCode: "ProtectedNodeSelectorClear",
		Explanation:       "The target node does not match the configured protected-node selector.",
		CorrectiveActions: []string{},
	}
}
