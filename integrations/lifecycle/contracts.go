// Package lifecycle contains narrow contracts for optional local infrastructure adapters.
package lifecycle

import (
	"context"
	"errors"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/integrations/safety"
)

type Operation struct {
	ID        string
	ClusterID string
	NodeName  string
	NodeUID   string
	Action    string
}

type Evidence struct {
	Provider   string
	Reference  string
	ObservedAt time.Time
	ValidFor   time.Duration
	Details    map[string]string
}

type Storage interface {
	Preflight(context.Context, Operation, Evidence) (safety.Result, error)
	EnterMaintenance(context.Context, Operation) (ownershipToken string, err error)
	ObserveRecovery(ctx context.Context, op Operation, ownershipToken string) (safety.Result, error)
	ExitMaintenance(ctx context.Context, op Operation, ownershipToken string) error
}

type Quorum interface {
	Preflight(context.Context, Operation) (safety.Result, error)
	ObserveRecovery(context.Context, Operation) (safety.Result, error)
}

type NodeLifecycle interface {
	Preflight(context.Context, Operation) (Evidence, safety.Result, error)
	Execute(context.Context, Operation, string) (operationReference string, err error)
	Observe(context.Context, Operation, string) (Evidence, safety.Result, error)
}

// Shared protocol types own validation and digest semantics used by permits and CRDs.
type UpgradePolicy = protocol.UpgradePolicy
type PackagePin = protocol.PackagePin
type RebootPolicy = protocol.RebootPolicy
type ProviderNodeUpgradePlan = protocol.ProviderNodeUpgradePlan

const (
	RebootNever    = protocol.RebootNever
	RebootIfNeeded = protocol.RebootIfNeeded
	RebootRequired = protocol.RebootRequired
)

// CheckpointPhase enumerates the durable lifecycle expected by an upgrade
// executor. Existing operator actions do not enter these phases yet.
type CheckpointPhase string

const (
	PhasePending            CheckpointPhase = "Pending"
	PhasePreflighting       CheckpointPhase = "Preflighting"
	PhaseCordoning          CheckpointPhase = "Cordoning"
	PhaseDraining           CheckpointPhase = "Draining"
	PhaseExecuting          CheckpointPhase = "Executing"
	PhaseRebooting          CheckpointPhase = "Rebooting"
	PhaseVerifyingNode      CheckpointPhase = "VerifyingNode"
	PhaseVerifyingWorkloads CheckpointPhase = "VerifyingWorkloads"
	PhaseUncordoning        CheckpointPhase = "Uncordoning"
	PhaseSucceeded          CheckpointPhase = "Succeeded"
	PhaseBlocked            CheckpointPhase = "Blocked"
	PhaseRecoveryRequired   CheckpointPhase = "RecoveryRequired"
	PhaseFailed             CheckpointPhase = "Failed"
	PhaseCancelled          CheckpointPhase = "Cancelled"
)

var phaseEdges = map[CheckpointPhase]map[CheckpointPhase]struct{}{
	PhasePending:            {PhasePreflighting: {}, PhaseCancelled: {}, PhaseFailed: {}},
	PhasePreflighting:       {PhaseCordoning: {}, PhaseBlocked: {}, PhaseCancelled: {}, PhaseFailed: {}},
	PhaseCordoning:          {PhaseDraining: {}, PhaseRecoveryRequired: {}},
	PhaseDraining:           {PhaseExecuting: {}, PhaseRecoveryRequired: {}, PhaseBlocked: {}},
	PhaseExecuting:          {PhaseRebooting: {}, PhaseVerifyingNode: {}, PhaseRecoveryRequired: {}},
	PhaseRebooting:          {PhaseVerifyingNode: {}, PhaseRecoveryRequired: {}},
	PhaseVerifyingNode:      {PhaseVerifyingWorkloads: {}, PhaseRecoveryRequired: {}},
	PhaseVerifyingWorkloads: {PhaseUncordoning: {}, PhaseRecoveryRequired: {}},
	PhaseUncordoning:        {PhaseSucceeded: {}, PhaseCancelled: {}, PhaseFailed: {}, PhaseRecoveryRequired: {}},
	PhaseBlocked:            {PhasePreflighting: {}, PhaseRecoveryRequired: {}},
	PhaseRecoveryRequired:   {PhaseVerifyingNode: {}, PhaseVerifyingWorkloads: {}, PhaseUncordoning: {}},
}

func CanTransition(from, to CheckpointPhase) bool {
	_, ok := phaseEdges[from][to]
	return ok
}

type HostIdentity struct {
	NodeUID   string `json:"nodeUid"`
	MachineID string `json:"machineId"`
	BootID    string `json:"bootId"`
}

type ActionMarker struct {
	OperationID  string          `json:"operationId"`
	ActionDigest string          `json:"actionDigest"`
	Host         HostIdentity    `json:"host"`
	Phase        CheckpointPhase `json:"phase"`
	Sequence     uint64          `json:"sequence"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}

// ValidateMarkerAdvance enforces the identity and sequence fences needed by a
// future durable host journal. A boot-ID change is accepted only as evidence
// when moving from Rebooting to VerifyingNode; callers must still verify all
// package, node and workload postconditions before completion.
func ValidateMarkerAdvance(previous, next ActionMarker) error {
	if previous.OperationID == "" || previous.OperationID != next.OperationID || previous.ActionDigest == "" || previous.ActionDigest != next.ActionDigest {
		return errors.New("operation or action identity changed")
	}
	if previous.Host.NodeUID == "" || previous.Host.NodeUID != next.Host.NodeUID || previous.Host.MachineID == "" || previous.Host.MachineID != next.Host.MachineID || previous.Host.BootID == "" || next.Host.BootID == "" {
		return errors.New("host identity changed or is incomplete")
	}
	if next.Sequence != previous.Sequence+1 || !next.UpdatedAt.After(previous.UpdatedAt) || !CanTransition(previous.Phase, next.Phase) {
		return errors.New("invalid checkpoint sequence or phase transition")
	}
	bootChanged := previous.Host.BootID != next.Host.BootID
	if (previous.Phase == PhaseRebooting && next.Phase == PhaseVerifyingNode) != bootChanged {
		return errors.New("boot identity change does not match reboot checkpoint")
	}
	return nil
}

type ExecutionReceipt struct {
	OperationID  string       `json:"operationId"`
	ActionDigest string       `json:"actionDigest"`
	Before       HostIdentity `json:"before"`
	After        HostIdentity `json:"after"`
	Observed     Evidence     `json:"observed"`
	Outcome      string       `json:"outcome"`
	CompletedAt  time.Time    `json:"completedAt"`
}

// ExecutionEnvironmentJob is the bounded input to an Ansible EE runner. It
// contains no playbook text, arbitrary command, inventory, SSH key or secret.
type ExecutionEnvironmentJob struct {
	Operation  Operation
	Host       HostIdentity
	Policy     UpgradePolicy
	PlanDigest string
	Phase      CheckpointPhase
	Marker     ActionMarker
}

type ExecutionEnvironmentResult struct {
	JobReference string
	Phase        CheckpointPhase
	Evidence     Evidence
	Outcome      string
	Changed      bool
	RebootNeeded bool
}

// AnsibleExecutionEnvironment starts and observes catalog jobs using a
// digest-pinned EE. Implementations must source credentials from the deployment
// secret provider and resolve ambiguous launches by operation identity instead
// of blindly submitting a duplicate.
type AnsibleExecutionEnvironment interface {
	Start(context.Context, ExecutionEnvironmentJob) (ExecutionEnvironmentResult, error)
	Observe(context.Context, ExecutionEnvironmentJob, string) (ExecutionEnvironmentResult, error)
	Cancel(context.Context, ExecutionEnvironmentJob, string) error
}
