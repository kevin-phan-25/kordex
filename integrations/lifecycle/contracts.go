// Package lifecycle contains narrow contracts for optional local infrastructure adapters.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

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

type PackagePlan struct {
	Manager        string
	Current        string
	Target         string
	RequiresReboot bool
	Packages       []string
}

// UpgradePolicy is a declarative, bounded description of an approved host
// update. It deliberately contains package names and versions, never commands.
// It is a contract only; no implementation in this module executes it.
type UpgradePolicy struct {
	SchemaVersion       int           `json:"schemaVersion"`
	ID                  string        `json:"id"`
	OSFamily            string        `json:"osFamily"`
	ExecutionBackend    string        `json:"executionBackend"`
	Packages            []PackagePin  `json:"packages"`
	Channel             string        `json:"channel"`
	Reboot              RebootPolicy  `json:"reboot"`
	PreHooks            []string      `json:"preHooks,omitempty"`
	PostHooks           []string      `json:"postHooks,omitempty"`
	ExecutionTimeout    time.Duration `json:"executionTimeout"`
	RebootTimeout       time.Duration `json:"rebootTimeout"`
	VerificationTimeout time.Duration `json:"verificationTimeout"`
	MaxAttempts         int           `json:"maxAttempts"`
}

type PackagePin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type RebootPolicy string

const (
	RebootNever    RebootPolicy = "Never"
	RebootIfNeeded RebootPolicy = "IfNeeded"
	RebootRequired RebootPolicy = "Required"
)

var packageToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:-]{0,127}$`)
var versionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:~^-]{0,127}$`)
var policyToken = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

var allowedHooks = map[string]struct{}{
	"kordex.health-check.v1":            {},
	"kordex.package-lock-check.v1":      {},
	"kordex.application-smoke-check.v1": {},
}

// Validate rejects ambiguous or command-like policy values. The listed
// package managers are supported contract values, not proof an executor exists.
func (p UpgradePolicy) Validate() error {
	if p.SchemaVersion != 1 || !policyToken.MatchString(p.ID) || len(p.Packages) == 0 || len(p.Packages) > 128 {
		return errors.New("invalid upgrade policy identity or package count")
	}
	switch p.OSFamily {
	case "debian", "rhel", "cos":
	default:
		return errors.New("unsupported operating system family")
	}
	switch p.ExecutionBackend {
	case "apt", "dnf", "gke-node-image":
	default:
		return errors.New("unsupported execution backend")
	}
	if (p.OSFamily == "debian" && p.ExecutionBackend != "apt") || (p.OSFamily == "rhel" && p.ExecutionBackend != "dnf") || (p.OSFamily == "cos" && p.ExecutionBackend != "gke-node-image") {
		return errors.New("execution backend does not match operating system family")
	}
	if strings.TrimSpace(p.Channel) == "" || len(p.Channel) > 64 || strings.ContainsAny(p.Channel, "\x00\n\r") {
		return errors.New("invalid update channel")
	}
	if p.Reboot != RebootNever && p.Reboot != RebootIfNeeded && p.Reboot != RebootRequired {
		return errors.New("invalid reboot policy")
	}
	if p.ExecutionTimeout < time.Minute || p.ExecutionTimeout > 2*time.Hour || p.RebootTimeout < time.Minute || p.RebootTimeout > 2*time.Hour || p.VerificationTimeout < time.Minute || p.VerificationTimeout > 2*time.Hour || p.MaxAttempts < 1 || p.MaxAttempts > 3 {
		return errors.New("upgrade timeouts or retry count outside safe bounds")
	}
	seen := make(map[string]struct{}, len(p.Packages))
	for _, item := range p.Packages {
		if !packageToken.MatchString(item.Name) || !versionToken.MatchString(item.Version) || isFloatingVersion(item.Version) {
			return errors.New("invalid package name or pinned version")
		}
		if _, exists := seen[item.Name]; exists {
			return errors.New("duplicate package in upgrade policy")
		}
		seen[item.Name] = struct{}{}
	}
	for _, hook := range append(append([]string{}, p.PreHooks...), p.PostHooks...) {
		if _, ok := allowedHooks[hook]; !ok {
			return errors.New("hook is not in the built-in allowlist")
		}
	}
	return nil
}

func isFloatingVersion(version string) bool {
	switch strings.ToLower(version) {
	case "latest", "stable", "current", "*":
		return true
	default:
		return strings.ContainsAny(version, "*?")
	}
}

// Digest returns a stable digest for immutable approval and signed-permit
// binding. Package ordering does not change the resulting digest.
func (p UpgradePolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	packages := append([]PackagePin(nil), p.Packages...)
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	p.Packages = packages
	data := []byte(strconv.Itoa(p.SchemaVersion) + "\n" + p.ID + "\n" + p.OSFamily + "\n" + p.ExecutionBackend + "\n" + p.Channel + "\n" + string(p.Reboot) + "\n" + p.ExecutionTimeout.String() + "\n" + p.RebootTimeout.String() + "\n" + p.VerificationTimeout.String() + "\nattempts=" + strconv.Itoa(p.MaxAttempts))
	for _, item := range p.Packages {
		data = append(data, []byte("\n"+item.Name+"="+item.Version)...)
	}
	pre := append([]string(nil), p.PreHooks...)
	post := append([]string(nil), p.PostHooks...)
	sort.Strings(pre)
	sort.Strings(post)
	for _, hook := range pre {
		data = append(data, []byte("\npre="+hook)...)
	}
	for _, hook := range post {
		data = append(data, []byte("\npost="+hook)...)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

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
	PhaseBlocked:            {PhasePreflighting: {}, PhaseRecoveryRequired: {}, PhaseCancelled: {}},
	PhaseRecoveryRequired:   {PhaseVerifyingNode: {}, PhaseVerifyingWorkloads: {}, PhaseUncordoning: {}, PhaseFailed: {}, PhaseCancelled: {}},
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

type PackageManager interface {
	Plan(context.Context, Operation, []string) (PackagePlan, error)
	Apply(context.Context, Operation, PackagePlan) error
	Verify(context.Context, Operation, PackagePlan) (Evidence, safety.Result, error)
}
