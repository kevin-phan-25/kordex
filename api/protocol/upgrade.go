package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type UpgradePhase string

const (
	UpgradePending            UpgradePhase = "Pending"
	UpgradePreflighting       UpgradePhase = "Preflighting"
	UpgradeCordoning          UpgradePhase = "Cordoning"
	UpgradeDraining           UpgradePhase = "Draining"
	UpgradeExecuting          UpgradePhase = "Executing"
	UpgradeRebooting          UpgradePhase = "Rebooting"
	UpgradeVerifyingNode      UpgradePhase = "VerifyingNode"
	UpgradeVerifyingWorkloads UpgradePhase = "VerifyingWorkloads"
	UpgradeUncordoning        UpgradePhase = "Uncordoning"
	UpgradeSucceeded          UpgradePhase = "Succeeded"
	UpgradeBlocked            UpgradePhase = "Blocked"
	UpgradeRecoveryRequired   UpgradePhase = "RecoveryRequired"
	UpgradeFailed             UpgradePhase = "Failed"
	UpgradeCancelled          UpgradePhase = "Cancelled"
)

var upgradePhaseEdges = map[UpgradePhase]map[UpgradePhase]struct{}{
	UpgradePending:            {UpgradePreflighting: {}, UpgradeCancelled: {}, UpgradeFailed: {}},
	UpgradePreflighting:       {UpgradeCordoning: {}, UpgradeBlocked: {}, UpgradeCancelled: {}, UpgradeFailed: {}},
	UpgradeCordoning:          {UpgradeDraining: {}, UpgradeRecoveryRequired: {}},
	UpgradeDraining:           {UpgradeExecuting: {}, UpgradeRecoveryRequired: {}, UpgradeBlocked: {}},
	UpgradeExecuting:          {UpgradeRebooting: {}, UpgradeVerifyingNode: {}, UpgradeRecoveryRequired: {}},
	UpgradeRebooting:          {UpgradeVerifyingNode: {}, UpgradeRecoveryRequired: {}},
	UpgradeVerifyingNode:      {UpgradeVerifyingWorkloads: {}, UpgradeRecoveryRequired: {}},
	UpgradeVerifyingWorkloads: {UpgradeUncordoning: {}, UpgradeRecoveryRequired: {}},
	UpgradeUncordoning:        {UpgradeSucceeded: {}, UpgradeCancelled: {}, UpgradeFailed: {}, UpgradeRecoveryRequired: {}},
	UpgradeBlocked:            {UpgradePreflighting: {}, UpgradeRecoveryRequired: {}, UpgradeFailed: {}, UpgradeCancelled: {}},
	UpgradeRecoveryRequired:   {UpgradeVerifyingNode: {}, UpgradeVerifyingWorkloads: {}, UpgradeUncordoning: {}, UpgradeFailed: {}},
}

func CanAdvanceUpgrade(from, to UpgradePhase) bool {
	_, ok := upgradePhaseEdges[from][to]
	return ok
}

// UpgradeCheckpoint is persisted in the NodeMaintenance status. The digest,
// node UID, and machine ID fence execution identity across controller restarts.
type UpgradeCheckpoint struct {
	// +kubebuilder:validation:Pattern="^[a-f0-9]{64}$"
	PlanDigest string `json:"planDigest"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	NodeUID string `json:"nodeUid"`
	// +kubebuilder:validation:MaxLength=128
	MachineID string `json:"machineId,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	BootID string `json:"bootId,omitempty"`
	// +kubebuilder:validation:Enum=Pending;Preflighting;Cordoning;Draining;Executing;Rebooting;VerifyingNode;VerifyingWorkloads;Uncordoning;Succeeded;Blocked;RecoveryRequired;Failed;Cancelled
	Phase UpgradePhase `json:"phase"`
	// +kubebuilder:validation:Minimum=1
	Sequence int64 `json:"sequence"`
	// +kubebuilder:validation:MaxLength=256
	ExecutionReference string `json:"executionReference,omitempty"`
	RebootRequested    bool   `json:"rebootRequested,omitempty"`
	Outcome            string `json:"outcome,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	Reason    string      `json:"reason,omitempty"`
	UpdatedAt metav1.Time `json:"updatedAt"`
}

func (in *UpgradeCheckpoint) DeepCopy() *UpgradeCheckpoint {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

// ValidateUpgradeCheckpointAdvance fences checkpoint writes to the signed
// plan and node identity, with reboot evidence restricted to the reboot edge.
func ValidateUpgradeCheckpointAdvance(previous, next UpgradeCheckpoint) error {
	if err := ValidateUpgradeCheckpoint(next); err != nil {
		return err
	}
	if previous.PlanDigest != "" && previous.PlanDigest != next.PlanDigest {
		return errors.New("upgrade plan digest changed")
	}
	if next.NodeUID == "" || previous.NodeUID != "" && previous.NodeUID != next.NodeUID {
		return errors.New("upgrade target node identity changed or is empty")
	}
	if previous.Sequence == 0 {
		if next.Sequence != 1 || next.Phase != UpgradePending || next.UpdatedAt.IsZero() {
			return errors.New("invalid initial upgrade checkpoint")
		}
		return nil
	}
	if next.Sequence != previous.Sequence+1 || !next.UpdatedAt.After(previous.UpdatedAt.Time) || !CanAdvanceUpgrade(previous.Phase, next.Phase) {
		return errors.New("invalid upgrade checkpoint sequence or phase transition")
	}
	if previous.MachineID != "" && previous.MachineID != next.MachineID {
		return errors.New("upgrade host machine identity changed")
	}
	if previous.Phase == UpgradeExecuting && next.Phase == UpgradeRebooting && next.MachineID == "" {
		return errors.New("machine identity is required before reboot")
	}
	bootChanged := previous.BootID != "" && previous.BootID != next.BootID
	if previous.Phase == UpgradeRebooting && next.Phase == UpgradeVerifyingNode {
		if !previous.RebootRequested || !bootChanged {
			return errors.New("reboot verification requires a requested reboot and changed boot ID")
		}
	} else if bootChanged {
		return errors.New("boot identity changed outside reboot verification")
	}
	return nil
}

func ValidateUpgradeCheckpoint(checkpoint UpgradeCheckpoint) error {
	if !ValidSHA256Digest(checkpoint.PlanDigest) || checkpoint.NodeUID == "" || checkpoint.Sequence < 1 || checkpoint.UpdatedAt.IsZero() {
		return errors.New("upgrade checkpoint identity, sequence, or timestamp is invalid")
	}
	if _, ok := upgradePhaseEdges[checkpoint.Phase]; !ok {
		if checkpoint.Phase != UpgradeSucceeded && checkpoint.Phase != UpgradeFailed && checkpoint.Phase != UpgradeCancelled {
			return errors.New("upgrade checkpoint phase is invalid")
		}
	}
	if len(checkpoint.NodeUID) > 128 || len(checkpoint.MachineID) > 128 || len(checkpoint.BootID) > 128 || len(checkpoint.ExecutionReference) > 256 || len(checkpoint.Reason) > 128 {
		return errors.New("upgrade checkpoint field exceeds its limit")
	}
	return nil
}

// UpgradePolicy is a bounded declarative plan for an Ansible Execution
// Environment. It contains no arbitrary playbook text, shell command, or key.
type UpgradePolicy struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	// +kubebuilder:validation:Enum=debian
	OSFamily string `json:"osFamily"`
	// +kubebuilder:validation:Enum=ansible-ee
	ExecutionBackend string `json:"executionBackend"`
	// +kubebuilder:validation:Enum=kordex.os-upgrade.debian.v1
	PlaybookCatalogID    string `json:"playbookCatalogId"`
	ExecutionEnvironment string `json:"executionEnvironment"`
	PlaybookDigest       string `json:"playbookDigest"`
	CollectionsDigest    string `json:"collectionsDigest"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	Packages []PackagePin `json:"packages"`
	// +kubebuilder:validation:Enum=stable
	Channel string `json:"channel"`
	// +kubebuilder:validation:Enum=Never;IfNeeded;Required
	Reboot RebootPolicy `json:"reboot"`
	// +kubebuilder:validation:MaxItems=0
	PreHooks []string `json:"preHooks,omitempty"`
	// +kubebuilder:validation:MaxItems=0
	PostHooks           []string      `json:"postHooks,omitempty"`
	ExecutionTimeout    time.Duration `json:"executionTimeout"`
	RebootTimeout       time.Duration `json:"rebootTimeout"`
	VerificationTimeout time.Duration `json:"verificationTimeout"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1
	MaxAttempts int `json:"maxAttempts"`
}

func (in *UpgradePolicy) DeepCopyInto(out *UpgradePolicy) {
	*out = *in
	if in.Packages != nil {
		out.Packages = append([]PackagePin(nil), in.Packages...)
	}
	if in.PreHooks != nil {
		out.PreHooks = append([]string(nil), in.PreHooks...)
	}
	if in.PostHooks != nil {
		out.PostHooks = append([]string(nil), in.PostHooks...)
	}
}

func (in *UpgradePolicy) DeepCopy() *UpgradePolicy {
	if in == nil {
		return nil
	}
	out := new(UpgradePolicy)
	in.DeepCopyInto(out)
	return out
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
var providerResourceToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var imageDigestRef = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$`)
var sha256Digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (p UpgradePolicy) Validate() error {
	if p.SchemaVersion != 1 || !policyToken.MatchString(p.ID) || len(p.Packages) == 0 || len(p.Packages) > 128 {
		return errors.New("invalid upgrade policy identity or package count")
	}
	if p.OSFamily != "debian" {
		return errors.New("the current Ansible EE executor supports Debian-family nodes only")
	}
	if p.ExecutionBackend != "ansible-ee" {
		return errors.New("self-managed upgrades require the Ansible Execution Environment backend")
	}
	if !imageDigestRef.MatchString(p.ExecutionEnvironment) || !sha256Digest.MatchString(p.PlaybookDigest) || !sha256Digest.MatchString(p.CollectionsDigest) {
		return errors.New("execution environment, playbook and collection digests must be pinned")
	}
	if p.PlaybookCatalogID != "kordex.os-upgrade.debian.v1" {
		return errors.New("playbook catalog does not match operating system family")
	}
	if p.Channel != "stable" {
		return errors.New("the initial Ansible EE catalog supports only the stable update channel")
	}
	if p.Reboot != RebootNever && p.Reboot != RebootIfNeeded && p.Reboot != RebootRequired {
		return errors.New("invalid reboot policy")
	}
	if p.ExecutionTimeout < time.Minute || p.ExecutionTimeout > 2*time.Hour || p.RebootTimeout < time.Minute || p.RebootTimeout > 2*time.Hour || p.VerificationTimeout < time.Minute || p.VerificationTimeout > 2*time.Hour || p.MaxAttempts != 1 {
		return errors.New("upgrade timeouts outside safe bounds or local attempts must equal one")
	}
	if len(p.PreHooks) != 0 || len(p.PostHooks) != 0 {
		return errors.New("the current Ansible EE catalog does not support hooks")
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
		if p.Reboot == RebootNever && isKernelPackage(item.Name) {
			return errors.New("kernel package upgrades require an explicit reboot policy")
		}
	}
	return nil
}

func isKernelPackage(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "linux-image") || strings.HasPrefix(name, "linux-modules") || name == "kernel" || strings.HasPrefix(name, "kernel-")
}

func (p UpgradePolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	packages := append([]PackagePin(nil), p.Packages...)
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	data := []byte(strconv.Itoa(p.SchemaVersion) + "\n" + p.ID + "\n" + p.OSFamily + "\n" + p.ExecutionBackend + "\n" + p.PlaybookCatalogID + "\n" + p.ExecutionEnvironment + "\n" + p.PlaybookDigest + "\n" + p.CollectionsDigest + "\n" + p.Channel + "\n" + string(p.Reboot) + "\n" + p.ExecutionTimeout.String() + "\n" + p.RebootTimeout.String() + "\n" + p.VerificationTimeout.String() + "\nattempts=" + strconv.Itoa(p.MaxAttempts))
	for _, item := range packages {
		data = append(data, []byte("\n"+item.Name+"="+item.Version)...)
	}
	pre, post := append([]string(nil), p.PreHooks...), append([]string(nil), p.PostHooks...)
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

type ProviderNodeUpgradePlan struct {
	SchemaVersion int           `json:"schemaVersion"`
	Provider      string        `json:"provider"`
	Resource      string        `json:"resource"`
	TargetVersion string        `json:"targetVersion"`
	Timeout       time.Duration `json:"timeout"`
}

func (p ProviderNodeUpgradePlan) Validate() error {
	if p.SchemaVersion != 1 || (p.Provider != "gke" && p.Provider != "eks" && p.Provider != "aks") {
		return errors.New("unsupported provider upgrade plan")
	}
	if !providerResourceToken.MatchString(p.Resource) || !versionToken.MatchString(p.TargetVersion) || isFloatingVersion(p.TargetVersion) {
		return errors.New("provider resource and target version must be explicit")
	}
	if p.Timeout < 5*time.Minute || p.Timeout > 24*time.Hour {
		return errors.New("provider upgrade timeout outside safe bounds")
	}
	return nil
}

func (p ProviderNodeUpgradePlan) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	data := []byte(strconv.Itoa(p.SchemaVersion) + "\n" + p.Provider + "\n" + p.Resource + "\n" + p.TargetVersion + "\n" + p.Timeout.String())
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func isFloatingVersion(version string) bool {
	switch strings.ToLower(version) {
	case "latest", "stable", "current", "*":
		return true
	default:
		return strings.ContainsAny(version, "*?")
	}
}
