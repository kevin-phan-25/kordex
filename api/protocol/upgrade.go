package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
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

// UpgradeReceiptEvidence is an immutable summary of one verified EE receipt.
// The full receipt stays in a cluster-local immutable ConfigMap; this summary
// is safe to forward through the agent and management-plane audit history.
type UpgradeReceiptEvidence struct {
	// +kubebuilder:validation:Enum=preflight;apply;reboot;inspect
	Phase string `json:"phase"`
	// +kubebuilder:validation:MaxLength=253
	Reference string `json:"reference"`
	// +kubebuilder:validation:Pattern="^[a-f0-9]{64}$"
	Digest string `json:"digest"`
	// +kubebuilder:validation:Pattern="^[a-fA-F0-9]{32}$"
	MachineID             string                `json:"machineId"`
	BootIDBefore          string                `json:"bootIdBefore"`
	BootIDAfter           string                `json:"bootIdAfter"`
	OSID                  string                `json:"osId,omitempty"`
	OSVersion             string                `json:"osVersion,omitempty"`
	OSPointRelease        string                `json:"osPointRelease,omitempty"`
	Architecture          string                `json:"architecture,omitempty"`
	ServiceManager        string                `json:"serviceManager,omitempty"`
	CgroupMode            string                `json:"cgroupMode,omitempty"`
	SELinuxMode           string                `json:"selinuxMode,omitempty"`
	FirewallState         string                `json:"firewallState,omitempty"`
	KernelVersion         string                `json:"kernelVersion,omitempty"`
	ExpectedKernelVersion string                `json:"expectedKernelVersion,omitempty"`
	Rebooted              bool                  `json:"rebooted,omitempty"`
	RebootRequired        bool                  `json:"rebootRequired,omitempty"`
	Packages              map[string]string     `json:"packages,omitempty"`
	ActionMarker          *ActionMarkerEvidence `json:"actionMarker,omitempty"`
	CompletedAt           metav1.Time           `json:"completedAt"`
}

// ActionMarkerEvidence identifies the durable root-owned host journal record
// observed or written by a marker-enabled Ansible catalog. SHA256 is computed
// over the exact marker file bytes and carried in the immutable EE receipt.
type ActionMarkerEvidence struct {
	Version      int    `json:"version"`
	OperationID  string `json:"operationId"`
	ActionDigest string `json:"actionDigest"`
	NodeUID      string `json:"nodeUid"`
	MachineID    string `json:"machineId"`
	BootID       string `json:"bootId"`
	Phase        string `json:"phase"`
	Sequence     int64  `json:"sequence"`
	SHA256       string `json:"sha256"`
}

func (m ActionMarkerEvidence) Validate() error {
	if m.Version != 1 || !ValidUUID(m.OperationID) || !ValidSHA256Digest(m.ActionDigest) || m.NodeUID == "" || len(m.NodeUID) > 128 || !machineIDToken.MatchString(m.MachineID) || !ValidUUID(m.BootID) || m.Sequence < 1 || !ValidSHA256Digest(m.SHA256) {
		return errors.New("host action marker identity is invalid")
	}
	switch m.Phase {
	case "apply-intent", "packages-verified", "reboot-intent", "reboot-verified":
	default:
		return errors.New("host action marker phase is invalid")
	}
	if m.Phase == "apply-intent" && m.Sequence != 1 || m.Phase == "packages-verified" && m.Sequence != 2 || m.Phase == "reboot-intent" && m.Sequence != 3 || m.Phase == "reboot-verified" && m.Sequence != 4 {
		return errors.New("host action marker sequence does not match phase")
	}
	return nil
}

func (in *UpgradeReceiptEvidence) DeepCopyInto(out *UpgradeReceiptEvidence) {
	*out = *in
	if in.Packages != nil {
		out.Packages = make(map[string]string, len(in.Packages))
		for name, version := range in.Packages {
			out.Packages[name] = version
		}
	}
	if in.ActionMarker != nil {
		marker := *in.ActionMarker
		out.ActionMarker = &marker
	}
	in.CompletedAt.DeepCopyInto(&out.CompletedAt)
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
	// +kubebuilder:validation:Enum=apply;reboot
	InterruptedPhase string `json:"interruptedPhase,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	RecoveryReference string `json:"recoveryReference,omitempty"`
	// Recovery attempts are read-only inspections. Changed trust material or an
	// explicit retry token creates a new identity, never package/reboot authority.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	RecoveryAttempt int32 `json:"recoveryAttempt,omitempty"`
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	RecoveryTrustDigest string `json:"recoveryTrustDigest,omitempty"`
	// RecoveryRetryToken records the operator-supplied, one-time authorization
	// to retry a read-only inspection after SSH transport becomes available.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	RecoveryRetryToken string `json:"recoveryRetryToken,omitempty"`
	// +kubebuilder:validation:MaxItems=4
	Receipts []UpgradeReceiptEvidence `json:"receipts,omitempty"`
	Outcome  string                   `json:"outcome,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	Reason    string      `json:"reason,omitempty"`
	UpdatedAt metav1.Time `json:"updatedAt"`
}

func (in *UpgradeCheckpoint) DeepCopy() *UpgradeCheckpoint {
	if in == nil {
		return nil
	}
	out := *in
	if in.Receipts != nil {
		out.Receipts = make([]UpgradeReceiptEvidence, len(in.Receipts))
		for i := range in.Receipts {
			in.Receipts[i].DeepCopyInto(&out.Receipts[i])
		}
	}
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
	if next.Sequence != previous.Sequence+1 || !next.UpdatedAt.After(previous.UpdatedAt.Time) || !(CanAdvanceUpgrade(previous.Phase, next.Phase) || previous.Phase == UpgradeRecoveryRequired && next.Phase == UpgradeRecoveryRequired) {
		return errors.New("invalid upgrade checkpoint sequence or phase transition")
	}
	if previous.MachineID != "" && previous.MachineID != next.MachineID {
		return errors.New("upgrade host machine identity changed")
	}
	if previous.InterruptedPhase != "" && previous.InterruptedPhase != next.InterruptedPhase || next.InterruptedPhase != "" && next.InterruptedPhase != "apply" && next.InterruptedPhase != "reboot" {
		return errors.New("upgrade interrupted phase changed or is invalid")
	}
	if previous.InterruptedPhase == "" && next.InterruptedPhase != "" && next.Phase != UpgradeRecoveryRequired {
		return errors.New("interrupted phase can only be recorded when entering recovery")
	}
	recoveryAdvance := recoveryInspectionAdvanceAllowed(previous, next)
	if previous.RecoveryReference != "" && previous.RecoveryReference != next.RecoveryReference && !recoveryAdvance {
		return errors.New("upgrade recovery reference changed outside a new read-only inspection attempt")
	}
	if previous.RecoveryAttempt != next.RecoveryAttempt && !recoveryAdvance {
		return errors.New("upgrade recovery attempt changed outside a new read-only inspection attempt")
	}
	if previous.RecoveryTrustDigest != "" && previous.RecoveryTrustDigest != next.RecoveryTrustDigest && !recoveryAdvance {
		return errors.New("upgrade recovery trust digest changed outside a new read-only inspection attempt")
	}
	if previous.RecoveryRetryToken != next.RecoveryRetryToken && !recoveryAdvance {
		return errors.New("upgrade recovery retry token changed outside a new read-only inspection attempt")
	}
	if next.RecoveryReference != "" && next.Phase != UpgradeRecoveryRequired && next.Phase != UpgradeVerifyingNode && next.Phase != UpgradeVerifyingWorkloads && next.Phase != UpgradeUncordoning && next.Phase != UpgradeCancelled && next.Phase != UpgradeFailed {
		return errors.New("upgrade recovery reference exists outside recovery lifecycle")
	}
	if len(next.Receipts) < len(previous.Receipts) || len(next.Receipts)-len(previous.Receipts) > 1 {
		return errors.New("upgrade receipt history cannot be removed or skipped")
	}
	for i := range previous.Receipts {
		if !reflect.DeepEqual(previous.Receipts[i], next.Receipts[i]) {
			return errors.New("upgrade receipt history is immutable")
		}
	}
	if previous.Phase == UpgradeExecuting && next.Phase == UpgradeRebooting && (next.MachineID == "" || !next.RebootRequested) {
		return errors.New("machine identity and explicit reboot intent are required before reboot")
	}
	bootChanged := previous.BootID != "" && previous.BootID != next.BootID
	if previous.Phase == UpgradeRebooting && next.Phase == UpgradeVerifyingNode {
		if !previous.RebootRequested || !bootChanged {
			return errors.New("reboot verification requires a requested reboot and changed boot ID")
		}
	} else if previous.Phase == UpgradeRecoveryRequired && next.Phase == UpgradeVerifyingNode {
		if previous.RecoveryReference == "" || previous.InterruptedPhase == "" || len(next.Receipts) != len(previous.Receipts)+1 {
			return errors.New("ambiguous execution recovery requires a durable inspection reference and receipt")
		}
		evidence := next.Receipts[len(next.Receipts)-1]
		if evidence.Phase != "inspect" || evidence.MachineID != next.MachineID || evidence.BootIDAfter != next.BootID {
			return errors.New("ambiguous execution recovery receipt does not prove the checkpoint identity")
		}
		if previous.InterruptedPhase == "reboot" {
			if !previous.RebootRequested || !bootChanged {
				return errors.New("interrupted reboot recovery requires requested reboot and changed boot ID")
			}
		} else {
			if bootChanged {
				return errors.New("boot identity changed outside an interrupted reboot")
			}
			if evidence.RebootRequired {
				return errors.New("recovery cannot uncordon while package evidence requires a reboot")
			}
		}
	} else if bootChanged {
		return errors.New("boot identity changed outside reboot verification")
	}
	return nil
}

// ValidateProviderUpgradeCheckpointAdvance protects the central audit copy of
// a provider lifecycle checkpoint from regressions and identity rewrites. The
// operator remains the source of execution evidence; the control plane checks
// that each later report only advances that evidence monotonically.
func ValidateProviderUpgradeCheckpointAdvance(previous, next ProviderUpgradeCheckpoint) error {
	return validateReportedProviderCheckpointAdvance(previous, next)
}

// ValidateOperationCheckpointAdvance checks that a later signed agent report
// does not erase or rewrite lifecycle evidence. A first checkpoint can be
// observed after earlier local reconciles because agent sync is periodic, so
// its self-contained schema is validated by OperationReport.Validate; all
// subsequent changes must move forward through reachable phases while keeping
// identity, cancellation, and receipt evidence immutable.
func ValidateOperationCheckpointAdvance(previous, next OperationReport) error {
	if previous.UpgradeCheckpoint != nil && next.UpgradeCheckpoint == nil || previous.ProviderUpgradeCheckpoint != nil && next.ProviderUpgradeCheckpoint == nil {
		return errors.New("operation checkpoint was removed")
	}
	if previous.UpgradeCheckpoint != nil && next.ProviderUpgradeCheckpoint != nil || previous.ProviderUpgradeCheckpoint != nil && next.UpgradeCheckpoint != nil {
		return errors.New("operation checkpoint type changed")
	}
	if previous.UpgradeCheckpoint != nil && next.UpgradeCheckpoint != nil && !reflect.DeepEqual(previous.UpgradeCheckpoint, next.UpgradeCheckpoint) {
		return validateReportedUpgradeCheckpointAdvance(*previous.UpgradeCheckpoint, *next.UpgradeCheckpoint)
	}
	if previous.ProviderUpgradeCheckpoint != nil && next.ProviderUpgradeCheckpoint != nil && !reflect.DeepEqual(previous.ProviderUpgradeCheckpoint, next.ProviderUpgradeCheckpoint) {
		return ValidateProviderUpgradeCheckpointAdvance(*previous.ProviderUpgradeCheckpoint, *next.ProviderUpgradeCheckpoint)
	}
	return nil
}

func validateReportedUpgradeCheckpointAdvance(previous, next UpgradeCheckpoint) error {
	if err := ValidateUpgradeCheckpoint(previous); err != nil {
		return err
	}
	if err := ValidateUpgradeCheckpoint(next); err != nil {
		return err
	}
	if next.Sequence <= previous.Sequence || !next.UpdatedAt.After(previous.UpdatedAt.Time) || previous.PlanDigest != next.PlanDigest || previous.NodeUID != next.NodeUID {
		return errors.New("reported upgrade checkpoint identity, sequence, or timestamp regressed")
	}
	if !upgradePhaseReachable(previous.Phase, next.Phase) {
		return errors.New("reported upgrade checkpoint phase is not forward reachable")
	}
	recoveryAdvance := recoveryInspectionAdvanceAllowed(previous, next)
	if previous.MachineID != "" && previous.MachineID != next.MachineID || previous.InterruptedPhase != "" && previous.InterruptedPhase != next.InterruptedPhase || previous.RecoveryReference != "" && previous.RecoveryReference != next.RecoveryReference && !recoveryAdvance || previous.RecoveryAttempt != next.RecoveryAttempt && !recoveryAdvance || previous.RecoveryTrustDigest != "" && previous.RecoveryTrustDigest != next.RecoveryTrustDigest && !recoveryAdvance || previous.RecoveryRetryToken != next.RecoveryRetryToken && !recoveryAdvance || previous.RebootRequested && !next.RebootRequested {
		return errors.New("reported upgrade checkpoint immutable evidence changed")
	}
	if len(next.Receipts) < len(previous.Receipts) {
		return errors.New("reported upgrade receipt history was removed")
	}
	for i := range previous.Receipts {
		if !reflect.DeepEqual(previous.Receipts[i], next.Receipts[i]) {
			return errors.New("reported upgrade receipt history was rewritten")
		}
	}
	if next.BootID != previous.BootID {
		if !next.RebootRequested || previous.InterruptedPhase != "reboot" && !upgradePhaseReachable(previous.Phase, UpgradeRebooting) {
			return errors.New("reported boot identity changed outside a requested reboot")
		}
		if previous.InterruptedPhase == "reboot" && !upgradePhaseReachable(UpgradeVerifyingNode, next.Phase) {
			return errors.New("reported interrupted reboot advanced without node verification")
		}
		verified := false
		for i := len(previous.Receipts); i < len(next.Receipts); i++ {
			receipt := next.Receipts[i]
			if receipt.BootIDAfter != next.BootID || receipt.MachineID != next.MachineID {
				continue
			}
			if receipt.Phase == "reboot" && receipt.Rebooted && receipt.BootIDBefore != receipt.BootIDAfter && upgradePhaseReachable(UpgradeVerifyingNode, next.Phase) || receipt.Phase == "inspect" && previous.InterruptedPhase == "reboot" {
				verified = true
			}
		}
		if !verified {
			return errors.New("reported boot identity change lacks new reboot or recovery evidence")
		}
	}
	return nil
}

func recoveryInspectionAdvanceAllowed(previous, next UpgradeCheckpoint) bool {
	if previous.Phase != UpgradeRecoveryRequired || next.Phase != UpgradeRecoveryRequired || next.RecoveryAttempt != previous.RecoveryAttempt+1 || next.RecoveryReference == "" || !ValidSHA256Digest(next.RecoveryTrustDigest) || len(next.Receipts) != len(previous.Receipts) || previous.InterruptedPhase != next.InterruptedPhase {
		return false
	}
	if previous.RecoveryReference == "" {
		return previous.RecoveryAttempt == 0 && previous.RecoveryTrustDigest == "" && previous.RecoveryRetryToken == ""
	}
	if next.RecoveryReference == previous.RecoveryReference {
		return false
	}
	if next.RecoveryTrustDigest != previous.RecoveryTrustDigest {
		return true
	}
	return ValidUUID(next.RecoveryRetryToken) && next.RecoveryRetryToken != previous.RecoveryRetryToken
}

func upgradePhaseReachable(from, to UpgradePhase) bool {
	if from == to {
		return true
	}
	seen := map[UpgradePhase]struct{}{from: {}}
	queue := []UpgradePhase{from}
	for len(queue) > 0 {
		phase := queue[0]
		queue = queue[1:]
		for next := range upgradePhaseEdges[phase] {
			if next == to {
				return true
			}
			if _, ok := seen[next]; !ok {
				seen[next] = struct{}{}
				queue = append(queue, next)
			}
		}
	}
	return false
}

func validateReportedProviderCheckpointAdvance(previous, next ProviderUpgradeCheckpoint) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	if next.Sequence <= previous.Sequence || !next.UpdatedAt.After(previous.UpdatedAt.Time) || previous.PlanDigest != next.PlanDigest || previous.Resource != next.Resource || previous.TargetVersion != next.TargetVersion {
		return errors.New("reported provider checkpoint identity, sequence, or timestamp regressed")
	}
	if !providerPhaseReachable(previous.Phase, next.Phase) {
		return errors.New("reported provider checkpoint phase is not forward reachable")
	}
	if previous.InitialVersion != "" && previous.InitialVersion != next.InitialVersion || previous.OperationName != "" && previous.OperationName != next.OperationName || !previous.IntentAt.IsZero() && !next.IntentAt.Equal(&previous.IntentAt) {
		return errors.New("reported provider checkpoint evidence changed")
	}
	if len(previous.InitialNodeIdentityDigests) > 0 && !reflect.DeepEqual(previous.InitialNodeIdentityDigests, next.InitialNodeIdentityDigests) {
		return errors.New("reported provider node identity evidence changed")
	}
	if previous.CancelRequested && !next.CancelRequested {
		return errors.New("reported provider cancellation request was removed")
	}
	return nil
}

func providerPhaseReachable(from, to string) bool {
	if from == to {
		return true
	}
	edges := map[string][]string{
		"Pending":          {"Submitting", "Verifying", "Cancelled", "RecoveryRequired"},
		"Submitting":       {"Updating", "RecoveryRequired"},
		"Updating":         {"Verifying", "RecoveryRequired"},
		"Verifying":        {"Succeeded", "RecoveryRequired"},
		"RecoveryRequired": {"RecoveryRequired"},
	}
	seen := map[string]struct{}{from: {}}
	queue := []string{from}
	for len(queue) > 0 {
		phase := queue[0]
		queue = queue[1:]
		for _, next := range edges[phase] {
			if next == to {
				return true
			}
			if _, ok := seen[next]; !ok {
				seen[next] = struct{}{}
				queue = append(queue, next)
			}
		}
	}
	return false
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
	if len(checkpoint.NodeUID) > 128 || len(checkpoint.MachineID) > 128 || len(checkpoint.BootID) > 128 || len(checkpoint.ExecutionReference) > 256 || len(checkpoint.Reason) > 128 || len(checkpoint.RecoveryReference) > 253 || checkpoint.RecoveryAttempt < 0 || checkpoint.RecoveryAttempt > 100 || checkpoint.RecoveryRetryToken != "" && !ValidUUID(checkpoint.RecoveryRetryToken) || (checkpoint.InterruptedPhase != "" && checkpoint.InterruptedPhase != "apply" && checkpoint.InterruptedPhase != "reboot") {
		return errors.New("upgrade checkpoint field exceeds its limit")
	}
	if checkpoint.RecoveryAttempt == 0 && checkpoint.RecoveryTrustDigest != "" || checkpoint.RecoveryAttempt > 0 && (checkpoint.RecoveryReference == "" || !ValidSHA256Digest(checkpoint.RecoveryTrustDigest)) {
		return errors.New("upgrade recovery attempt and trust identity are inconsistent")
	}
	if len(checkpoint.Receipts) > 4 {
		return errors.New("upgrade receipt history exceeds its limit")
	}
	seenReceiptPhases := make(map[string]struct{}, len(checkpoint.Receipts))
	for _, receipt := range checkpoint.Receipts {
		if (receipt.Phase != "preflight" && receipt.Phase != "apply" && receipt.Phase != "reboot" && receipt.Phase != "inspect") || !validName(receipt.Reference, 253) || !ValidSHA256Digest(receipt.Digest) || !machineIDToken.MatchString(receipt.MachineID) || !ValidUUID(receipt.BootIDBefore) || !ValidUUID(receipt.BootIDAfter) || receipt.CompletedAt.IsZero() || len(receipt.Packages) > 128 || receipt.KernelVersion != "" && !kernelVersionToken.MatchString(receipt.KernelVersion) || receipt.ExpectedKernelVersion != "" && !kernelVersionToken.MatchString(receipt.ExpectedKernelVersion) {
			return errors.New("upgrade receipt evidence is invalid")
		}
		if receipt.OSID != "" && (!validName(receipt.OSID, 32) || !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`).MatchString(receipt.OSVersion) ||
			!regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`).MatchString(receipt.OSPointRelease) ||
			receipt.Architecture != "amd64" || receipt.ServiceManager != "systemd" ||
			(receipt.CgroupMode != "v1" && receipt.CgroupMode != "v2") ||
			(receipt.SELinuxMode != "Enforcing" && receipt.SELinuxMode != "NotApplicable") ||
			(receipt.FirewallState != "active" && receipt.FirewallState != "not-applicable")) {
			return errors.New("upgrade receipt platform identity evidence is invalid")
		}
		if receipt.ActionMarker != nil {
			if err := receipt.ActionMarker.Validate(); err != nil || receipt.ActionMarker.ActionDigest != checkpoint.PlanDigest || receipt.ActionMarker.NodeUID != checkpoint.NodeUID || receipt.ActionMarker.MachineID != receipt.MachineID {
				return errors.New("upgrade receipt action marker does not match checkpoint identity")
			}
			switch receipt.Phase {
			case "apply":
				if receipt.ActionMarker.Phase != "packages-verified" || receipt.ActionMarker.Sequence != 2 || receipt.ActionMarker.BootID != receipt.BootIDBefore {
					return errors.New("apply receipt marker is not package-verification evidence")
				}
			case "reboot":
				if receipt.ActionMarker.Phase != "reboot-verified" || receipt.ActionMarker.Sequence != 4 || receipt.ActionMarker.BootID != receipt.BootIDAfter {
					return errors.New("reboot receipt marker is not post-reboot evidence")
				}
			}
		}
		if _, exists := seenReceiptPhases[receipt.Phase]; exists {
			return errors.New("duplicate upgrade receipt phase")
		}
		seenReceiptPhases[receipt.Phase] = struct{}{}
		switch receipt.Phase {
		case "preflight":
			if len(receipt.Packages) != 0 || receipt.Rebooted || receipt.RebootRequired || receipt.BootIDBefore != receipt.BootIDAfter {
				return errors.New("preflight receipt evidence is inconsistent")
			}
		case "apply":
			if len(receipt.Packages) == 0 || receipt.Rebooted || receipt.BootIDBefore != receipt.BootIDAfter {
				return errors.New("package receipt evidence is inconsistent")
			}
		case "reboot":
			if len(receipt.Packages) == 0 || !receipt.Rebooted || !receipt.RebootRequired || receipt.BootIDBefore == receipt.BootIDAfter {
				return errors.New("reboot receipt evidence is inconsistent")
			}
			if receipt.ExpectedKernelVersion != "" && receipt.KernelVersion != receipt.ExpectedKernelVersion {
				return errors.New("reboot receipt does not prove the expected kernel is running")
			}
		case "inspect":
			if len(receipt.Packages) == 0 || receipt.Rebooted || receipt.BootIDBefore != receipt.BootIDAfter {
				return errors.New("read-only recovery receipt evidence is inconsistent")
			}
		}
		for name, version := range receipt.Packages {
			if !packageToken.MatchString(name) || name != strings.ToLower(name) || !packageVersionToken.MatchString(version) || isFloatingVersion(version) {
				return errors.New("upgrade receipt package evidence is invalid")
			}
		}
	}
	return nil
}

// UpgradePolicy is a bounded declarative plan for an Ansible Execution
// Environment. It contains no arbitrary playbook text, shell command, or key.
type UpgradePolicy struct {
	// Schema version 1 resolves packages through the node's configured package
	// repositories. Version 2 is the offline-artifact contract: every package
	// must be staged locally and SHA-256 pinned.
	// +kubebuilder:validation:Enum=1;2
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	// +kubebuilder:validation:Enum=debian;rhel
	OSFamily string `json:"osFamily"`
	// OSID/OSMajor/OSMinor bind the normalized distribution release to the
	// signed plan. Debian 13 also binds its selected stable point release;
	// RHEL 9 binds the exact selected minor release.
	// +kubebuilder:validation:Enum=ubuntu;debian;rhel;amzn
	OSID string `json:"osId"`
	// +kubebuilder:validation:Pattern="^[0-9]{1,4}$"
	OSMajor string `json:"osMajor"`
	// +kubebuilder:validation:Pattern="^([0-9]{1,2})?$"
	OSMinor string `json:"osMinor,omitempty"`
	// OSPointRelease binds the selected Debian 13 stable point or exact RHEL 9
	// minor into the signed plan digest. Supplemental Ubuntu and AL2023 leave it empty.
	// +kubebuilder:validation:Pattern="^([0-9]+\\.[0-9]+)?$"
	OSPointRelease string `json:"osPointRelease,omitempty"`
	// +kubebuilder:validation:Enum=ansible-ee
	ExecutionBackend string `json:"executionBackend"`
	// +kubebuilder:validation:Enum=kordex.os-upgrade.debian.v2;kordex.os-upgrade.rhel.v1
	PlaybookCatalogID    string `json:"playbookCatalogId"`
	ExecutionEnvironment string `json:"executionEnvironment"`
	PlaybookDigest       string `json:"playbookDigest"`
	CollectionsDigest    string `json:"collectionsDigest"`
	// ActionMarkerVersion selects the durable host-side operation journal.
	// Version 1 is mandatory for every executable host-upgrade plan.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1
	ActionMarkerVersion int `json:"actionMarkerVersion,omitempty"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	Packages []PackagePin `json:"packages"`
	// ArtifactMode is required for schema version 2. OfflineArtifacts prohibits
	// package repository access and installs only hash-verified local artifacts.
	// +kubebuilder:validation:Enum=OfflineArtifacts
	ArtifactMode string `json:"artifactMode,omitempty"`
	// ExpectedKernelVersion binds a kernel package plan to the kernel that must
	// be running before the operator can complete recovery and uncordon.
	ExpectedKernelVersion string `json:"expectedKernelVersion,omitempty"`
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

// HostOSIdentity is the normalized OS ID and release identity used by the
// fixed self-managed host-upgrade catalogs.
type HostOSIdentity struct {
	ID    string
	Major string
	Minor string
}

var hostOSImagePatterns = []struct {
	id      string
	pattern *regexp.Regexp
}{
	{"ubuntu", regexp.MustCompile(`^ubuntu(?: linux)?\s+([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:\s|$)`)},
	{"debian", regexp.MustCompile(`^debian(?: gnu/linux)?\s+([0-9]+)(?:\D|$)`)},
	{"rhel", regexp.MustCompile(`^(?:red hat enterprise linux|rhel)\s+([0-9]+)\.([0-9]+)(?:\D|$)`)},
	{"rocky", regexp.MustCompile(`^rocky linux\s+([0-9]+)\.([0-9]+)(?:\D|$)`)},
	{"almalinux", regexp.MustCompile(`^(?:almalinux|alma linux)\s+([0-9]+)\.([0-9]+)(?:\D|$)`)},
	{"amzn", regexp.MustCompile(`^amazon linux\s+(2023)(?:\.|\D|$)`)},
}

// ParseHostOSImage accepts only the explicit image-name forms emitted for the
// cataloged mutable distributions. It deliberately does not infer ID_LIKE or
// accept arbitrary substring matches.
func ParseHostOSImage(osImage string) (HostOSIdentity, bool) {
	image := strings.ToLower(strings.TrimSpace(osImage))
	for _, pattern := range hostOSImagePatterns {
		match := pattern.pattern.FindStringSubmatch(image)
		if match == nil {
			continue
		}
		identity := HostOSIdentity{ID: pattern.id, Major: match[1]}
		if len(match) > 2 {
			identity.Minor = match[2]
		}
		return identity, true
	}
	return HostOSIdentity{}, false
}

func supportedHostOSIdentity(family, id, major, minor string) bool {
	switch id {
	case "ubuntu":
		return family == "debian" && major == "24" && minor == "04"
	case "debian":
		return family == "debian" && major == "13" && minor == ""
	case "rhel":
		if family != "rhel" || major != "9" || minor == "" {
			return false
		}
		value, err := strconv.Atoi(minor)
		return err == nil && value >= 8
	case "amzn":
		return family == "rhel" && major == "2023" && minor == ""
	default:
		return false
	}
}

// MatchesNodeOS routes only when inventory identifies the exact release tuple
// bound into the signed policy. The EE playbook repeats this check against live
// Ansible facts before package or reboot operations.
func (p UpgradePolicy) MatchesNodeOS(node Node) bool {
	if strings.EqualFold(node.Labels["kubernetes.io/os"], "windows") {
		return false
	}
	identity, ok := ParseHostOSImage(node.OSImage)
	return ok && supportedHostOSIdentity(p.OSFamily, p.OSID, p.OSMajor, p.OSMinor) &&
		identity.ID == p.OSID && identity.Major == p.OSMajor && identity.Minor == p.OSMinor
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
	// +kubebuilder:validation:Pattern="^[a-z0-9][a-z0-9+_.-]{0,127}(:[a-z0-9][a-z0-9_-]{0,31})?$"
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern="^([0-9]+:)?[0-9][A-Za-z0-9.+:~_-]{0,127}$"
	Version string `json:"version"`
	// ArtifactSHA256 binds the exact local .deb or .rpm payload for schema v2.
	// +kubebuilder:validation:Pattern="^[a-f0-9]{64}$"
	ArtifactSHA256 string `json:"artifactSHA256,omitempty"`
}

type RebootPolicy string

const (
	RebootNever    RebootPolicy = "Never"
	RebootIfNeeded RebootPolicy = "IfNeeded"
	RebootRequired RebootPolicy = "Required"
)

var packageToken = regexp.MustCompile(`^[a-z0-9][a-z0-9+_.-]{0,127}(?::[a-z0-9][a-z0-9_-]{0,31})?$`)
var packageVersionToken = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+:~_-]{0,127}$`)
var rpmEVRToken = regexp.MustCompile(`^([0-9]+:)?[0-9][A-Za-z0-9.+~_^]*-[A-Za-z0-9][A-Za-z0-9.+~_^.-]*$`)
var versionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:~^-]{0,127}$`)
var kernelVersionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$`)
var machineIDToken = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)
var policyToken = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
var providerResourceToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var gkeVersionToken = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-gke\.[0-9]+$`)
var gkeProjectToken = regexp.MustCompile(`^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$`)
var gkeLocationToken = regexp.MustCompile(`^[a-z]+-[a-z0-9-]+$`)
var imageDigestRef = regexp.MustCompile(`^[A-Za-z0-9.-]+(?::[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[a-f0-9]{64}$`)
var sha256Digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ValidKernelVersion(version string) bool { return kernelVersionToken.MatchString(version) }

func (p UpgradePolicy) Validate() error {
	if (p.SchemaVersion != 1 && p.SchemaVersion != 2) || !policyToken.MatchString(p.ID) || len(p.Packages) == 0 || len(p.Packages) > 128 {
		return errors.New("invalid upgrade policy identity or package count")
	}
	if p.SchemaVersion == 1 && p.ArtifactMode != "" || p.SchemaVersion == 2 && p.ArtifactMode != "OfflineArtifacts" {
		return errors.New("upgrade artifact mode does not match policy schema version")
	}
	if p.OSFamily != "debian" && p.OSFamily != "rhel" {
		return errors.New("unsupported self-managed Linux OS family")
	}
	if !supportedHostOSIdentity(p.OSFamily, p.OSID, p.OSMajor, p.OSMinor) {
		return errors.New("unsupported or incomplete self-managed Linux OS identity")
	}
	switch p.OSID {
	case "debian":
		if !regexp.MustCompile(`^13\.[0-9]+$`).MatchString(p.OSPointRelease) {
			return errors.New("Debian 13 upgrade policy must bind its selected stable point release")
		}
	case "rhel":
		if p.OSPointRelease != "9."+p.OSMinor {
			return errors.New("RHEL upgrade policy point release must match its selected minor release")
		}
	case "ubuntu", "amzn":
		if p.OSPointRelease != "" {
			return errors.New("supplemental Ubuntu and Amazon Linux policy must not set an OS point release")
		}
	}
	if p.ExecutionBackend != "ansible-ee" {
		return errors.New("self-managed upgrades require the Ansible Execution Environment backend")
	}
	if p.ActionMarkerVersion != 1 {
		return errors.New("host upgrades require action marker version 1")
	}
	if !imageDigestRef.MatchString(p.ExecutionEnvironment) || !sha256Digest.MatchString(p.PlaybookDigest) || !sha256Digest.MatchString(p.CollectionsDigest) {
		return errors.New("execution environment, playbook and collection digests must be pinned")
	}
	if p.OSFamily == "debian" && p.PlaybookCatalogID != "kordex.os-upgrade.debian.v2" ||
		p.OSFamily == "rhel" && p.PlaybookCatalogID != "kordex.os-upgrade.rhel.v1" {
		return errors.New("playbook catalog does not match operating system family")
	}
	if p.Channel != "stable" {
		return errors.New("the fixed Ansible EE catalogs support only the stable update channel")
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
	hasKernelPackage := false
	for _, item := range p.Packages {
		if !packageToken.MatchString(item.Name) || item.Name != strings.ToLower(item.Name) || !packageVersionToken.MatchString(item.Version) || isFloatingVersion(item.Version) {
			return errors.New("invalid package name or pinned version")
		}
		if p.OSFamily == "rhel" && !rpmEVRToken.MatchString(item.Version) {
			return errors.New("RHEL packages require an exact RPM epoch, version, and release pin")
		}
		if p.OSFamily == "debian" && strings.Contains(item.Name, "_") {
			return errors.New("invalid Debian package name")
		}
		if _, exists := seen[item.Name]; exists {
			return errors.New("duplicate package in upgrade policy")
		}
		seen[item.Name] = struct{}{}
		if p.SchemaVersion == 1 && item.ArtifactSHA256 != "" || p.SchemaVersion == 2 && !sha256Digest.MatchString(item.ArtifactSHA256) {
			return errors.New("offline artifact package pins require a SHA-256 digest")
		}
		if isKernelPackage(item.Name) {
			hasKernelPackage = true
			if p.Reboot == RebootNever {
				return errors.New("kernel package upgrades require an explicit reboot policy")
			}
		}
	}
	if hasKernelPackage != (p.ExpectedKernelVersion != "") || p.ExpectedKernelVersion != "" && !kernelVersionToken.MatchString(p.ExpectedKernelVersion) {
		return errors.New("kernel package plans require one exact expected running kernel version")
	}
	return nil
}

func isKernelPackage(name string) bool {
	name = strings.ToLower(name)
	name, _, _ = strings.Cut(name, ":")
	if strings.HasPrefix(name, "kernel-") || name == "kernel" {
		return true
	}
	for _, family := range []string{"linux-image", "linux-modules", "linux-headers", "linux-generic", "linux-virtual", "linux-lowlatency", "linux-oem", "linux-signed", "linux-azure", "linux-gcp", "linux-kvm", "linux-cloud-tools", "linux-tools", "linux-firmware"} {
		if name == family || strings.HasPrefix(name, family+"-") {
			return true
		}
	}
	return false
}

func (p UpgradePolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	packages := append([]PackagePin(nil), p.Packages...)
	sort.Slice(packages, func(i, j int) bool { return packages[i].Name < packages[j].Name })
	data := []byte(strconv.Itoa(p.SchemaVersion) + "\n" + p.ID + "\n" + p.OSFamily + "\n" + p.OSID + "\n" + p.OSMajor + "\n" + p.OSMinor + "\n" + p.OSPointRelease + "\n" + p.ExecutionBackend + "\n" + p.PlaybookCatalogID + "\n" + p.ExecutionEnvironment + "\n" + p.PlaybookDigest + "\n" + p.CollectionsDigest + "\n" + p.Channel + "\n" + string(p.Reboot) + "\n" + p.ExecutionTimeout.String() + "\n" + p.RebootTimeout.String() + "\n" + p.VerificationTimeout.String() + "\nattempts=" + strconv.Itoa(p.MaxAttempts))
	if p.ActionMarkerVersion != 0 {
		data = append(data, []byte("\nmarker="+strconv.Itoa(p.ActionMarkerVersion))...)
	}
	if p.SchemaVersion == 2 {
		data = append(data, []byte("\nartifactMode="+p.ArtifactMode)...)
	}
	if p.ExpectedKernelVersion != "" {
		data = append(data, []byte("\nkernel="+p.ExpectedKernelVersion)...)
	}
	for _, item := range packages {
		pin := item.Name + "=" + item.Version
		if p.SchemaVersion == 2 {
			pin += "@sha256:" + item.ArtifactSHA256
		}
		data = append(data, []byte("\n"+pin)...)
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
	// +kubebuilder:validation:Enum=2
	SchemaVersion int    `json:"schemaVersion"`
	Provider      string `json:"provider"`
	Resource      string `json:"resource"`
	TargetVersion string `json:"targetVersion"`
	// GKE surge settings are pinned in the policy digest and must match the
	// existing node-pool configuration before the provider update is submitted.
	// The first GKE adapter supports only one surge node and zero unavailable.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1
	MaxSurge int `json:"maxSurge"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=0
	MaxUnavailable int           `json:"maxUnavailable"`
	Timeout        time.Duration `json:"timeout"`
}

// ProviderUpgradeCheckpoint is the durable pool-scoped lifecycle record for
// provider APIs that replace nodes. It intentionally has no NodeUID field:
// Kubernetes node UIDs are expected to change during a managed pool upgrade.
type ProviderUpgradeCheckpoint struct {
	PlanDigest     string `json:"planDigest"`
	Resource       string `json:"resource"`
	TargetVersion  string `json:"targetVersion"`
	InitialVersion string `json:"initialVersion,omitempty"`
	// InitialNodeIdentityDigests contains bounded SHA-256 digests of the
	// provider ID, Kubernetes UID, machine ID, and boot ID before mutation.
	InitialNodeIdentityDigests []string    `json:"initialNodeIdentityDigests,omitempty"`
	Phase                      string      `json:"phase"`
	Sequence                   int64       `json:"sequence"`
	OperationName              string      `json:"operationName,omitempty"`
	IntentAt                   metav1.Time `json:"intentAt,omitempty"`
	UpdatedAt                  metav1.Time `json:"updatedAt"`
	Reason                     string      `json:"reason,omitempty"`
	CancelRequested            bool        `json:"cancelRequested,omitempty"`
}

func (c ProviderUpgradeCheckpoint) Validate() error {
	if !ValidSHA256Digest(c.PlanDigest) || c.Resource == "" || len(c.Resource) > 512 || c.TargetVersion == "" || len(c.TargetVersion) > 128 || c.Sequence < 1 || c.UpdatedAt.IsZero() || len(c.Reason) > 128 {
		return errors.New("invalid provider upgrade checkpoint identity")
	}
	switch c.Phase {
	case "Pending", "Submitting", "Updating", "Verifying", "Succeeded", "RecoveryRequired", "Failed", "Cancelled":
	default:
		return errors.New("invalid provider upgrade checkpoint phase")
	}
	if c.OperationName != "" && (len(c.OperationName) > 512 || !strings.HasPrefix(c.OperationName, "projects/")) {
		return errors.New("invalid provider operation identity")
	}
	if len(c.InitialNodeIdentityDigests) > 5000 {
		return errors.New("provider initial node identity set exceeds bound")
	}
	seen := make(map[string]struct{}, len(c.InitialNodeIdentityDigests))
	for _, digest := range c.InitialNodeIdentityDigests {
		if !ValidSHA256Digest(digest) {
			return errors.New("provider initial node identity digest is invalid")
		}
		if _, exists := seen[digest]; exists {
			return errors.New("provider initial node identity digest is duplicated")
		}
		seen[digest] = struct{}{}
	}
	if (c.Phase == "Submitting" || c.Phase == "Updating" || c.Phase == "Verifying") && len(c.InitialNodeIdentityDigests) == 0 {
		return errors.New("provider node identity evidence is required after submission")
	}
	if c.Phase == "Submitting" && c.IntentAt.IsZero() {
		return errors.New("provider submission intent timestamp is required")
	}
	return nil
}

func (c *ProviderUpgradeCheckpoint) DeepCopy() *ProviderUpgradeCheckpoint {
	if c == nil {
		return nil
	}
	out := *c
	if c.InitialNodeIdentityDigests != nil {
		out.InitialNodeIdentityDigests = append([]string(nil), c.InitialNodeIdentityDigests...)
	}
	c.IntentAt.DeepCopyInto(&out.IntentAt)
	c.UpdatedAt.DeepCopyInto(&out.UpdatedAt)
	return &out
}

type GKENodePoolReference struct {
	Project  string
	Location string
	Cluster  string
	NodePool string
}

// GKENodePool parses the canonical GKE resource path. A short pool name is not
// sufficient authorization for a provider operation because it is ambiguous
// across projects, locations, and clusters.
func (p ProviderNodeUpgradePlan) GKENodePool() (GKENodePoolReference, bool) {
	if p.Provider != "gke" {
		return GKENodePoolReference{}, false
	}
	parts := strings.Split(p.Resource, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "clusters" || parts[6] != "nodePools" {
		return GKENodePoolReference{}, false
	}
	if !gkeProjectToken.MatchString(parts[1]) || !gkeLocationToken.MatchString(parts[3]) || len(validation.IsDNS1123Subdomain(parts[5])) != 0 || len(validation.IsDNS1123Subdomain(parts[7])) != 0 {
		return GKENodePoolReference{}, false
	}
	return GKENodePoolReference{Project: parts[1], Location: parts[3], Cluster: parts[5], NodePool: parts[7]}, true
}

// MatchesInventory ties a provider plan to fresh local node inventory before
// it can enter a campaign snapshot. ProviderID and topology are required; a
// missing value is unknown evidence, not permission.
func (p ProviderNodeUpgradePlan) MatchesInventory(clusterProvider, clusterName string, node Node) bool {
	ref, ok := p.GKENodePool()
	if !ok || clusterProvider != "gke" || clusterName != ref.Cluster || node.ProviderID == "" || node.Zone == "" || node.Labels["cloud.google.com/gke-nodepool"] != ref.NodePool {
		return false
	}
	const prefix = "gce://"
	if !strings.HasPrefix(node.ProviderID, prefix) {
		return false
	}
	identity := strings.Split(strings.TrimPrefix(node.ProviderID, prefix), "/")
	if len(identity) != 3 || identity[0] != ref.Project || identity[1] != node.Zone {
		return false
	}
	if ref.Location != identity[1] && !strings.HasPrefix(identity[1], ref.Location+"-") {
		return false
	}
	return identity[2] != ""
}

func (p ProviderNodeUpgradePlan) Validate() error {
	if p.SchemaVersion != 2 || p.Provider != "gke" {
		return errors.New("unsupported provider upgrade plan")
	}
	if !providerResourceToken.MatchString(p.Resource) || !versionToken.MatchString(p.TargetVersion) || isFloatingVersion(p.TargetVersion) {
		return errors.New("provider resource and target version must be explicit")
	}
	if p.Provider == "gke" {
		if _, ok := p.GKENodePool(); !ok {
			return errors.New("GKE provider resource must be a canonical node-pool path")
		}
		if !gkeVersionToken.MatchString(p.TargetVersion) {
			return errors.New("GKE target version must be an explicit x.y.z-gke.n release")
		}
		if p.MaxSurge != 1 || p.MaxUnavailable != 0 {
			return errors.New("GKE upgrades require pinned SURGE settings maxSurge=1 and maxUnavailable=0")
		}
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
	data := []byte(strconv.Itoa(p.SchemaVersion) + "\n" + p.Provider + "\n" + p.Resource + "\n" + p.TargetVersion + "\n" + strconv.Itoa(p.MaxSurge) + "\n" + strconv.Itoa(p.MaxUnavailable) + "\n" + p.Timeout.String())
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
