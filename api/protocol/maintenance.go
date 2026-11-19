package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"strings"
	"time"
)

const ValidateOnly = "ValidateOnly"
const DrainAndVerify = "DrainAndVerify"
const UpgradePackages = "UpgradePackages"
const UpgradeNodePool = "UpgradeNodePool"
const ConnectionLease = "kordex-hub-connection"
const ConnectionTTL = 45 * time.Second
const SlotNamespace = "kordex-operations-ledger"
const SlotLease = "kordex-maintenance-cluster-slot"
const OperationGroup = "operations.kordex.local"
const OperationVersion = "v1alpha1"
const OperationResource = "nodemaintenances"
const OperationFinalizer = OperationGroup + "/safe-recovery"
const AckAnnotation = OperationGroup + "/ack-sequence"

type PolicyReference struct {
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}
type MaintenanceRequest struct {
	OperationID string          `json:"operationId"`
	NodeName    string          `json:"nodeName"`
	NodeUID     string          `json:"nodeUid"`
	Policy      PolicyReference `json:"policy"`
	Action      string          `json:"action"`
	PlanDigest  string          `json:"planDigest,omitempty"`
}

func (r MaintenanceRequest) Validate() error {
	if !ValidUUID(r.OperationID) || r.OperationID != strings.ToLower(r.OperationID) || !validName(r.NodeName, 253) || !validName(r.Policy.Name, 253) || r.NodeUID == "" || len(r.NodeUID) > 128 || r.Policy.UID == "" || len(r.Policy.UID) > 128 || r.Policy.Generation < 1 {
		return fmt.Errorf("invalid maintenance request")
	}
	switch r.Action {
	case ValidateOnly, DrainAndVerify:
		if r.PlanDigest != "" {
			return fmt.Errorf("plan digest is not valid for this action")
		}
	case UpgradePackages, UpgradeNodePool:
		if !ValidSHA256Digest(r.PlanDigest) {
			return fmt.Errorf("upgrade action requires a SHA-256 plan digest")
		}
	default:
		return fmt.Errorf("invalid maintenance action")
	}
	return nil
}

func ValidSHA256Digest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validName(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && len(validation.IsDNS1123Subdomain(s)) == 0
}

// ValidDNS1123Subdomain validates a Kubernetes DNS subdomain identifier.
// It is used when a name is passed into a host-facing configuration field.
func ValidDNS1123Subdomain(s string) bool { return validName(s, 253) }

type MaintenancePermit struct {
	Version        string `json:"version"`
	OrganizationID string `json:"organizationId"`
	ClusterID      string `json:"clusterId"`
	ClusterUID     string `json:"clusterUid"`
	MaintenanceRequest
	CampaignID             string    `json:"campaignId,omitempty"`
	CampaignStage          int       `json:"campaignStage,omitempty"`
	CampaignPlanGeneration int64     `json:"campaignPlanGeneration,omitempty"`
	SnapshotDigest         string    `json:"snapshotDigest,omitempty"`
	Attempt                int       `json:"attempt,omitempty"`
	IssuedAt               time.Time `json:"issuedAt"`
	NotBefore              time.Time `json:"notBefore"`
	ExpiresAt              time.Time `json:"expiresAt"`
	KeyID                  string    `json:"keyId"`
}
type MaintenanceCommand struct {
	Authorization string `json:"authorization"`
	Signature     string `json:"signature"`
}

func SignMaintenance(p MaintenancePermit, key ed25519.PrivateKey) (MaintenanceCommand, error) {
	p.Version = Version
	p.KeyID = KeyID(key.Public().(ed25519.PublicKey))
	data, err := json.Marshal(p)
	if err != nil {
		return MaintenanceCommand{}, err
	}
	return MaintenanceCommand{Authorization: string(data), Signature: Proof(key, append([]byte("kordex.maintenance.v1\n"), data...))}, nil
}
func DecodeMaintenance(c MaintenanceCommand, keys map[string]ed25519.PublicKey) (MaintenancePermit, error) {
	var p MaintenancePermit
	if len(c.Authorization) > 8192 {
		return p, fmt.Errorf("authorization too large")
	}
	d := json.NewDecoder(bytes.NewBufferString(c.Authorization))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid authorization")
	}
	if d.Decode(new(any)) != io.EOF {
		return p, fmt.Errorf("trailing authorization data")
	}
	key := keys[p.KeyID]
	if len(key) != ed25519.PublicKeySize || !VerifyProof(key, append([]byte("kordex.maintenance.v1\n"), []byte(c.Authorization)...), c.Signature) {
		return p, fmt.Errorf("invalid hub signature")
	}
	if p.Version != Version || !ValidUUID(p.OrganizationID) || !ValidUUID(p.ClusterID) || p.ClusterUID == "" || len(p.ClusterUID) > 128 || p.MaintenanceRequest.Validate() != nil || p.NotBefore.Before(p.IssuedAt) || !p.ExpiresAt.After(p.NotBefore) || p.ExpiresAt.Sub(p.IssuedAt) > 15*time.Minute {
		return p, fmt.Errorf("invalid permit constraints")
	}
	if p.CampaignID != "" {
		decoded, err := hex.DecodeString(p.SnapshotDigest)
		if !ValidUUID(p.CampaignID) || p.CampaignStage < 0 || p.CampaignStage > 3 || p.CampaignPlanGeneration < 1 || p.Attempt < 1 || err != nil || len(decoded) != 32 {
			return p, fmt.Errorf("invalid campaign provenance")
		}
	}
	return p, nil
}
func (p MaintenancePermit) Fresh(now time.Time) bool {
	return !now.Before(p.NotBefore) && now.Before(p.ExpiresAt) && !p.IssuedAt.After(now.Add(5*time.Second))
}
func (c MaintenanceCommand) Digest() string {
	h := sha256.Sum256([]byte(c.Authorization + "\n" + c.Signature))
	return hex.EncodeToString(h[:])
}

type PhaseEvent struct {
	Sequence    int64       `json:"sequence"`
	Phase       string      `json:"phase"`
	Reason      string      `json:"reason"`
	ResourceUID string      `json:"resourceUid,omitempty"`
	Time        metav1.Time `json:"time"`
}
type OperationReport struct {
	OperationID               string                     `json:"operationId"`
	Sequence                  int64                      `json:"sequence"`
	Phase                     string                     `json:"phase"`
	Reason                    string                     `json:"reason"`
	Events                    []PhaseEvent               `json:"events"`
	UpgradeCheckpoint         *UpgradeCheckpoint         `json:"upgradeCheckpoint,omitempty"`
	ProviderUpgradeCheckpoint *ProviderUpgradeCheckpoint `json:"providerUpgradeCheckpoint,omitempty"`
}
type OperationSync struct {
	Reports []OperationReport `json:"reports"`
}
type OperationSyncResult struct {
	Controls     []OperationControl   `json:"controls"`
	Commands     []MaintenanceCommand `json:"commands"`
	Acknowledged map[string]int64     `json:"acknowledged"`
	ServerTime   time.Time            `json:"serverTime"`
}

func TerminalPhase(phase string) bool {
	return phase == "Succeeded" || phase == "Failed" || phase == "Cancelled"
}
func ValidPhase(phase string) bool {
	switch phase {
	case "Pending", "Validating", "SafetyChecking", "Blocked", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled":
		return true
	}
	return false
}

// CanAdvanceMaintenancePhase checks the durable operation state machine. The
// resume phase is required only when leaving Blocked; callers that validate a
// signed report infer it from the most recent non-Blocked event.
func CanAdvanceMaintenancePhase(from, to, resume string) bool {
	if !ValidPhase(to) {
		return false
	}
	if from == "" {
		return to == "Pending" || to == "Failed" || to == "Cancelled" || to == "RecoveryRequired"
	}
	if !ValidPhase(from) {
		return false
	}
	if from == to {
		return true
	}
	if TerminalPhase(from) {
		// A terminal record that still owns a cordon must re-enter recovery.
		return to == "RecoveryRequired"
	}
	if from == "Blocked" {
		if !ValidPhase(resume) || resume == "Blocked" || TerminalPhase(resume) {
			return false
		}
		from = resume
	}
	if to == "Blocked" || to == "RecoveryRequired" {
		return true
	}
	edges := map[string]map[string]struct{}{
		"Pending":            {"Validating": {}, "Failed": {}, "Cancelled": {}},
		"Validating":         {"SafetyChecking": {}, "Failed": {}, "Cancelled": {}},
		"SafetyChecking":     {"Preflighting": {}, "Cordoning": {}, "Executing": {}, "VerifyingNode": {}, "Succeeded": {}, "Failed": {}, "Cancelled": {}},
		"Preflighting":       {"Cordoning": {}},
		"Cordoning":          {"Draining": {}},
		"Draining":           {"Executing": {}, "VerifyingNode": {}},
		"Executing":          {"Rebooting": {}, "VerifyingNode": {}},
		"Rebooting":          {"VerifyingNode": {}},
		"VerifyingNode":      {"VerifyingWorkloads": {}},
		"VerifyingWorkloads": {"Uncordoning": {}, "Succeeded": {}, "Cancelled": {}},
		"Uncordoning":        {"Succeeded": {}, "Failed": {}, "Cancelled": {}},
		"RecoveryRequired":   {"VerifyingNode": {}, "VerifyingWorkloads": {}, "Uncordoning": {}},
	}
	_, ok := edges[from][to]
	return ok
}

func (r OperationReport) Validate() bool {
	if !ValidUUID(r.OperationID) || r.OperationID != strings.ToLower(r.OperationID) || r.Sequence < 1 || !ValidPhase(r.Phase) || len(r.Reason) > 128 || len(r.Events) > 256 {
		return false
	}
	last := int64(0)
	for i, e := range r.Events {
		if e.Sequence != last+1 || e.Sequence > r.Sequence || !ValidPhase(e.Phase) || len(e.Reason) > 128 || len(e.ResourceUID) > 128 || e.Time.IsZero() {
			return false
		}
		if i == 0 {
			if !CanAdvanceMaintenancePhase("", e.Phase, "") {
				return false
			}
		} else {
			// Event sequence is the durable ordering source, but timestamps must
			// not contradict that order. Equal timestamps are valid for clocks
			// with coarse resolution; backwards timestamps are not.
			if e.Time.Before(&r.Events[i-1].Time) {
				return false
			}
			previous := r.Events[i-1].Phase
			resume := ""
			if TerminalPhase(previous) && e.Phase == "RecoveryRequired" && e.Reason != "TerminalRecoveryIncomplete" {
				return false
			}
			if previous == "Blocked" {
				for j := i - 2; j >= 0; j-- {
					if r.Events[j].Phase != "Blocked" {
						resume = r.Events[j].Phase
						break
					}
				}
			}
			if !CanAdvanceMaintenancePhase(previous, e.Phase, resume) {
				return false
			}
		}
		last = e.Sequence
	}
	if r.UpgradeCheckpoint != nil && ValidateUpgradeCheckpoint(*r.UpgradeCheckpoint) != nil {
		return false
	}
	if r.ProviderUpgradeCheckpoint != nil && r.ProviderUpgradeCheckpoint.Validate() != nil {
		return false
	}
	if r.UpgradeCheckpoint != nil && r.ProviderUpgradeCheckpoint != nil {
		return false
	}
	return len(r.Events) > 0 && last == r.Sequence && r.Events[len(r.Events)-1].Phase == r.Phase && r.Events[len(r.Events)-1].Reason == r.Reason
}

// ValidateAt applies a receiver-clock bound to timestamps that are otherwise
// structurally valid. Operation reports are signed by cluster agents, so a
// signature alone does not make their wall-clock timestamps trustworthy.
func (r OperationReport) ValidateAt(now time.Time, allowedFutureSkew time.Duration) bool {
	if now.IsZero() || allowedFutureSkew < 0 || !r.Validate() {
		return false
	}
	latest := now.Add(allowedFutureSkew)
	for _, event := range r.Events {
		if event.Time.Time.After(latest) {
			return false
		}
	}
	if checkpoint := r.UpgradeCheckpoint; checkpoint != nil {
		if checkpoint.UpdatedAt.Time.After(latest) {
			return false
		}
		for _, receipt := range checkpoint.Receipts {
			if receipt.CompletedAt.Time.After(latest) {
				return false
			}
		}
	}
	if checkpoint := r.ProviderUpgradeCheckpoint; checkpoint != nil {
		if checkpoint.UpdatedAt.Time.After(latest) || !checkpoint.IntentAt.IsZero() && checkpoint.IntentAt.Time.After(latest) {
			return false
		}
	}
	return true
}

// ValidateForAction prevents a signed agent report from attributing lifecycle
// phases to an operation that cannot perform them. Local operator checks stay
// authoritative; this is a second audit-ingestion consistency boundary.
func (r OperationReport) ValidateForAction(action string) bool {
	if !r.Validate() {
		return false
	}
	allowed := map[string]map[string]struct{}{
		ValidateOnly:    phaseSet("Pending", "Validating", "SafetyChecking", "Blocked", "Succeeded", "Failed", "Cancelled"),
		DrainAndVerify:  phaseSet("Pending", "Validating", "SafetyChecking", "Blocked", "Cordoning", "Draining", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled"),
		UpgradePackages: phaseSet("Pending", "Validating", "SafetyChecking", "Blocked", "Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled"),
		UpgradeNodePool: phaseSet("Pending", "Validating", "SafetyChecking", "Blocked", "Executing", "VerifyingNode", "VerifyingWorkloads", "RecoveryRequired", "Succeeded", "Failed", "Cancelled"),
	}
	phases, ok := allowed[action]
	if !ok {
		return false
	}
	for _, event := range r.Events {
		if _, ok := phases[event.Phase]; !ok {
			return false
		}
	}
	for i := 1; i < len(r.Events); i++ {
		from := r.Events[i-1].Phase
		if from == "Blocked" {
			from = ""
			for j := i - 2; j >= 0; j-- {
				if r.Events[j].Phase != "Blocked" {
					from = r.Events[j].Phase
					break
				}
			}
		}
		if !maintenanceActionEdge(action, from, r.Events[i].Phase) {
			return false
		}
	}
	if r.UpgradeCheckpoint != nil && action != UpgradePackages || r.ProviderUpgradeCheckpoint != nil && action != UpgradeNodePool {
		return false
	}
	seen := make(map[string]struct{}, len(r.Events))
	for _, event := range r.Events {
		seen[event.Phase] = struct{}{}
	}
	if action == UpgradePackages {
		for _, phase := range []string{"Preflighting", "Cordoning", "Draining", "Executing", "Rebooting", "VerifyingNode", "VerifyingWorkloads", "Uncordoning"} {
			if _, exists := seen[phase]; exists && r.UpgradeCheckpoint == nil {
				return false
			}
		}
	}
	if action == UpgradeNodePool {
		for _, phase := range []string{"Executing", "VerifyingNode", "VerifyingWorkloads"} {
			if _, exists := seen[phase]; exists && r.ProviderUpgradeCheckpoint == nil {
				return false
			}
		}
	}
	if r.Phase == "Succeeded" {
		switch action {
		case ValidateOnly:
			if _, ok := seen["SafetyChecking"]; !ok {
				return false
			}
		case DrainAndVerify:
			for _, phase := range []string{"Cordoning", "Draining", "VerifyingNode", "VerifyingWorkloads", "Uncordoning"} {
				if _, ok := seen[phase]; !ok {
					return false
				}
			}
		case UpgradePackages:
			for _, phase := range []string{"Preflighting", "Cordoning", "Draining", "Executing", "VerifyingNode", "VerifyingWorkloads", "Uncordoning"} {
				if _, ok := seen[phase]; !ok {
					return false
				}
			}
			if r.UpgradeCheckpoint == nil || !successfulUpgradeCheckpointValid(*r.UpgradeCheckpoint, r.OperationID) {
				return false
			}
			if r.UpgradeCheckpoint.RebootRequested {
				if _, ok := seen["Rebooting"]; !ok {
					return false
				}
			} else if _, ok := seen["Rebooting"]; ok {
				return false
			}
		case UpgradeNodePool:
			if _, ok := seen["VerifyingWorkloads"]; !ok || r.ProviderUpgradeCheckpoint == nil || r.ProviderUpgradeCheckpoint.Phase != "Succeeded" {
				return false
			}
			if r.ProviderUpgradeCheckpoint.InitialVersion == "" || len(r.ProviderUpgradeCheckpoint.InitialNodeIdentityDigests) == 0 {
				return false
			}
			_, executed := seen["Executing"]
			if !executed && r.ProviderUpgradeCheckpoint.InitialVersion != r.ProviderUpgradeCheckpoint.TargetVersion {
				return false
			}
		}
	}
	return true
}

func maintenanceActionEdge(action, from, to string) bool {
	if from == to {
		return true
	}
	if to == "Blocked" {
		return !TerminalPhase(from)
	}
	if to == "RecoveryRequired" {
		return action != ValidateOnly
	}
	if TerminalPhase(from) {
		return to == "RecoveryRequired" && action != ValidateOnly
	}
	common := map[string]map[string]struct{}{
		"Pending":    {"Validating": {}, "Failed": {}, "Cancelled": {}},
		"Validating": {"SafetyChecking": {}, "Failed": {}, "Cancelled": {}},
	}
	if edges, ok := common[from]; ok {
		_, ok = edges[to]
		return ok
	}
	edges := map[string]map[string]map[string]struct{}{
		ValidateOnly: {
			"SafetyChecking": {"Succeeded": {}, "Failed": {}, "Cancelled": {}},
		},
		DrainAndVerify: {
			"SafetyChecking":     {"Cordoning": {}, "Failed": {}, "Cancelled": {}},
			"Cordoning":          {"Draining": {}},
			"Draining":           {"VerifyingNode": {}},
			"VerifyingNode":      {"VerifyingWorkloads": {}},
			"VerifyingWorkloads": {"Uncordoning": {}, "Cancelled": {}},
			"Uncordoning":        {"Succeeded": {}, "Failed": {}, "Cancelled": {}},
			"RecoveryRequired":   {"VerifyingNode": {}, "VerifyingWorkloads": {}, "Uncordoning": {}},
		},
		UpgradePackages: {
			"SafetyChecking":     {"Preflighting": {}, "Failed": {}, "Cancelled": {}},
			"Preflighting":       {"Cordoning": {}},
			"Cordoning":          {"Draining": {}},
			"Draining":           {"Executing": {}},
			"Executing":          {"Rebooting": {}, "VerifyingNode": {}},
			"Rebooting":          {"VerifyingNode": {}},
			"VerifyingNode":      {"VerifyingWorkloads": {}},
			"VerifyingWorkloads": {"Uncordoning": {}, "Cancelled": {}},
			"Uncordoning":        {"Succeeded": {}, "Failed": {}, "Cancelled": {}},
			"RecoveryRequired":   {"VerifyingNode": {}, "VerifyingWorkloads": {}, "Uncordoning": {}},
		},
		UpgradeNodePool: {
			"SafetyChecking":     {"Executing": {}, "VerifyingNode": {}, "Failed": {}, "Cancelled": {}},
			"Executing":          {"VerifyingNode": {}},
			"VerifyingNode":      {"VerifyingWorkloads": {}},
			"VerifyingWorkloads": {"Succeeded": {}, "Cancelled": {}},
			"RecoveryRequired":   {"VerifyingNode": {}, "VerifyingWorkloads": {}},
		},
	}
	byPhase, ok := edges[action]
	if !ok {
		return false
	}
	allowed, ok := byPhase[from]
	if !ok {
		return false
	}
	_, ok = allowed[to]
	return ok
}

func phaseSet(phases ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(phases))
	for _, phase := range phases {
		set[phase] = struct{}{}
	}
	return set
}

func successfulUpgradeCheckpointValid(checkpoint UpgradeCheckpoint, operationID string) bool {
	if checkpoint.Phase != UpgradeSucceeded || !machineIDToken.MatchString(checkpoint.MachineID) || !ValidUUID(checkpoint.BootID) {
		return false
	}
	var preflight, apply, reboot *UpgradeReceiptEvidence
	preflightIndex, applyIndex, rebootIndex := -1, -1, -1
	for i := range checkpoint.Receipts {
		receipt := &checkpoint.Receipts[i]
		switch receipt.Phase {
		case "preflight":
			preflight = receipt
			preflightIndex = i
		case "apply":
			apply = receipt
			applyIndex = i
		case "reboot":
			reboot = receipt
			rebootIndex = i
		}
	}
	if preflight == nil || apply == nil || preflightIndex >= applyIndex || reboot != nil && rebootIndex <= applyIndex || preflight.MachineID != checkpoint.MachineID || preflight.BootIDBefore != apply.BootIDBefore || preflight.BootIDAfter != apply.BootIDAfter {
		return false
	}
	applyMarker := apply.ActionMarker
	if apply.MachineID != checkpoint.MachineID || apply.BootIDBefore != apply.BootIDAfter || len(apply.Packages) == 0 || applyMarker == nil || applyMarker.Validate() != nil || applyMarker.OperationID != operationID || applyMarker.ActionDigest != checkpoint.PlanDigest || applyMarker.NodeUID != checkpoint.NodeUID || applyMarker.MachineID != checkpoint.MachineID || applyMarker.BootID != apply.BootIDBefore || applyMarker.Phase != "packages-verified" || applyMarker.Sequence != 2 {
		return false
	}
	if checkpoint.RebootRequested {
		if checkpoint.Outcome != "PackagesAndRebootVerified" || !apply.RebootRequired || reboot == nil || !reboot.RebootRequired || !reboot.Rebooted || reboot.MachineID != checkpoint.MachineID || reboot.BootIDBefore != apply.BootIDAfter || reboot.BootIDAfter != checkpoint.BootID || reboot.ExpectedKernelVersion != apply.ExpectedKernelVersion {
			return false
		}
		if len(reboot.Packages) != len(apply.Packages) {
			return false
		}
		for name, version := range apply.Packages {
			if reboot.Packages[name] != version {
				return false
			}
		}
		rebootMarker := reboot.ActionMarker
		if rebootMarker == nil || rebootMarker.Validate() != nil || rebootMarker.OperationID != operationID || rebootMarker.ActionDigest != checkpoint.PlanDigest || rebootMarker.NodeUID != checkpoint.NodeUID || rebootMarker.MachineID != checkpoint.MachineID || rebootMarker.BootID != reboot.BootIDAfter || rebootMarker.Phase != "reboot-verified" || rebootMarker.Sequence != 4 {
			return false
		}
		return checkpoint.BootID != apply.BootIDAfter
	}
	return checkpoint.Outcome == "PackagesVerified" && !apply.RebootRequired && reboot == nil && checkpoint.BootID == apply.BootIDAfter && (apply.ExpectedKernelVersion == "" || apply.KernelVersion == apply.ExpectedKernelVersion)
}

// DeepCopyInto allows CRD status snapshots to copy the shared event value safely.
func (in *PhaseEvent) DeepCopyInto(out *PhaseEvent) { *out = *in; in.Time.DeepCopyInto(&out.Time) }
