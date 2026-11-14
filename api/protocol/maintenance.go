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
	"time"
)

const ValidateOnly = "ValidateOnly"
const DrainAndVerify = "DrainAndVerify"
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
}

func (r MaintenanceRequest) Validate() error {
	if !ValidUUID(r.OperationID) || !validName(r.NodeName, 253) || !validName(r.Policy.Name, 253) || r.NodeUID == "" || len(r.NodeUID) > 128 || r.Policy.UID == "" || len(r.Policy.UID) > 128 || r.Policy.Generation < 1 || (r.Action != ValidateOnly && r.Action != DrainAndVerify) {
		return fmt.Errorf("invalid maintenance request")
	}
	return nil
}
func validName(s string, max int) bool {
	return len(s) > 0 && len(s) <= max && len(validation.IsDNS1123Subdomain(s)) == 0
}

type MaintenancePermit struct {
	Version        string `json:"version"`
	OrganizationID string `json:"organizationId"`
	ClusterID      string `json:"clusterId"`
	ClusterUID     string `json:"clusterUid"`
	MaintenanceRequest
	IssuedAt  time.Time `json:"issuedAt"`
	NotBefore time.Time `json:"notBefore"`
	ExpiresAt time.Time `json:"expiresAt"`
	KeyID     string    `json:"keyId"`
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
	OperationID string       `json:"operationId"`
	Sequence    int64        `json:"sequence"`
	Phase       string       `json:"phase"`
	Reason      string       `json:"reason"`
	Events      []PhaseEvent `json:"events"`
}
type OperationSync struct {
	Reports []OperationReport `json:"reports"`
}
type OperationSyncResult struct {
	Commands     []MaintenanceCommand `json:"commands"`
	Acknowledged map[string]int64     `json:"acknowledged"`
	ServerTime   time.Time            `json:"serverTime"`
}

func TerminalPhase(phase string) bool {
	return phase == "Succeeded" || phase == "Failed" || phase == "Cancelled"
}
func ValidPhase(phase string) bool {
	switch phase {
	case "Pending", "Validating", "SafetyChecking", "Blocked", "Cordoning", "Draining", "VerifyingNode", "VerifyingWorkloads", "Uncordoning", "RecoveryRequired", "Succeeded", "Failed", "Cancelled":
		return true
	}
	return false
}
func (r OperationReport) Validate() bool {
	if !ValidUUID(r.OperationID) || r.Sequence < 1 || !ValidPhase(r.Phase) || len(r.Reason) > 128 || len(r.Events) > 256 {
		return false
	}
	last := int64(0)
	for _, e := range r.Events {
		if e.Sequence <= last || e.Sequence > r.Sequence || !ValidPhase(e.Phase) || len(e.Reason) > 128 || len(e.ResourceUID) > 128 || e.Time.IsZero() {
			return false
		}
		last = e.Sequence
	}
	return len(r.Events) > 0 && last == r.Sequence && r.Events[len(r.Events)-1].Phase == r.Phase && r.Events[len(r.Events)-1].Reason == r.Reason
}

// DeepCopyInto allows CRD status snapshots to copy the shared event value safely.
func (in *PhaseEvent) DeepCopyInto(out *PhaseEvent) { *out = *in; in.Time.DeepCopyInto(&out.Time) }
