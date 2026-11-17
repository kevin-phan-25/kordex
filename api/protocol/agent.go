// Package protocol defines the versioned outbound agent wire contract.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const Version = "1"
const MaxNodes = 5000
const MaxReportBytes = 4 << 20
const ClockSkew = 2 * time.Minute
const KeyLifetime = 24 * time.Hour
const KeyRotationInterval = 12 * time.Hour
const OperatorCapabilityLifetime = 45 * time.Second

// Enrollment binds an immutable kube-system namespace UID to a pre-registered cluster.
type Enrollment struct {
	ClusterID  string `json:"clusterId"`
	ClusterUID string `json:"clusterUid"`
	Token      string `json:"token"`
	PublicKey  string `json:"publicKey"`
	Proof      string `json:"proof"`
}
type Node struct {
	Labels           map[string]string `json:"labels"`
	UID              string            `json:"uid"`
	Name             string            `json:"name"`
	OSImage          string            `json:"osImage"`
	KernelVersion    string            `json:"kernelVersion"`
	KubeletVersion   string            `json:"kubeletVersion"`
	Architecture     string            `json:"architecture"`
	ContainerRuntime string            `json:"containerRuntime"`
	ProviderID       string            `json:"providerId,omitempty"`
	Ready            bool              `json:"ready"`
	Unschedulable    bool              `json:"unschedulable"`
	ControlPlane     bool              `json:"controlPlane"`
	Zone             string            `json:"zone"`
}
type Report struct {
	ClusterUID        string                    `json:"clusterUid"`
	Version           int64                     `json:"version"`
	ObservedAt        time.Time                 `json:"observedAt"`
	KubernetesVersion string                    `json:"kubernetesVersion"`
	Nodes             []Node                    `json:"nodes"`
	PolicyCatalog     *MaintenancePolicyCatalog `json:"policyCatalog,omitempty"`
}

type MaintenancePolicyCatalog struct {
	ObservedAt   time.Time                       `json:"observedAt"`
	Capabilities *OperatorCapabilities           `json:"operatorCapabilities,omitempty"`
	Items        []MaintenancePolicyCatalogEntry `json:"items"`
}

// OperatorCapabilities is an agent-relayed, short-lived report from the local
// operator. It is advisory for central campaign admission; local execution
// always checks its own configured executors again.
type OperatorCapabilities struct {
	ObservedAt         time.Time `json:"observedAt"`
	HostUpgrades       bool      `json:"hostUpgrades"`
	GKENodePoolUpgrade bool      `json:"gkeNodePoolUpgrade"`
}

func (c OperatorCapabilities) Fresh(now time.Time) bool {
	return !c.ObservedAt.IsZero() && !c.ObservedAt.Before(now.Add(-OperatorCapabilityLifetime)) && !c.ObservedAt.After(now.Add(ClockSkew))
}

type MaintenancePolicyCatalogEntry struct {
	Policy              PolicyReference          `json:"policy"`
	NodeSelector        metav1.LabelSelector     `json:"nodeSelector"`
	Suspended           bool                     `json:"suspended"`
	Upgrade             *UpgradePolicy           `json:"upgrade,omitempty"`
	UpgradePlanDigest   string                   `json:"upgradePlanDigest,omitempty"`
	UpgradePlanInvalid  bool                     `json:"upgradePlanInvalid,omitempty"`
	ProviderUpgrade     *ProviderNodeUpgradePlan `json:"providerUpgrade,omitempty"`
	ProviderPlanDigest  string                   `json:"providerPlanDigest,omitempty"`
	ProviderPlanInvalid bool                     `json:"providerPlanInvalid,omitempty"`
}

const MaxPolicyCatalogItems = 256

func (c MaintenancePolicyCatalog) Validate(now time.Time) error {
	if c.ObservedAt.IsZero() || c.ObservedAt.Before(now.Add(-ClockSkew)) || c.ObservedAt.After(now.Add(ClockSkew)) || c.Items == nil || len(c.Items) > MaxPolicyCatalogItems {
		return fmt.Errorf("invalid or stale maintenance policy catalog")
	}
	if c.Capabilities != nil && (c.Capabilities.ObservedAt.IsZero() || c.Capabilities.ObservedAt.After(now.Add(ClockSkew))) {
		return fmt.Errorf("invalid operator capability timestamp")
	}
	seen := make(map[string]struct{}, len(c.Items))
	for _, item := range c.Items {
		if !validName(item.Policy.Name, 253) || item.Policy.UID == "" || len(item.Policy.UID) > 128 || item.Policy.Generation < 1 {
			return fmt.Errorf("invalid maintenance policy identity")
		}
		if _, exists := seen[item.Policy.Name]; exists {
			return fmt.Errorf("duplicate maintenance policy name")
		}
		seen[item.Policy.Name] = struct{}{}
		if _, err := metav1.LabelSelectorAsSelector(&item.NodeSelector); err != nil {
			return fmt.Errorf("invalid maintenance policy node selector")
		}
		if item.Upgrade == nil {
			if item.UpgradePlanDigest != "" {
				return fmt.Errorf("upgrade digest without upgrade policy")
			}
		} else if item.UpgradePlanInvalid {
			return fmt.Errorf("upgrade plan cannot be both valid and invalid")
		} else {
			digest, err := item.Upgrade.Digest()
			if err != nil || digest != item.UpgradePlanDigest {
				return fmt.Errorf("invalid maintenance upgrade plan digest")
			}
		}
		if item.ProviderUpgrade == nil {
			if item.ProviderPlanDigest != "" {
				return fmt.Errorf("provider digest without provider upgrade plan")
			}
		} else if item.ProviderPlanInvalid {
			return fmt.Errorf("provider plan cannot be both valid and invalid")
		} else {
			digest, err := item.ProviderUpgrade.Digest()
			if err != nil || digest != item.ProviderPlanDigest {
				return fmt.Errorf("invalid maintenance provider plan digest")
			}
		}
	}
	return nil
}

type Identity struct {
	ClusterID string    `json:"clusterId"`
	KeyID     string    `json:"keyId"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type Rotation struct {
	PublicKey string `json:"publicKey"`
	Proof     string `json:"proof"`
}

func KeyID(public ed25519.PublicKey) string {
	h := sha256.Sum256(public)
	return hex.EncodeToString(h[:])
}
func EncodeKey(public ed25519.PublicKey) string { return base64.RawStdEncoding.EncodeToString(public) }
func DecodeKey(value string) (ed25519.PublicKey, error) {
	b, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
func TokenHash(token string) []byte { h := sha256.Sum256([]byte(token)); return h[:] }
func EnrollmentMessage(e Enrollment) []byte {
	return []byte("kordex.enroll.v1\n" + e.ClusterID + "\n" + e.ClusterUID + "\n" + hex.EncodeToString(TokenHash(e.Token)) + "\n" + e.PublicKey)
}
func RotationMessage(cluster, oldKey, newPublic string) []byte {
	return []byte("kordex.rotate.v1\n" + cluster + "\n" + oldKey + "\n" + newPublic)
}
func Proof(private ed25519.PrivateKey, message []byte) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, message))
}
func VerifyProof(public ed25519.PublicKey, message []byte, proof string) bool {
	b, err := base64.RawStdEncoding.DecodeString(proof)
	return err == nil && ed25519.Verify(public, message, b)
}
func canonical(method, path, cluster, key, timestamp, nonce string, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte(strings.Join([]string{"kordex.agent.v1", method, path, cluster, key, timestamp, nonce, hex.EncodeToString(h[:])}, "\n"))
}
func Sign(r *http.Request, cluster string, private ed25519.PrivateKey, body []byte, now time.Time) {
	public := private.Public().(ed25519.PublicKey)
	key := KeyID(public)
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	encodedNonce := hex.EncodeToString(nonce)
	r.Header.Set("X-Kordex-Version", Version)
	r.Header.Set("X-Kordex-Cluster", cluster)
	r.Header.Set("X-Kordex-Key", key)
	r.Header.Set("X-Kordex-Time", timestamp)
	r.Header.Set("X-Kordex-Nonce", encodedNonce)
	r.Header.Set("X-Kordex-Signature", Proof(private, canonical(r.Method, r.URL.EscapedPath(), cluster, key, timestamp, encodedNonce, body)))
}
func Verify(r *http.Request, public ed25519.PublicKey, body []byte, now time.Time) bool {
	if r.URL.RawQuery != "" || r.Header.Get("X-Kordex-Version") != Version || r.Header.Get("X-Kordex-Key") != KeyID(public) {
		return false
	}
	n, err := strconv.ParseInt(r.Header.Get("X-Kordex-Time"), 10, 64)
	if err != nil {
		return false
	}
	when := time.Unix(n, 0)
	if when.Before(now.Add(-ClockSkew)) || when.After(now.Add(ClockSkew)) {
		return false
	}
	nonce, err := hex.DecodeString(r.Header.Get("X-Kordex-Nonce"))
	if err != nil || len(nonce) != 24 {
		return false
	}
	return VerifyProof(public, canonical(r.Method, r.URL.EscapedPath(), r.Header.Get("X-Kordex-Cluster"), r.Header.Get("X-Kordex-Key"), r.Header.Get("X-Kordex-Time"), r.Header.Get("X-Kordex-Nonce"), body), r.Header.Get("X-Kordex-Signature"))
}
func ValidUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(decoded) == 16
}

// ValidNodeLabels validates a complete set; collectors must never truncate selector evidence.
func ValidNodeLabels(values map[string]string) bool {
	if len(values) > 64 {
		return false
	}
	size := 0
	for key, value := range values {
		size += len(key) + len(value)
		if len(validation.IsQualifiedName(key)) > 0 || len(validation.IsValidLabelValue(value)) > 0 {
			return false
		}
	}
	return size <= 4096
}
