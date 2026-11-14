// Package protocol defines the versioned outbound agent wire contract.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

// Enrollment binds an immutable kube-system namespace UID to a pre-registered cluster.
type Enrollment struct {
	ClusterID  string `json:"clusterId"`
	ClusterUID string `json:"clusterUid"`
	Token      string `json:"token"`
	PublicKey  string `json:"publicKey"`
	Proof      string `json:"proof"`
}
type Node struct {
	UID              string `json:"uid"`
	Name             string `json:"name"`
	OSImage          string `json:"osImage"`
	KernelVersion    string `json:"kernelVersion"`
	KubeletVersion   string `json:"kubeletVersion"`
	Architecture     string `json:"architecture"`
	ContainerRuntime string `json:"containerRuntime"`
	Ready            bool   `json:"ready"`
	Unschedulable    bool   `json:"unschedulable"`
	ControlPlane     bool   `json:"controlPlane"`
	Zone             string `json:"zone"`
}
type Report struct {
	ClusterUID        string    `json:"clusterUid"`
	Version           int64     `json:"version"`
	ObservedAt        time.Time `json:"observedAt"`
	KubernetesVersion string    `json:"kubernetesVersion"`
	Nodes             []Node    `json:"nodes"`
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
