package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSignedRequestBinding(t *testing.T) {
	public, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	body := []byte(`{"version":1}`)
	request := httptest.NewRequest("POST", "https://hub.example/v1/agent/report", nil)
	Sign(request, "cluster-a", key, body, now)
	if !Verify(request, public, body, now) {
		t.Fatal("valid signature rejected")
	}
	if Verify(request, public, []byte("tampered"), now) {
		t.Fatal("accepted tampered body")
	}
	if Verify(request, public, body, now.Add(3*time.Minute)) {
		t.Fatal("accepted expired request")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if Verify(request, other, body, now) {
		t.Fatal("accepted wrong key")
	}
	changed := request.Clone(request.Context())
	changed.Header = request.Header.Clone()
	changed.Header.Set("X-Kordex-Cluster", "cluster-b")
	if Verify(changed, public, body, now) {
		t.Fatal("accepted wrong cluster")
	}
	changed = request.Clone(request.Context())
	changed.Method = "GET"
	if Verify(changed, public, body, now) {
		t.Fatal("accepted wrong method")
	}
	changed = request.Clone(request.Context())
	changed.URL.Path = "/v1/agent/rotate"
	if Verify(changed, public, body, now) {
		t.Fatal("accepted wrong path")
	}
}

func TestValidNodeDetailsBoundsKubernetesInventory(t *testing.T) {
	now := time.Now().UTC()
	node := Node{OSID: "ubuntu", OSVersion: "24.04.5", OperatingSystem: "linux", ProviderID: "gce://project/zone/node", InternalIP: "10.0.0.2", Capacity: map[string]string{"cpu": "4", "pods": "110"}, Allocatable: map[string]string{"cpu": "3900m", "pods": "110"}, Taints: []NodeTaint{{Key: "node-role.kubernetes.io/control-plane", Effect: "NoSchedule"}}, Conditions: []NodeCondition{{Type: "Ready", Status: "True", Reason: "KubeletReady", LastTransitionTime: now}}}
	if !ValidNodeDetails(node, now) {
		t.Fatal("valid node metadata rejected")
	}
	node.ProviderID = strings.Repeat("x", 257)
	if ValidNodeDetails(node, now) {
		t.Fatal("oversized provider ID accepted")
	}
	node.ProviderID = "gce://project/zone/node"
	node.InternalIP = "not-an-ip"
	if ValidNodeDetails(node, now) {
		t.Fatal("invalid node IP accepted")
	}
	node.InternalIP = "10.0.0.2"
	node.Taints = []NodeTaint{{Key: "x", Effect: "Unknown"}}
	if ValidNodeDetails(node, now) {
		t.Fatal("unknown taint effect accepted")
	}
}
func TestUUIDValidation(t *testing.T) {
	for _, s := range []string{"00000000-0000-0000-0000-00000000--00", "00000000000000000000000000000000", "gggggggg-0000-0000-0000-000000000000", ""} {
		if ValidUUID(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	if !ValidUUID("80bd80f9-f097-4474-86f4-b80986fd5423") {
		t.Fatal("valid UUID rejected")
	}
}

func TestMaintenancePolicyCatalogValidation(t *testing.T) {
	now := time.Now().UTC()
	catalog := MaintenancePolicyCatalog{ObservedAt: now, Items: []MaintenancePolicyCatalogEntry{{Policy: PolicyReference{Name: "worker-maintenance", UID: "policy-uid", Generation: 2}, NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"pool": "worker"}}}}}
	if err := catalog.Validate(now); err != nil {
		t.Fatalf("valid catalog rejected: %v", err)
	}
	if MaintenancePolicyAllows(catalog.Items[0].AllowedActions, ValidateOnly) {
		t.Fatal("catalog without an explicit action list authorized a legacy policy")
	}
	catalog.Items[0].AllowedActions = []string{ValidateOnly, "ArbitraryCommand"}
	if err := catalog.Validate(now); err == nil {
		t.Fatal("catalog with an unknown action was accepted")
	}
	catalog.Items[0].AllowedActions = nil
	catalog.Items[0].ProtectedNodeSelector = &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "maintenance", Operator: "Unknown"}}}
	catalog.ObservedAt = now
	if err := catalog.Validate(now); err == nil {
		t.Fatal("catalog with invalid protected-node selector was accepted")
	}
	catalog.Items[0].ProtectedNodeSelector = nil
	catalog.ObservedAt = now.Add(-ClockSkew - time.Second)
	if err := catalog.Validate(now); err == nil {
		t.Fatal("stale catalog accepted")
	}
	catalog.ObservedAt = now
	catalog.Items = append(catalog.Items, catalog.Items[0])
	if err := catalog.Validate(now); err == nil {
		t.Fatal("duplicate policy identity accepted")
	}
}

func TestOperatorCapabilityFreshnessIsBounded(t *testing.T) {
	now := time.Now().UTC()
	capability := OperatorCapabilities{ObservedAt: now}
	if !capability.Fresh(now.Add(30 * time.Second)) {
		t.Fatal("fresh short-lived capability rejected")
	}
	if capability.Fresh(now.Add(46 * time.Second)) {
		t.Fatal("stale capability accepted")
	}
	if capability.Fresh(now.Add(-ClockSkew - time.Second)) {
		t.Fatal("future capability accepted")
	}
}

func TestNodeMaintenanceCapabilityIsExplicitInAgentCatalog(t *testing.T) {
	encoded, err := json.Marshal(OperatorCapabilities{ObservedAt: time.Now().UTC(), NodeMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	if value["nodeMaintenance"] != true {
		t.Fatalf("node-maintenance readiness was not serialized: %s", encoded)
	}
	var legacy OperatorCapabilities
	if err = json.Unmarshal([]byte(`{"observedAt":"2026-11-19T00:00:00Z","hostUpgrades":true,"gkeNodePoolUpgrade":false}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.NodeMaintenance {
		t.Fatal("legacy capability report without the RBAC probe was trusted")
	}
}
