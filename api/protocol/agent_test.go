package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
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
