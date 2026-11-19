package protocol

import (
	"testing"
	"time"
)

func validClusterCapabilities(now time.Time) ClusterCapabilities {
	observed := CapabilityObservation{State: "Observed", Source: "api-discovery", Values: []string{"first", "second"}}
	unknown := CapabilityObservation{State: "Unknown", Source: "read-only-inventory", Values: []string{}, ReasonCode: "PermissionDenied"}
	return ClusterCapabilities{
		ObservedAt:                 now,
		CNIHints:                   observed,
		CSIDrivers:                 observed,
		StorageProvisioners:        observed,
		AdmissionAPIs:              unknown,
		PodSecurityNamespaceLabels: unknown,
	}
}

func TestClusterCapabilitiesValidationPreservesUnknownEvidence(t *testing.T) {
	now := time.Now().UTC()
	if err := validClusterCapabilities(now).Validate(now); err != nil {
		t.Fatalf("valid observed and unknown evidence rejected: %v", err)
	}
}

func TestClusterCapabilitiesValidationRejectsInvalidEvidence(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name   string
		mutate func(*ClusterCapabilities)
	}{
		{name: "stale observation", mutate: func(value *ClusterCapabilities) { value.ObservedAt = now.Add(-ClockSkew - time.Second) }},
		{name: "unknown reason", mutate: func(value *ClusterCapabilities) { value.CNIHints.ReasonCode = "assumed-supported" }},
		{name: "unknown with values", mutate: func(value *ClusterCapabilities) {
			value.AdmissionAPIs.Values = []string{"admissionregistration.k8s.io/v1"}
		}},
		{name: "observed with reason", mutate: func(value *ClusterCapabilities) { value.CSIDrivers.ReasonCode = "PermissionDenied" }},
		{name: "unsorted values", mutate: func(value *ClusterCapabilities) { value.CNIHints.Values = []string{"z", "a"} }},
		{name: "duplicate values", mutate: func(value *ClusterCapabilities) { value.CNIHints.Values = []string{"same", "same"} }},
		{name: "missing values", mutate: func(value *ClusterCapabilities) { value.StorageProvisioners.Values = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validClusterCapabilities(now)
			test.mutate(&value)
			if err := value.Validate(now); err == nil {
				t.Fatal("invalid capability evidence accepted")
			}
		})
	}
}
