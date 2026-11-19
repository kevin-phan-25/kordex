package store

import "testing"

func TestGKEProviderMetadataValidation(t *testing.T) {
	for _, metadata := range []*ProviderMetadata{
		{GCPProjectID: "kordex-fleet-platform", Location: "us-east1-b"},
		{GCPProjectID: "project-123456", Location: "us-east1"},
	} {
		if !ValidGKEProviderMetadata(metadata) {
			t.Errorf("valid GKE metadata rejected: %+v", metadata)
		}
	}
	for _, metadata := range []*ProviderMetadata{
		nil,
		{GCPProjectID: "INVALID PROJECT", Location: "us-east1-b"},
		{GCPProjectID: "kordex-fleet-platform", Location: "localhost"},
	} {
		if ValidGKEProviderMetadata(metadata) {
			t.Errorf("invalid GKE metadata accepted: %+v", metadata)
		}
	}
}
