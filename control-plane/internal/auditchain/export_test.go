package auditchain

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestExportBundleSignatureBindsCheckpointAndDigest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := ExportBundle{
		Format: "kordex-audit-export-v1", RecordsFormat: "ndjson-v1", OrganizationID: "kordex-security",
		ThroughEventID: 19, RecordCount: 2, RecordsSHA256: "records-digest", CreatedAt: "2026-11-18T12:00:00Z",
	}
	if err = SignExportBundle(&bundle, "test-key", private); err != nil {
		t.Fatal(err)
	}
	if !VerifyExportBundleSignature(bundle, public) {
		t.Fatal("valid signature rejected")
	}
	for name, mutate := range map[string]func(*ExportBundle){
		"checkpoint": func(v *ExportBundle) { v.ThroughEventID++ },
		"digest":     func(v *ExportBundle) { v.RecordsSHA256 = "changed" },
		"tenant":     func(v *ExportBundle) { v.OrganizationID = "other" },
		"key id":     func(v *ExportBundle) { v.SigningKeyID = "other-key" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := bundle
			mutate(&changed)
			if VerifyExportBundleSignature(changed, public) {
				t.Fatal("modified signed field accepted")
			}
		})
	}
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyExportBundleSignature(bundle, wrongPublic) {
		t.Fatal("signature verified with an untrusted key")
	}
}

func TestSignExportBundleRequiresPrivateKey(t *testing.T) {
	if err := SignExportBundle(&ExportBundle{}, "key", nil); err == nil {
		t.Fatal("empty private key accepted")
	}
}

func TestExportCheckpointSignatureBindsTenantAndSnapshot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := ExportCheckpoint{
		Format: "kordex-audit-checkpoint-v1", OrganizationID: "12345678-1234-1234-1234-123456789abc",
		ThroughEventID: 22, RecordCount: 3, RecordsSHA256: "records-digest", CreatedAt: "2026-11-19T12:00:00Z",
	}
	if err = SignExportCheckpoint(&checkpoint, "test-key", private); err != nil {
		t.Fatal(err)
	}
	if !VerifyExportCheckpointSignature(checkpoint, public) {
		t.Fatal("valid checkpoint signature rejected")
	}
	for name, mutate := range map[string]func(*ExportCheckpoint){
		"tenant":     func(v *ExportCheckpoint) { v.OrganizationID = "other" },
		"checkpoint": func(v *ExportCheckpoint) { v.ThroughEventID++ },
		"count":      func(v *ExportCheckpoint) { v.RecordCount++ },
		"digest":     func(v *ExportCheckpoint) { v.RecordsSHA256 = "changed" },
		"timestamp":  func(v *ExportCheckpoint) { v.CreatedAt = "2026-11-19T12:00:01Z" },
		"key ID":     func(v *ExportCheckpoint) { v.SigningKeyID = "other-key" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := checkpoint
			mutate(&changed)
			if VerifyExportCheckpointSignature(changed, public) {
				t.Fatal("modified signed field accepted")
			}
		})
	}
}
