package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
)

func TestVerifyAcceptsGlobalIDGapsFromOtherOrganizations(t *testing.T) {
	previous := make([]byte, 32)
	first := testAuditRecord(t, 41, "org-a", previous, "first")
	firstHash, err := hex.DecodeString(first.EventHash)
	if err != nil {
		t.Fatal(err)
	}
	second := testAuditRecord(t, 44, "org-a", firstHash, "second")
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	secondData, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, secondData...)
	data = append(data, '\n')

	count, err := verify(bytes.NewReader(data), second.ID)
	if err != nil || count != 2 {
		t.Fatalf("valid organization chain with globally interleaved IDs rejected: count=%d err=%v", count, err)
	}
}

func TestVerifyStillRejectsMissingOrganizationEventAndWrongCheckpoint(t *testing.T) {
	zero := make([]byte, 32)
	first := testAuditRecord(t, 41, "org-a", zero, "first")
	firstHash, err := hex.DecodeString(first.EventHash)
	if err != nil {
		t.Fatal(err)
	}
	missing := testAuditRecord(t, 43, "org-a", firstHash, "missing")
	missingHash, err := hex.DecodeString(missing.EventHash)
	if err != nil {
		t.Fatal(err)
	}
	last := testAuditRecord(t, 47, "org-a", missingHash, "last")
	firstData, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	lastData, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	input := append(append(append(firstData, '\n'), lastData...), '\n')
	if _, err = verify(bytes.NewReader(input), last.ID); err == nil {
		t.Fatal("omitted same-organization event was accepted")
	}
	validInput, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	validInput = append(validInput, '\n')
	if _, err = verify(bytes.NewReader(validInput), first.ID+1); err == nil {
		t.Fatal("wrong final audit checkpoint was accepted")
	}
}

func TestVerifyBundleChecksDigestChainTenantAndExternalCheckpoint(t *testing.T) {
	zero := make([]byte, 32)
	first := testAuditRecord(t, 51, "org-a", zero, "first")
	firstHash, err := hex.DecodeString(first.EventHash)
	if err != nil {
		t.Fatal(err)
	}
	second := testAuditRecord(t, 55, "org-a", firstHash, "second")
	records := marshalAuditRecords(t, first, second)
	bundle := testBundle(t, records, "org-a", second.ID, 2)
	count, err := verifyBundle(bytes.NewReader(bundle), second.ID, nil)
	if err != nil || count != 2 {
		t.Fatalf("valid audit bundle rejected: count=%d err=%v", count, err)
	}
	if _, err = verifyBundle(bytes.NewReader(bundle), second.ID+1, nil); err == nil {
		t.Fatal("bundle checkpoint differing from the independently retained checkpoint was accepted")
	}

	var changed auditchain.ExportBundle
	if err = json.Unmarshal(bundle, &changed); err != nil {
		t.Fatal(err)
	}
	changed.RecordsNDJSON = strings.Replace(changed.RecordsNDJSON, `"actor":"test"`, `"actor":"tost"`, 1)
	tampered, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyBundle(bytes.NewReader(tampered), second.ID, nil); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("record tampering was not detected: %v", err)
	}
	wrongCount := testBundle(t, records, "org-a", second.ID, 3)
	if _, err = verifyBundle(bytes.NewReader(wrongCount), second.ID, nil); err == nil || !strings.Contains(err.Error(), "manifest says") {
		t.Fatalf("wrong bundle record count was accepted: %v", err)
	}
	wrongOrgRecord := testAuditRecord(t, 51, "org-b", zero, "first")
	wrongOrg := testBundle(t, marshalAuditRecords(t, wrongOrgRecord), "org-a", wrongOrgRecord.ID, 1)
	if _, err = verifyBundle(bytes.NewReader(wrongOrg), wrongOrgRecord.ID, nil); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("cross-organization bundle record was accepted: %v", err)
	}
}

func TestVerifyBundleRejectsDuplicateJSONMembers(t *testing.T) {
	record := testAuditRecord(t, 61, "org-a", make([]byte, 32), "first")
	bundle := testBundle(t, marshalAuditRecords(t, record), "org-a", record.ID, 1)
	duplicate := bytes.Replace(bundle, []byte(`"format":"kordex-audit-export-v1"`), []byte(`"format":"kordex-audit-export-v1","format":"kordex-audit-export-v1"`), 1)
	if _, err := verifyBundle(bytes.NewReader(duplicate), record.ID, nil); err == nil || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate bundle member was accepted: %v", err)
	}
	duplicateRecord := bytes.Replace(marshalAuditRecords(t, record), []byte(`"actor":"test"`), []byte(`"actor":"attacker","actor":"test"`), 1)
	duplicateRecordBundle := testBundle(t, duplicateRecord, "org-a", record.ID, 1)
	if _, err := verifyBundle(bytes.NewReader(duplicateRecordBundle), record.ID, nil); err == nil || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate audit record member was accepted: %v", err)
	}
}

func TestVerifyBundleRequiresTrustedSignatureForPlatformSecurity(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record := testAuditRecord(t, 71, "kordex-security", make([]byte, 32), "authorization.denied")
	data := signedTestBundle(t, marshalAuditRecords(t, record), "kordex-security", record.ID, 1, private)
	keyID := protocol.KeyID(public)
	trusted := map[string]ed25519.PublicKey{keyID: public}
	if _, err = verifyBundle(bytes.NewReader(data), record.ID, trusted); err != nil {
		t.Fatalf("trusted signed security bundle rejected: %v", err)
	}
	if _, err = verifyBundle(bytes.NewReader(data), record.ID, nil); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("bundle without independently trusted key accepted: %v", err)
	}
	unsigned := testBundle(t, marshalAuditRecords(t, record), "kordex-security", record.ID, 1)
	if _, err = verifyBundle(bytes.NewReader(unsigned), record.ID, trusted); err == nil || !strings.Contains(err.Error(), "must have") {
		t.Fatalf("unsigned platform security bundle accepted: %v", err)
	}
	changed := bytes.Replace(data, []byte(`"throughEventId":71`), []byte(`"throughEventId":72`), 1)
	if _, err = verifyBundle(bytes.NewReader(changed), record.ID, trusted); err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("tampered signed checkpoint accepted: %v", err)
	}
}

func TestLoadTrustBundleValidatesKeyIDsAndDuplicateMembers(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit-trust.json")
	valid, err := json.Marshal(map[string]string{protocol.KeyID(public): protocol.EncodeKey(public)})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted, err := loadTrustBundle(path)
	if err != nil || len(trusted) != 1 {
		t.Fatalf("valid trust bundle rejected: keys=%d err=%v", len(trusted), err)
	}
	if err = os.WriteFile(path, []byte(`{"key":"bad","key":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadTrustBundle(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate trust key accepted: %v", err)
	}
	if err = os.WriteFile(path, []byte(`{"wrong-key-id":"`+protocol.EncodeKey(public)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadTrustBundle(path); err == nil || !strings.Contains(err.Error(), "invalid public key entry") {
		t.Fatalf("mismatched key ID accepted: %v", err)
	}
}

func TestVerifyCheckpointAuthenticatesTenantExportAndExternalHighWater(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	organization := "12345678-1234-1234-1234-123456789abc"
	record := testAuditRecord(t, 81, organization, make([]byte, 32), "site.created")
	records := marshalAuditRecords(t, record)
	digest := sha256.Sum256(records)
	checkpoint := auditchain.ExportCheckpoint{
		Format: "kordex-audit-checkpoint-v1", OrganizationID: organization,
		ThroughEventID: record.ID, RecordCount: 1, RecordsSHA256: fmt.Sprintf("%x", digest),
		CreatedAt: time.Date(2026, time.November, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}
	keyID := protocol.KeyID(public)
	if err = auditchain.SignExportCheckpoint(&checkpoint, keyID, private); err != nil {
		t.Fatal(err)
	}
	checkpointData, err := json.Marshal(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(t.TempDir(), "checkpoint.json")
	if err = os.WriteFile(checkpointPath, checkpointData, 0o600); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{keyID: public}
	count, chainCount, err := verifyCheckpoint(bytes.NewReader(records), checkpointPath, record.ID, trusted)
	if err != nil || count != 1 || chainCount != 1 {
		t.Fatalf("valid signed checkpoint rejected: count=%d chain=%d err=%v", count, chainCount, err)
	}
	if _, _, err = verifyCheckpoint(bytes.NewReader(records), checkpointPath, record.ID+1, trusted); err == nil || !strings.Contains(err.Error(), "independently retained") {
		t.Fatalf("wrong external high-water accepted: %v", err)
	}
	if _, _, err = verifyCheckpoint(bytes.NewReader(records), checkpointPath, record.ID, nil); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("checkpoint without trusted key accepted: %v", err)
	}
	tampered := bytes.Replace(records, []byte(`"actor":"test"`), []byte(`"actor":"tost"`), 1)
	if _, _, err = verifyCheckpoint(bytes.NewReader(tampered), checkpointPath, record.ID, trusted); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("tampered tenant export accepted: %v", err)
	}
}

func marshalAuditRecords(t *testing.T, records ...auditchain.Record) []byte {
	t.Helper()
	var result []byte
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, data...)
		result = append(result, '\n')
	}
	return result
}

func testBundle(t *testing.T, records []byte, organization string, throughID int64, recordCount int) []byte {
	t.Helper()
	digest := sha256.Sum256(records)
	bundle := auditchain.ExportBundle{
		Format: "kordex-audit-export-v1", RecordsFormat: "ndjson-v1", OrganizationID: organization,
		ThroughEventID: throughID, RecordCount: recordCount, RecordsSHA256: fmt.Sprintf("%x", digest),
		CreatedAt: time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), RecordsNDJSON: string(records),
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func signedTestBundle(t *testing.T, records []byte, organization string, throughID int64, recordCount int, private ed25519.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256(records)
	bundle := auditchain.ExportBundle{
		Format: "kordex-audit-export-v1", RecordsFormat: "ndjson-v1", OrganizationID: organization,
		ThroughEventID: throughID, RecordCount: recordCount, RecordsSHA256: fmt.Sprintf("%x", digest),
		CreatedAt: time.Date(2026, time.November, 18, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), RecordsNDJSON: string(records),
	}
	public := private.Public().(ed25519.PublicKey)
	if err := auditchain.SignExportBundle(&bundle, protocol.KeyID(public), private); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testAuditRecord(t *testing.T, id int64, organization string, previous []byte, action string) auditchain.Record {
	t.Helper()
	event := auditchain.Event{
		ID: id, OrganizationID: organization, Actor: "test", Action: action,
		ResourceID: "resource", RequestID: "request", OccurredAt: time.Unix(id, 0).UTC(),
		Metadata: json.RawMessage(`{"test":true}`),
	}
	hash, err := auditchain.Hash(previous, event)
	if err != nil {
		t.Fatal(err)
	}
	return auditchain.Record{Event: event, PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash)}
}
