package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
)

func TestRunSignsVerifiedTenantExportCheckpoint(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	organization := "12345678-1234-1234-1234-123456789abc"
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "audit.key")
	if err = os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(private.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KORDEX_AUDIT_SIGNING_KEY_FILE", keyPath)
	record := makeRecord(t, 17, organization, make([]byte, sha256.Size))
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(dir, "tenant.jsonl")
	if err = os.WriteFile(exportPath, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(dir, "tenant.manifest")
	if err = run([]string{"-input", exportPath, "-organization-id", organization, "-through-id", "17", "-output", checkpointPath}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(checkpointPath)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint auditchain.ExportCheckpoint
	if err = json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.Format != "kordex-audit-checkpoint-v1" || checkpoint.OrganizationID != organization || checkpoint.ThroughEventID != 17 || checkpoint.RecordCount != 1 || checkpoint.SigningKeyID != protocol.KeyID(public) || !auditchain.VerifyExportCheckpointSignature(checkpoint, public) {
		t.Fatalf("invalid signed checkpoint: %+v", checkpoint)
	}
	expectedDigest := sha256.Sum256(append(line, '\n'))
	if checkpoint.RecordsSHA256 != hex.EncodeToString(expectedDigest[:]) {
		t.Fatal("checkpoint digest does not bind exact NDJSON bytes")
	}
	info, err := os.Stat(checkpointPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("checkpoint permissions=%v err=%v", info, err)
	}
	if err = run([]string{"-input", exportPath, "-organization-id", organization, "-through-id", "17", "-output", checkpointPath}); err == nil {
		t.Fatal("existing checkpoint was overwritten")
	}
}

func TestReadAndVerifyExportRejectsWrongTenantAndBrokenChain(t *testing.T) {
	organization := "12345678-1234-1234-1234-123456789abc"
	record := makeRecord(t, 4, organization, make([]byte, sha256.Size))
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err = os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, count, err := readAndVerifyExport(path, organization, 4); err != nil || count != 1 {
		t.Fatalf("valid chain rejected: count=%d err=%v", count, err)
	}
	if _, _, err = readAndVerifyExport(path, "87654321-4321-4321-4321-cba987654321", 4); err == nil {
		t.Fatal("cross-tenant export accepted")
	}
	broken := record
	broken.EventHash = strings.Repeat("0", 64)
	line, err = json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readAndVerifyExport(path, organization, 4); err == nil {
		t.Fatal("broken event hash accepted")
	}
}

func TestReadAndVerifyExportRejectsDuplicateJSONMembersAndSymlink(t *testing.T) {
	organization := "12345678-1234-1234-1234-123456789abc"
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":1,"id":2,"organizationId":"`+organization+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAndVerifyExport(path, organization, 2); err == nil || !strings.Contains(err.Error(), "duplicate JSON member") {
		t.Fatalf("duplicate event member accepted: %v", err)
	}
	link := filepath.Join(dir, "audit-link.jsonl")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readAndVerifyExport(link, organization, 2); err == nil {
		t.Fatal("symlinked export accepted")
	}
}

func makeRecord(t *testing.T, id int64, organization string, previous []byte) auditchain.Record {
	t.Helper()
	event := auditchain.Event{
		ID: id, OrganizationID: organization, Actor: "oidc:alice", Action: "site.created",
		ResourceID: "resource", RequestID: "12345678-1234-1234-1234-123456789abc",
		OccurredAt: time.Unix(id, 0).UTC(), Metadata: json.RawMessage(`{"source":"test"}`),
	}
	hash, err := auditchain.Hash(previous, event)
	if err != nil {
		t.Fatal(err)
	}
	return auditchain.Record{Event: event, PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash)}
}
