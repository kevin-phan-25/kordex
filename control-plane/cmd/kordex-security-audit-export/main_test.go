package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kordex.local/control-plane/internal/auditchain"
)

type fakeAuditSource struct{ records []auditchain.Record }

func (s fakeAuditSource) SecurityAuditCheckpoint(context.Context) (int64, []byte, error) {
	if len(s.records) == 0 {
		return 0, make([]byte, sha256.Size), nil
	}
	hash, err := hex.DecodeString(s.records[len(s.records)-1].EventHash)
	return s.records[len(s.records)-1].ID, hash, err
}
func (s fakeAuditSource) ListSecurityAudit(_ context.Context, afterID, throughID int64, limit int) ([]auditchain.Record, error) {
	items := make([]auditchain.Record, 0, limit)
	for _, record := range s.records {
		if record.ID > afterID && record.ID <= throughID && len(items) < limit {
			items = append(items, record)
		}
	}
	return items, nil
}

func testAuditRecords(t *testing.T, ids ...int64) []auditchain.Record {
	t.Helper()
	previous := make([]byte, sha256.Size)
	records := make([]auditchain.Record, 0, len(ids))
	for _, id := range ids {
		event := auditchain.Event{ID: id, OrganizationID: "kordex-security", Actor: "oidc:alice", Action: "authorization.denied", ResourceID: "", RequestID: "80bd80f9-f097-4474-86f4-b80986fd5423", OccurredAt: time.Unix(id, 0).UTC(), Metadata: json.RawMessage(`{"reason":"role_denied","method":"POST","route":"POST /v1/organizations/{organizationID}/sites","role":"viewer"}`)}
		hash, err := auditchain.Hash(previous, event)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, auditchain.Record{Event: event, PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash)})
		previous = hash
	}
	return records
}

func TestCreateBundleVerifiesChainAcrossSequenceGaps(t *testing.T) {
	records := testAuditRecords(t, 2, 5)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, count, throughID, err := createBundle(context.Background(), fakeAuditSource{records: records}, private)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || throughID != 5 {
		t.Fatalf("count=%d checkpoint=%d", count, throughID)
	}
	var got bundle
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.OrganizationID != "kordex-security" || got.ThroughEventID != 5 || got.RecordCount != 2 || got.CreatedAt == "" || got.SigningKeyID == "" || got.Signature == "" {
		t.Fatalf("invalid bundle manifest: %+v", got)
	}
	digest := sha256.Sum256([]byte(got.RecordsNDJSON))
	if got.RecordsSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("bundle records digest mismatch")
	}
}

func TestCreateBundleRejectsTamperedChainAndMissingTail(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	records := testAuditRecords(t, 1, 3)
	records[1].EventHash = records[0].EventHash
	if _, _, _, err := createBundle(context.Background(), fakeAuditSource{records: records}, private); err == nil {
		t.Fatal("tampered chain accepted")
	}
	if _, _, _, err := createBundle(context.Background(), fakeAuditSource{records: testAuditRecords(t, 1)}, private); err != nil {
		t.Fatalf("valid single-record chain rejected: %v", err)
	}
	missing := fakeAuditSource{records: testAuditRecords(t, 1)}
	missing.records = append(missing.records, auditchain.Record{Event: auditchain.Event{ID: 4}})
	if _, _, _, err := createBundle(context.Background(), missing, private); err == nil {
		t.Fatal("invalid tail accepted")
	}
}

func TestWriteNewFileUsesPrivateModeAndNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.json")
	if err := writeNewFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("export permissions are too broad: %o", info.Mode().Perm())
	}
	if err = writeNewFile(path, []byte("second")); err == nil {
		t.Fatal("existing export overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first" {
		t.Fatalf("existing export changed: %q err=%v", data, err)
	}
}

func TestWriteNewFileRefusesSymlinkDestination(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "export.json")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeNewFile(link, []byte("replace")); err == nil {
		t.Fatal("symlink export destination accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: %q err=%v", data, err)
	}
}

func TestLoadAuditSigningKeyRequiresPrivateRegularFile(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit-key")
	if err = os.WriteFile(path, []byte(base64.RawStdEncoding.EncodeToString(private.Seed())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadAuditSigningKey(path)
	if err != nil || !loaded.Equal(private) {
		t.Fatalf("valid private key rejected: err=%v", err)
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAuditSigningKey(path); err == nil {
		t.Fatal("group/world-readable signing key accepted")
	}
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "key-link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAuditSigningKey(link); err == nil {
		t.Fatal("symlink signing key accepted")
	}
}
