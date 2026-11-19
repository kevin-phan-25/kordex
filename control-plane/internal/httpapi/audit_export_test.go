package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
	"kordex.local/control-plane/internal/store"
)

type auditExportRepo struct {
	*fakeRepo
	entries []store.AuditEntry
}

func chainedAuditEntry(t *testing.T, id int64, org, action string, occurred time.Time, previous []byte) (store.AuditEntry, []byte) {
	t.Helper()
	metadata := json.RawMessage(`{"ok":true}`)
	event := auditchain.Event{ID: id, OrganizationID: org, Actor: "admin", Action: action, ResourceID: "site-1", RequestID: "request", OccurredAt: occurred, Metadata: metadata}
	hash, err := auditchain.Hash(previous, event)
	if err != nil {
		t.Fatal(err)
	}
	return store.AuditEntry{ID: id, OrganizationID: org, Actor: event.Actor, Action: action, ResourceID: event.ResourceID,
		RequestID: event.RequestID, OccurredAt: occurred, Metadata: metadata,
		PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash)}, hash
}

func (r *auditExportRepo) ListAudit(_ context.Context, org, _ string, ascending bool, afterID, throughID int64, limit, _ int) ([]store.AuditEntry, error) {
	if !ascending {
		if len(r.entries) == 0 {
			return nil, nil
		}
		return []store.AuditEntry{r.entries[len(r.entries)-1]}, nil
	}
	items := make([]store.AuditEntry, 0, limit)
	for _, entry := range r.entries {
		if entry.OrganizationID == org && entry.ID > afterID && entry.ID <= throughID && len(items) < limit {
			items = append(items, entry)
		}
	}
	return items, nil
}

func TestDashboardAuditExportReturnsSignedFixedTenantSnapshot(t *testing.T) {
	org := "80bd80f9-f097-4474-86f4-b80986fd5423"
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	baseTime := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	first, previous := chainedAuditEntry(t, 1, org, "site.created", baseTime, make([]byte, sha256.Size))
	second, _ := chainedAuditEntry(t, 3, org, "site.updated", baseTime.Add(time.Minute), previous)
	second.PreviousHash = first.EventHash
	repo := &auditExportRepo{fakeRepo: &fakeRepo{}, entries: []store.AuditEntry{first, second}}
	h := NewWithOptions(repo, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), Options{AllowBootstrap: true, AuditKey: private})
	response := request(h, http.MethodGet, "/v1/organizations/"+org+"/audit/export", "", token)
	if response.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", response.Code, response.Body.String())
	}
	var bundle auditchain.ExportBundle
	if err = json.Unmarshal(response.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.OrganizationID != org || bundle.ThroughEventID != 3 || bundle.RecordCount != 2 || bundle.SigningKeyID != protocol.KeyID(public) {
		t.Fatalf("unexpected signed checkpoint: %+v", bundle)
	}
	if !auditchain.VerifyExportBundleSignature(bundle, public) {
		t.Fatal("API export signature did not verify")
	}
	digest := sha256.Sum256([]byte(bundle.RecordsNDJSON))
	if bundle.RecordsSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("signed digest does not match the exported NDJSON bytes")
	}
	count, chained, err := auditchain.VerifyExportRecords([]byte(bundle.RecordsNDJSON), org, 3, true)
	if err != nil || count != 2 || chained != 2 {
		t.Fatalf("export records count=%d chained=%d err=%v", count, chained, err)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("audit export cache policy = %q", response.Header().Get("Cache-Control"))
	}
}

func TestDashboardAuditExportFailsClosedWithoutKeyAndOnInvalidSnapshot(t *testing.T) {
	org := "80bd80f9-f097-4474-86f4-b80986fd5423"
	repo := &auditExportRepo{fakeRepo: &fakeRepo{}, entries: []store.AuditEntry{{
		ID: 1, OrganizationID: org, Actor: "admin", Action: "test", ResourceID: "resource", RequestID: "request",
		OccurredAt: time.Now().UTC(), Metadata: json.RawMessage(`{}`),
	}}}
	withoutKey := NewWithOptions(repo, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), Options{AllowBootstrap: true})
	response := request(withoutKey, http.MethodGet, "/v1/organizations/"+org+"/audit/export", "", token)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing key status=%d body=%s", response.Code, response.Body.String())
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repo.entries[0].OrganizationID = "90bd80f9-f097-4474-86f4-b80986fd5423"
	withKey := NewWithOptions(repo, token, "Kordex", slog.New(slog.NewJSONHandler(io.Discard, nil)), Options{AllowBootstrap: true, AuditKey: private})
	response = request(withKey, http.MethodGet, "/v1/organizations/"+org+"/audit/export", "", token)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("mismatched tenant status=%d body=%s", response.Code, response.Body.String())
	}
}
