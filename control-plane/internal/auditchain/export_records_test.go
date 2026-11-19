package auditchain

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyExportRecordsAllowsLegacyPrefixAndChecksChainedSuffix(t *testing.T) {
	organization := "12345678-1234-1234-1234-123456789abc"
	legacy := Record{Event: Event{ID: 2, OrganizationID: organization}}
	previous := make([]byte, 32)
	event := Event{ID: 7, OrganizationID: organization, Actor: "test", Action: "site.created", OccurredAt: time.Unix(7, 0).UTC(), Metadata: json.RawMessage(`{}`)}
	hash, err := Hash(previous, event)
	if err != nil {
		t.Fatal(err)
	}
	chained := Record{Event: event, PreviousHash: hex.EncodeToString(previous), EventHash: hex.EncodeToString(hash)}
	data := append(marshalRecordLine(t, legacy), marshalRecordLine(t, chained)...)
	count, chainedCount, err := VerifyExportRecords(data, organization, 7, true)
	if err != nil || count != 2 || chainedCount != 1 {
		t.Fatalf("valid legacy prefix and chained suffix rejected: count=%d chained=%d err=%v", count, chainedCount, err)
	}
	broken := Record{Event: Event{ID: 9, OrganizationID: organization}}
	data = append(marshalRecordLine(t, chained), marshalRecordLine(t, broken)...)
	if _, _, err = VerifyExportRecords(data, organization, 9, true); err == nil || !strings.Contains(err.Error(), "incomplete hash chain") {
		t.Fatalf("unchained event after chain start accepted: %v", err)
	}
}

func TestVerifyExportRecordsAuthenticatesLegacyOnlySnapshotsBySignatureContract(t *testing.T) {
	organization := "12345678-1234-1234-1234-123456789abc"
	legacy := Record{Event: Event{ID: 5, OrganizationID: organization}}
	data := marshalRecordLine(t, legacy)
	count, chainedCount, err := VerifyExportRecords(data, organization, 5, true)
	if err != nil || count != 1 || chainedCount != 0 {
		t.Fatalf("signed legacy snapshot structure rejected: count=%d chained=%d err=%v", count, chainedCount, err)
	}
	if _, _, err = VerifyExportRecords(data, organization, 5, false); err == nil {
		t.Fatal("unsigned legacy-only snapshot accepted as hash-chain verified")
	}
	if _, _, err = VerifyExportRecords(data, "87654321-4321-4321-4321-cba987654321", 5, true); err == nil {
		t.Fatal("cross-tenant record accepted")
	}
}

func marshalRecordLine(t *testing.T, record Record) []byte {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}
