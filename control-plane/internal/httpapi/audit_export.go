package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/auditchain"
	"kordex.local/control-plane/internal/store"
)

const (
	dashboardAuditPageSize         = 500
	dashboardAuditMaxRows          = 100_000
	dashboardAuditMaxBytes         = 4 << 20
	dashboardAuditMaxResponseBytes = 8 << 20
)

// DashboardAuditExportRepository exposes only the tenant-scoped read needed to
// assemble a fixed high-water snapshot.
type DashboardAuditExportRepository interface {
	ListAudit(context.Context, string, string, bool, int64, int64, int, int) ([]store.AuditEntry, error)
}

func (s *Server) registerDashboardAuditExport(m *http.ServeMux) {
	m.Handle("GET /v1/organizations/{organizationID}/audit/export", s.auth(http.HandlerFunc(s.dashboardAuditExport)))
}

func (s *Server) dashboardAuditExport(w http.ResponseWriter, r *http.Request) {
	if len(s.auditKey) != 64 {
		problem(w, http.StatusServiceUnavailable, "audit_export_signing_unavailable")
		return
	}
	if len(r.URL.Query()) != 0 {
		problem(w, http.StatusBadRequest, "invalid_filter")
		return
	}
	repo, ok := s.repo.(DashboardAuditExportRepository)
	if !ok {
		problem(w, http.StatusServiceUnavailable, "dashboard_unavailable")
		return
	}
	org := r.PathValue("organizationID")
	head, err := repo.ListAudit(r.Context(), org, "", false, 0, 0, 1, 0)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	if len(head) == 0 {
		problem(w, http.StatusNotFound, "audit_export_empty")
		return
	}
	throughID := head[0].ID
	if throughID < 1 || head[0].OrganizationID != org {
		problem(w, http.StatusInternalServerError, "audit_export_snapshot_invalid")
		return
	}

	var records bytes.Buffer
	lastID := int64(0)
	count := 0
	for lastID < throughID {
		page, listErr := repo.ListAudit(r.Context(), org, "", true, lastID, throughID, dashboardAuditPageSize, 0)
		if listErr != nil {
			s.failure(w, r, listErr)
			return
		}
		if len(page) == 0 {
			problem(w, http.StatusConflict, "audit_export_snapshot_incomplete")
			return
		}
		for _, entry := range page {
			if entry.ID <= lastID || entry.ID > throughID || entry.OrganizationID != org {
				problem(w, http.StatusInternalServerError, "audit_export_snapshot_invalid")
				return
			}
			line, marshalErr := json.Marshal(entry)
			if marshalErr != nil {
				problem(w, http.StatusInternalServerError, "audit_export_snapshot_invalid")
				return
			}
			if count >= dashboardAuditMaxRows || records.Len()+len(line)+1 > dashboardAuditMaxBytes {
				problem(w, http.StatusRequestEntityTooLarge, "audit_export_size_limit")
				return
			}
			records.Write(line)
			records.WriteByte('\n')
			lastID = entry.ID
			count++
		}
	}
	if lastID != throughID {
		problem(w, http.StatusConflict, "audit_export_snapshot_incomplete")
		return
	}
	if _, _, err = auditchain.VerifyExportRecords(records.Bytes(), org, throughID, true); err != nil {
		s.logger.ErrorContext(r.Context(), "dashboard audit snapshot verification failed", "request_id", requestID(r), "organization_id", org)
		problem(w, http.StatusInternalServerError, "audit_export_integrity_failed")
		return
	}
	digest := sha256.Sum256(records.Bytes())
	bundle := auditchain.ExportBundle{
		Format:         "kordex-audit-export-v1",
		RecordsFormat:  "ndjson-v1",
		OrganizationID: org,
		ThroughEventID: throughID,
		RecordCount:    count,
		RecordsSHA256:  hex.EncodeToString(digest[:]),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		RecordsNDJSON:  records.String(),
	}
	keyID := protocol.KeyID(s.auditKey.Public().(ed25519.PublicKey))
	if err = auditchain.SignExportBundle(&bundle, keyID, s.auditKey); err != nil {
		problem(w, http.StatusInternalServerError, "audit_export_signing_failed")
		return
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		problem(w, http.StatusInternalServerError, "audit_export_signing_failed")
		return
	}
	if len(encoded)+1 > dashboardAuditMaxResponseBytes {
		problem(w, http.StatusRequestEntityTooLarge, "audit_export_size_limit")
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"kordex-audit-export.json\"")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err = w.Write(append(encoded, '\n')); err != nil {
		panic("audit export response write failed")
	}
}
