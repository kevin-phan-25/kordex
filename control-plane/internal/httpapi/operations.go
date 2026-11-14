package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"os"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
)

type operationRepository interface {
	CreateNodeOperation(context.Context, string, string, protocol.MaintenanceRequest, ed25519.PrivateKey, string, string) (store.NodeOperation, error)
	ListNodeOperations(context.Context, string, string, int, int) ([]store.NodeOperation, error)
	SyncNodeOperations(context.Context, string, string, string, protocol.OperationSync, string) (protocol.OperationSyncResult, error)
}

func LoadMaintenanceKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, err
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize]), raw) {
		return ed25519.PrivateKey(raw), nil
	}
	return nil, os.ErrInvalid
}
func (s *Server) operationAdmin(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repo.(operationRepository)
	if !ok {
		problem(w, 503, "maintenance_unavailable")
		return
	}
	org, cluster := r.PathValue("organizationID"), r.PathValue("clusterID")
	if !validID(cluster) {
		problem(w, 400, "invalid_cluster_id")
		return
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := repo.ListNodeOperations(r.Context(), org, cluster, limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
		return
	}
	if len(s.maintenanceKey) != ed25519.PrivateKeySize {
		problem(w, 503, "maintenance_signer_not_configured")
		return
	}
	var input protocol.MaintenanceRequest
	if !decode(w, r, &input) {
		return
	}
	if input.Validate() != nil {
		problem(w, 400, "invalid_operation")
		return
	}
	op, err := repo.CreateNodeOperation(r.Context(), org, cluster, input, s.maintenanceKey, actor(r), requestID(r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 201, op)
}
