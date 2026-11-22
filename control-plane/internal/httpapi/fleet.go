package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"kordex.local/api/protocol"
	"kordex.local/control-plane/internal/store"
)

type FleetRepository interface {
	CreateFleet(context.Context, string, string, string, string) (store.Fleet, error)
	ListFleets(context.Context, string, int, int) ([]store.Fleet, error)
	CreateCluster(context.Context, store.Cluster, string, string) (store.Cluster, error)
	ListClusters(context.Context, string, int, int) ([]store.Cluster, error)
	IssueEnrollment(context.Context, string, string, string, string) (store.EnrollmentToken, error)
	EnrollAgent(context.Context, protocol.Enrollment, string) (protocol.Identity, error)
	AgentIdentity(context.Context, string) (store.AgentKey, error)
	CheckAgent(context.Context, string, string, string) (protocol.Identity, error)
	AcceptReport(context.Context, string, string, string, protocol.Report) error
	RotateAgent(context.Context, string, string, string, protocol.Rotation, string) (protocol.Identity, error)
	RevokeAgent(context.Context, string, string, string, string) error
	ListNodes(context.Context, string, string, int, int) ([]protocol.Node, error)
	MaintenancePolicyCatalog(context.Context, string, string) (store.PolicyCatalogSnapshot, error)
	Membership(context.Context, string, string) (string, error)
	SetMembership(context.Context, string, string, string, string, string) error
	OrganizationsForSubject(context.Context, string, int, int) ([]store.Organization, error)
}

func (s *Server) registerFleetRoutes(mux *http.ServeMux) {
	for _, route := range []string{"GET /v1/organizations/{organizationID}/fleets", "POST /v1/organizations/{organizationID}/fleets", "GET /v1/organizations/{organizationID}/clusters", "POST /v1/organizations/{organizationID}/clusters", "POST /v1/organizations/{organizationID}/clusters/{clusterID}/enrollment-tokens", "POST /v1/organizations/{organizationID}/clusters/{clusterID}/revoke", "GET /v1/organizations/{organizationID}/clusters/{clusterID}/nodes", "GET /v1/organizations/{organizationID}/clusters/{clusterID}/maintenance-policies", "PUT /v1/organizations/{organizationID}/memberships"} {
		mux.Handle(route, s.auth(http.HandlerFunc(s.fleetAdmin)))
	}
	for _, method := range []string{"GET", "POST"} {
		mux.Handle(method+" /v1/organizations/{organizationID}/clusters/{clusterID}/operations", s.auth(http.HandlerFunc(s.operationAdmin)))
	}
	for _, route := range []string{
		"GET /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle",
		"POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop",
		"POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop/started",
		"POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop/complete",
		"POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/start",
		"POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/start/complete",
	} {
		mux.Handle(route, s.auth(http.HandlerFunc(s.labLifecycleAdmin)))
	}
	mux.HandleFunc("POST /v1/agent/operations/sync", s.agent)
	mux.HandleFunc("POST /v1/agent/enroll", s.enroll)
	for _, route := range []string{"GET /v1/agent/identity", "POST /v1/agent/report", "POST /v1/agent/rotate"} {
		mux.HandleFunc(route, s.agent)
	}
}
func requestID(r *http.Request) string { v, _ := r.Context().Value(requestKey{}).(string); return v }
func (s *Server) fleetRepo(w http.ResponseWriter) (FleetRepository, bool) {
	repo, ok := s.repo.(FleetRepository)
	if !ok {
		problem(w, 503, "inventory_unavailable")
	}
	return repo, ok
}
func (s *Server) fleetAdmin(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.fleetRepo(w)
	if !ok {
		return
	}
	org := r.PathValue("organizationID")
	cluster := r.PathValue("clusterID")
	if cluster != "" && !validID(cluster) {
		problem(w, 400, "invalid_cluster_id")
		return
	}
	switch r.Pattern {
	case "PUT /v1/organizations/{organizationID}/memberships":
		var input struct {
			Subject string `json:"subject"`
			Role    string `json:"role"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !validText(input.Subject, 255) || (input.Role != "viewer" && input.Role != "administrator" && input.Role != "operator" && input.Role != "approver") {
			problem(w, 400, "invalid_membership")
			return
		}
		if err := repo.SetMembership(r.Context(), org, input.Subject, input.Role, actor(r), requestID(r)); err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]string{"status": "updated"})
	case "POST /v1/organizations/{organizationID}/fleets":
		var input struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !validName(input.Name) {
			problem(w, 400, "invalid_name")
			return
		}
		item, err := repo.CreateFleet(r.Context(), org, input.Name, actor(r), requestID(r))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 201, item)
	case "GET /v1/organizations/{organizationID}/fleets":
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := repo.ListFleets(r.Context(), org, limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
	case "POST /v1/organizations/{organizationID}/clusters":
		var input struct {
			Name             string                  `json:"name"`
			FleetID          string                  `json:"fleetId"`
			SiteID           string                  `json:"siteId"`
			Provider         string                  `json:"provider"`
			ProviderMetadata *store.ProviderMetadata `json:"providerMetadata,omitempty"`
		}
		if !decode(w, r, &input) {
			return
		}
		if !validName(input.Name) || !validID(input.FleetID) || !validID(input.SiteID) || (input.Provider != "self-managed" && input.Provider != "gke" && input.Provider != "eks" && input.Provider != "aks") {
			problem(w, 400, "invalid_cluster")
			return
		}
		if input.Provider == "gke" && !store.ValidGKEProviderMetadata(input.ProviderMetadata) || input.Provider != "gke" && input.ProviderMetadata != nil {
			problem(w, 400, "invalid_provider_metadata")
			return
		}
		item, err := repo.CreateCluster(r.Context(), store.Cluster{OrganizationID: org, FleetID: input.FleetID, SiteID: input.SiteID, Name: input.Name, Provider: input.Provider, ProviderMetadata: input.ProviderMetadata}, actor(r), requestID(r))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 201, item)
	case "GET /v1/organizations/{organizationID}/clusters":
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := repo.ListClusters(r.Context(), org, limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
	case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/enrollment-tokens":
		item, err := repo.IssueEnrollment(r.Context(), org, cluster, actor(r), requestID(r))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 201, item)
	case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/revoke":
		if err := repo.RevokeAgent(r.Context(), org, cluster, actor(r), requestID(r)); err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]string{"status": "revoked"})
	case "GET /v1/organizations/{organizationID}/clusters/{clusterID}/nodes":
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		items, err := repo.ListNodes(r.Context(), org, cluster, limit, offset)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, map[string]any{"items": items, "limit": limit, "offset": offset})
	case "GET /v1/organizations/{organizationID}/clusters/{clusterID}/maintenance-policies":
		catalog, err := repo.MaintenancePolicyCatalog(r.Context(), org, cluster)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, catalog)
	}
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.fleetRepo(w)
	if !ok {
		return
	}
	var e protocol.Enrollment
	if !decode(w, r, &e) {
		return
	}
	if !validID(e.ClusterID) || !validText(e.ClusterUID, 128) || len(e.Token) != 43 {
		problem(w, 400, "invalid_enrollment")
		return
	}
	v, err := repo.EnrollAgent(r.Context(), e, requestID(r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 201, v)
}
func (s *Server) agent(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.fleetRepo(w)
	if !ok {
		return
	}
	cluster := r.Header.Get("X-Kordex-Cluster")
	if !validID(cluster) {
		problem(w, 401, "unauthorized")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxReportBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		problem(w, 413, "report_too_large")
		return
	}
	key, err := repo.AgentIdentity(r.Context(), cluster)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	if !protocol.Verify(r, key.PublicKey, body, time.Now()) {
		problem(w, 401, "unauthorized")
		return
	}
	nonce := r.Header.Get("X-Kordex-Nonce")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if len(body) > 0 {
			problem(w, 400, "unexpected_body")
			return
		}
		v, err := repo.CheckAgent(r.Context(), cluster, key.KeyID, nonce)
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, v)
		return
	}
	// Verify the exact bytes before decoding. Unknown fields and trailing JSON are rejected.
	r.Body = io.NopCloser(bytes.NewReader(body))
	if r.Pattern == "POST /v1/agent/rotate" {
		var input protocol.Rotation
		if !decode(w, r, &input) {
			return
		}
		v, err := repo.RotateAgent(r.Context(), cluster, key.KeyID, nonce, input, requestID(r))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, v)
		return
	}
	if r.Pattern == "POST /v1/agent/operations/sync" {
		var input protocol.OperationSync
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		if r.Header.Get("Content-Type") != "application/json" || d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || len(input.Reports) > 10 {
			problem(w, 400, "invalid_operation_sync")
			return
		}
		seen := map[string]bool{}
		for _, report := range input.Reports {
			if !report.Validate() || seen[report.OperationID] {
				problem(w, 400, "invalid_operation_status")
				return
			}
			seen[report.OperationID] = true
		}
		repo, ok := s.repo.(operationRepository)
		if !ok {
			problem(w, 503, "maintenance_unavailable")
			return
		}
		result, err := repo.SyncNodeOperations(r.Context(), cluster, key.KeyID, nonce, input, requestID(r))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		write(w, 200, result)
		return
	}
	var report protocol.Report
	// Inventory has its own larger bound; decode() intentionally caps administrative bodies at 16 KiB.
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if r.Header.Get("Content-Type") != "application/json" || d.Decode(&report) != nil || d.Decode(new(any)) != io.EOF || !validReport(report, time.Now()) {
		problem(w, 400, "invalid_report")
		return
	}
	if err = repo.AcceptReport(r.Context(), cluster, key.KeyID, nonce, report); err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 200, map[string]string{"status": "accepted"})
}
func validText(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func validReport(v protocol.Report, now time.Time) bool {
	if !validText(v.ClusterUID, 128) || v.Version < 1 || v.ObservedAt.Before(now.Add(-protocol.ClockSkew)) || v.ObservedAt.After(now.Add(protocol.ClockSkew)) || !validText(v.KubernetesVersion, 128) || v.Nodes == nil || len(v.Nodes) > protocol.MaxNodes {
		return false
	}
	if v.PolicyCatalog != nil && v.PolicyCatalog.Validate(now) != nil {
		return false
	}
	if v.ClusterCapabilities != nil && v.ClusterCapabilities.Validate(now) != nil {
		return false
	}
	uids := map[string]bool{}
	names := map[string]bool{}
	for _, node := range v.Nodes {
		if !protocol.ValidNodeLabels(node.Labels) || !protocol.ValidNodeDetails(node, now) {
			return false
		}
		if node.Lifecycle != nil && node.Lifecycle.Validate() != nil {
			return false
		}
		if !validText(node.UID, 128) || !validText(node.Name, 253) || uids[node.UID] || names[node.Name] {
			return false
		}
		uids[node.UID] = true
		names[node.Name] = true
		for _, field := range []struct {
			value string
			limit int
		}{{node.OSImage, 256}, {node.KernelVersion, 256}, {node.KubeletVersion, 256}, {node.Architecture, 256}, {node.ContainerRuntime, 256}, {node.Zone, 256}, {node.ProviderID, 512}} {
			if len(field.value) > field.limit || (!validText(field.value, field.limit) && field.value != "") {
				return false
			}
		}
	}
	return true
}
