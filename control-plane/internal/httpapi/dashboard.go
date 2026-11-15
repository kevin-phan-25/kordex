package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"kordex.local/control-plane/internal/store"
)

type DashboardRepository interface {
	DashboardSummary(context.Context, string) (store.DashboardSummary, error)
	ListInventoryNodes(context.Context, string, store.InventoryFilter, int, int) ([]store.InventoryNode, error)
	ListAudit(context.Context, string, string, bool, int64, int64, int, int) ([]store.AuditEntry, error)
}
type DashboardInventoryRepository interface {
	ListInventoryFleets(context.Context, string, int, int) ([]store.Fleet, error)
	ListInventorySites(context.Context, string, int, int) ([]store.Site, error)
	ListInventoryClusters(context.Context, string, int, int) ([]store.Cluster, error)
}

func (s *Server) registerDashboardRoutes(m *http.ServeMux) {
	for _, name := range []string{"summary", "identity", "nodes", "audit"} {
		m.Handle("GET /v1/organizations/{organizationID}/"+name, s.auth(http.HandlerFunc(s.dashboard)))
	}
	for _, name := range []string{"fleets", "sites", "clusters"} {
		m.Handle("GET /v1/organizations/{organizationID}/dashboard/"+name, s.auth(http.HandlerFunc(s.dashboardInventory)))
	}
}
func (s *Server) dashboardInventory(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repo.(DashboardInventoryRepository)
	if !ok {
		problem(w, 503, "dashboard_unavailable")
		return
	}
	for key := range r.URL.Query() {
		if key != "limit" && key != "offset" {
			problem(w, 400, "invalid_filter")
			return
		}
	}
	limit, offset, ok := page(w, r)
	if !ok {
		return
	}
	var v any
	var err error
	switch r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:] {
	case "fleets":
		v, err = repo.ListInventoryFleets(r.Context(), r.PathValue("organizationID"), limit, offset)
	case "sites":
		v, err = repo.ListInventorySites(r.Context(), r.PathValue("organizationID"), limit, offset)
	default:
		v, err = repo.ListInventoryClusters(r.Context(), r.PathValue("organizationID"), limit, offset)
	}
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, 200, map[string]any{"items": v, "limit": limit, "offset": offset})
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("organizationID")
	if strings.HasSuffix(r.Pattern, "/identity") {
		p := principal(r)
		write(w, 200, map[string]string{"subject": p.Subject, "actor": actor(r), "role": p.Role})
		return
	}
	repo, ok := s.repo.(DashboardRepository)
	if !ok {
		problem(w, 503, "dashboard_unavailable")
		return
	}
	if strings.HasSuffix(r.Pattern, "/summary") {
		v, e := repo.DashboardSummary(r.Context(), org)
		if e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, 200, v)
		return
	}
	query := r.URL.Query()
	f := store.InventoryFilter{}
	auditAscending := false
	auditAfterID := int64(0)
	auditAfterValue := ""
	auditThroughID := int64(0)
	auditThroughValue := ""
	allowed := map[string]*string{}
	if strings.HasSuffix(r.Pattern, "/nodes") {
		allowed["search"] = &f.Search
		allowed["clusterId"] = &f.ClusterID
		allowed["fleetId"] = &f.FleetID
		allowed["siteId"] = &f.SiteID
		allowed["health"] = &f.Health
	} else if strings.HasSuffix(r.Pattern, "/audit") {
		allowed["search"] = &f.Search
		allowed["afterId"] = &auditAfterValue
		allowed["throughId"] = &auditThroughValue
		order := query.Get("order")
		if order != "" && order != "asc" && order != "desc" {
			problem(w, 400, "invalid_filter")
			return
		}
		if len(query["order"]) > 1 {
			problem(w, 400, "invalid_filter")
			return
		}
		delete(query, "order")
		auditAscending = order == "asc"
	}
	for key, values := range query {
		if key == "limit" || key == "offset" {
			continue
		}
		destination, exists := allowed[key]
		if !exists || len(values) != 1 {
			problem(w, 400, "invalid_filter")
			return
		}
		*destination = values[0]
		query.Del(key)
	}
	for _, id := range []string{f.ClusterID, f.FleetID, f.SiteID} {
		if id != "" && !validID(id) {
			problem(w, 400, "invalid_filter")
			return
		}
	}
	if len(f.Search) > 128 || (f.Health != "" && f.Health != "healthy" && f.Health != "unhealthy" && f.Health != "unknown") {
		problem(w, 400, "invalid_filter")
		return
	}
	parseAuditCursor := func(value string) (int64, bool) {
		if value == "" {
			return 0, true
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil && parsed >= 0
	}
	if auditAfterValue != "" || auditThroughValue != "" {
		if !auditAscending {
			problem(w, 400, "invalid_filter")
			return
		}
		var valid bool
		auditAfterID, valid = parseAuditCursor(auditAfterValue)
		if !valid {
			problem(w, 400, "invalid_filter")
			return
		}
		auditThroughID, valid = parseAuditCursor(auditThroughValue)
		if !valid || (auditThroughID > 0 && auditAfterID > auditThroughID) {
			problem(w, 400, "invalid_filter")
			return
		}
	}
	copyRequest := r.Clone(r.Context())
	urlCopy := *r.URL
	urlCopy.RawQuery = query.Encode()
	copyRequest.URL = &urlCopy
	limit, offset, ok := page(w, copyRequest)
	if !ok {
		return
	}
	if (auditAfterID > 0 || auditThroughID > 0) && offset != 0 {
		problem(w, 400, "invalid_filter")
		return
	}
	var v any
	var e error
	if strings.HasSuffix(r.Pattern, "/audit") {
		v, e = repo.ListAudit(r.Context(), org, f.Search, auditAscending, auditAfterID, auditThroughID, limit, offset)
	} else {
		v, e = repo.ListInventoryNodes(r.Context(), org, f, limit, offset)
	}
	if e != nil {
		s.failure(w, r, e)
		return
	}
	write(w, 200, map[string]any{"items": v, "limit": limit, "offset": offset})
}
