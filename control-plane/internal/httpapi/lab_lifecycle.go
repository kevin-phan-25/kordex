package httpapi

import (
	"context"
	"net/http"

	"kordex.local/control-plane/internal/store"
)

type labLifecycleRepository interface {
	LabLifecycleStatus(context.Context, string, string) (store.LabLifecycle, error)
	RequestLabStop(context.Context, string, string, string, string) (store.LabLifecycle, error)
	MarkLabStopping(context.Context, string, string, string, string) (store.LabLifecycle, error)
	CompleteLabStop(context.Context, string, string, string, string) (store.LabLifecycle, error)
	BeginLabStart(context.Context, string, string, string, string) (store.LabLifecycle, error)
	CompleteLabStart(context.Context, string, string, string, string) (store.LabLifecycle, error)
}

func (s *Server) labLifecycleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Pattern == "GET /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/authorization" {
		identity := principal(r)
		if identity.Role != "administrator" || identity.Bootstrap {
			problem(w, http.StatusForbidden, "administrator_required")
			return
		}
		if !validID(r.PathValue("clusterID")) {
			problem(w, http.StatusBadRequest, "invalid_cluster_id")
			return
		}
		write(w, http.StatusOK, map[string]any{"authorized": true, "role": "administrator"})
		return
	}
	if r.Method != http.MethodGet && principal(r).Role != "administrator" {
		problem(w, http.StatusForbidden, "administrator_required")
		return
	}
	repo, ok := s.repo.(labLifecycleRepository)
	if !ok {
		problem(w, http.StatusServiceUnavailable, "lab_lifecycle_unavailable")
		return
	}
	org, cluster := r.PathValue("organizationID"), r.PathValue("clusterID")
	if !validID(cluster) {
		problem(w, http.StatusBadRequest, "invalid_cluster_id")
		return
	}
	var value store.LabLifecycle
	var err error
	if r.Method == http.MethodGet {
		value, err = repo.LabLifecycleStatus(r.Context(), org, cluster)
	} else {
		who, req := actor(r), requestID(r)
		switch r.Pattern {
		case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop":
			value, err = repo.RequestLabStop(r.Context(), org, cluster, who, req)
		case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop/started":
			value, err = repo.MarkLabStopping(r.Context(), org, cluster, who, req)
		case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop/complete":
			value, err = repo.CompleteLabStop(r.Context(), org, cluster, who, req)
		case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/start":
			value, err = repo.BeginLabStart(r.Context(), org, cluster, who, req)
		case "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/start/complete":
			value, err = repo.CompleteLabStart(r.Context(), org, cluster, who, req)
		default:
			problem(w, http.StatusNotFound, "route_not_found")
			return
		}
	}
	if err != nil {
		s.failure(w, r, err)
		return
	}
	write(w, http.StatusOK, value)
}
