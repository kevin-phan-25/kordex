package httpapi

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"

	"kordex.local/api/campaign"
	"kordex.local/control-plane/internal/store"
)

type CampaignRepository interface {
	PreviewCampaign(context.Context, string, campaign.Spec) (store.CampaignPreview, error)
	CreateCampaign(context.Context, string, string, campaign.Spec, string, string) (store.Campaign, error)
	UpdateCampaign(context.Context, string, string, int64, campaign.Spec, string, string) (store.Campaign, error)
	StartCampaign(context.Context, string, string, int64, string, string) (store.Campaign, error)
	ControlCampaign(context.Context, string, string, string, store.CampaignControl, string, string, string, ed25519.PrivateKey) (store.Campaign, error)
	GetCampaign(context.Context, string, string) (store.Campaign, error)
	ListCampaigns(context.Context, string, int, int) ([]store.Campaign, error)
	ListCampaignTargets(context.Context, string, string, int, int) ([]store.CampaignTarget, error)
	ListCampaignOperations(context.Context, string, string, int, int) ([]store.NodeOperation, error)
	ListCampaignEvents(context.Context, string, string, int, int) ([]store.CampaignEvent, error)
	ListCampaignApprovals(context.Context, string, string, int, int) ([]store.Approval, error)
	GetConcurrencyPolicy(context.Context, string) (store.ConcurrencyPolicy, error)
	SetConcurrencyPolicy(context.Context, string, int64, campaign.Limits, string, string) (store.ConcurrencyPolicy, error)
	CancelNodeOperation(context.Context, string, string, string, ed25519.PrivateKey, string, string) error
}

func authorizedRoute(r *http.Request, role string) bool {
	if role != "viewer" && role != "operator" && role != "approver" && role != "administrator" {
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	if role == "administrator" {
		return true
	}
	if strings.Contains(r.Pattern, "/campaigns") {
		if strings.HasSuffix(r.Pattern, "/approve") || strings.HasSuffix(r.Pattern, "/reject") {
			return role == "approver"
		}
		if strings.HasSuffix(r.Pattern, "/resume") {
			return role == "approver" || role == "operator"
		}
		return role == "operator"
	}
	return role == "operator" && strings.Contains(r.Pattern, "/operations")
}
func (s *Server) registerCampaignRoutes(m *http.ServeMux) {
	base := "/v1/organizations/{organizationID}"
	routes := []string{"GET " + base + "/campaigns", "POST " + base + "/campaigns", "POST " + base + "/campaigns/preview", "GET " + base + "/campaigns/{campaignID}", "PUT " + base + "/campaigns/{campaignID}", "GET " + base + "/concurrency-policy", "PUT " + base + "/concurrency-policy", "POST " + base + "/clusters/{clusterID}/operations/{operationID}/cancel"}
	for _, a := range []string{"start", "approve", "reject", "pause", "resume", "cancel"} {
		routes = append(routes, "POST "+base+"/campaigns/{campaignID}/"+a)
	}
	for _, a := range []string{"targets", "operations", "events", "approvals"} {
		routes = append(routes, "GET "+base+"/campaigns/{campaignID}/"+a)
	}
	for _, route := range routes {
		m.Handle(route, s.auth(http.HandlerFunc(s.campaignAdmin)))
	}
}
func (s *Server) campaignAdmin(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.repo.(CampaignRepository)
	if !ok {
		problem(w, 503, "campaigns_unavailable")
		return
	}
	org, id := r.PathValue("organizationID"), r.PathValue("campaignID")
	if id != "" && !validID(id) {
		problem(w, 400, "invalid_campaign_id")
		return
	}
	ctx := r.Context()
	who, request := actor(r), requestID(r)
	suffix := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	if r.Method == http.MethodPost && suffix == "preview" && id == "" {
		var spec campaign.Spec
		if !decodeSize(w, r, &spec, 256<<10) {
			return
		}
		preview, e := repo.PreviewCampaign(ctx, org, spec)
		if e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, http.StatusOK, preview)
		return
	}
	if strings.HasSuffix(r.Pattern, "/concurrency-policy") {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			v, e := repo.GetConcurrencyPolicy(ctx, org)
			if e != nil {
				s.failure(w, r, e)
				return
			}
			write(w, 200, v)
			return
		}
		var v store.ConcurrencyPolicy
		if !decode(w, r, &v) {
			return
		}
		result, e := repo.SetConcurrencyPolicy(ctx, org, v.Revision, v.Limits, who, request)
		if e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, 200, result)
		return
	}
	if operation := r.PathValue("operationID"); operation != "" {
		cluster := r.PathValue("clusterID")
		if !validID(operation) || !validID(cluster) {
			problem(w, 400, "invalid_operation_id")
			return
		}
		var input struct{}
		if !decode(w, r, &input) {
			return
		}
		if e := repo.CancelNodeOperation(ctx, org, cluster, operation, s.maintenanceKey, who, request); e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, 202, map[string]string{"status": "cancellation_requested"})
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if id != "" && suffix == id {
			v, e := repo.GetCampaign(ctx, org, id)
			if e != nil {
				s.failure(w, r, e)
				return
			}
			write(w, 200, v)
			return
		}
		if suffix == "approvals" {
			limit, offset, ok := page(w, r)
			if !ok {
				return
			}
			v, e := repo.ListCampaignApprovals(ctx, org, id, limit, offset)
			if e != nil {
				s.failure(w, r, e)
				return
			}
			write(w, 200, map[string]any{"items": v, "limit": limit, "offset": offset})
			return
		}
		limit, offset, ok := page(w, r)
		if !ok {
			return
		}
		var v any
		var e error
		switch suffix {
		case "targets":
			v, e = repo.ListCampaignTargets(ctx, org, id, limit, offset)
		case "operations":
			v, e = repo.ListCampaignOperations(ctx, org, id, limit, offset)
		case "events":
			v, e = repo.ListCampaignEvents(ctx, org, id, limit, offset)
		default:
			v, e = repo.ListCampaigns(ctx, org, limit, offset)
		}
		if e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, 200, map[string]any{"items": v, "limit": limit, "offset": offset})
		return
	}
	if id == "" || r.Method == http.MethodPut {
		var input struct {
			ID       string        `json:"id"`
			Revision int64         `json:"revision"`
			Spec     campaign.Spec `json:"spec"`
		}
		if !decodeSize(w, r, &input, 256<<10) {
			return
		}
		var v store.Campaign
		var e error
		status := 200
		if id == "" {
			if !validID(input.ID) {
				problem(w, 400, "invalid_campaign_id")
				return
			}
			v, e = repo.CreateCampaign(ctx, org, input.ID, input.Spec, who, request)
			status = 201
		} else {
			if input.ID != "" && input.ID != id {
				problem(w, 400, "invalid_campaign_id")
				return
			}
			v, e = repo.UpdateCampaign(ctx, org, id, input.Revision, input.Spec, who, request)
		}
		if e != nil {
			s.failure(w, r, e)
			return
		}
		write(w, status, v)
		return
	}
	var input store.CampaignControl
	if !decode(w, r, &input) {
		return
	}
	var v store.Campaign
	var e error
	if suffix == "start" {
		v, e = repo.StartCampaign(ctx, org, id, input.Revision, who, request)
	} else {
		v, e = repo.ControlCampaign(ctx, org, id, suffix, input, who, principal(r).Role, request, s.maintenanceKey)
	}
	if e != nil {
		s.failure(w, r, e)
		return
	}
	write(w, 200, v)
}
