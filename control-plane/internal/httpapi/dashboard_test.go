package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"kordex.local/control-plane/internal/store"
)

type inventoryFilterRepo struct {
	*fakeRepo
	filter    store.InventoryFilter
	listCalls int
}

func (r *inventoryFilterRepo) DashboardSummary(context.Context, string) (store.DashboardSummary, error) {
	return store.DashboardSummary{}, nil
}

func (r *inventoryFilterRepo) ListInventoryNodes(_ context.Context, _ string, filter store.InventoryFilter, _, _ int) ([]store.InventoryNode, error) {
	r.filter = filter
	r.listCalls++
	return []store.InventoryNode{}, nil
}

func (r *inventoryFilterRepo) ListAudit(context.Context, string, string, bool, int64, int64, int, int) ([]store.AuditEntry, error) {
	return []store.AuditEntry{}, nil
}

func TestInventoryNodeUIDFilterRequiresClusterAndIsPassedExactly(t *testing.T) {
	org := "80bd80f9-f097-4474-86f4-b80986fd5423"
	cluster := "213aa35f-5666-41f4-9fc5-5ec83493e1b0"
	repo := &inventoryFilterRepo{fakeRepo: &fakeRepo{}}
	h := New(repo, token, "Kordex", slog.New(slog.NewTextHandler(io.Discard, nil)))

	response := request(h, http.MethodGet, "/v1/organizations/"+org+"/nodes?clusterId="+cluster+"&nodeUid=node-uid-17&limit=1", "", token)
	if response.Code != http.StatusOK || repo.listCalls != 1 || repo.filter.ClusterID != cluster || repo.filter.NodeUID != "node-uid-17" {
		t.Fatalf("exact node filter request: status=%d calls=%d filter=%+v body=%s", response.Code, repo.listCalls, repo.filter, response.Body.String())
	}

	for _, query := range []string{
		"nodeUid=node-uid-17",
		"clusterId=" + cluster + "&nodeUid=",
		"clusterId=" + cluster + "&nodeUid=a%2Fb",
		"clusterId=" + cluster + "&nodeUid=one&nodeUid=two",
	} {
		before := repo.listCalls
		response = request(h, http.MethodGet, "/v1/organizations/"+org+"/nodes?"+query, "", token)
		if response.Code != http.StatusBadRequest || repo.listCalls != before {
			t.Errorf("invalid exact node filter %q reached repository: status=%d calls=%d body=%s", query, response.Code, repo.listCalls, response.Body.String())
		}
	}
	if strings.Contains(response.Body.String(), "nodeUid") {
		t.Fatal("validation response unexpectedly echoed the requested node UID")
	}
}
