package httpapi

import (
	"net/http"
	"testing"
)

func TestLabLifecycleMutationsRequireAdministrator(t *testing.T) {
	r := &http.Request{Method: http.MethodPost, Pattern: "POST /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle/stop"}
	for _, role := range []string{"viewer", "operator", "approver"} {
		if authorizedRoute(r, role) {
			t.Fatalf("%s was allowed to change durable lab lifecycle state", role)
		}
	}
	if !authorizedRoute(r, "administrator") {
		t.Fatal("administrator could not manage the lab lifecycle")
	}
	get := &http.Request{Method: http.MethodGet, Pattern: "GET /v1/organizations/{organizationID}/clusters/{clusterID}/lab-lifecycle"}
	if !authorizedRoute(get, "viewer") {
		t.Fatal("viewer could not read lab lifecycle status")
	}
}
