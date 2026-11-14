package httpapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestContractDocumentAndResponses(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../../api/openapi/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = doc.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, path, body, token, component string }{
		{"GET", "/healthz", "", "", "Health"},
		{"GET", "/v1/organizations", "", token, "OrganizationPage"},
		{"POST", "/v1/organizations", `{"name":"acme"}`, token, "Organization"},
		{"GET", "/v1/organizations", "", "", "Error"},
	} {
		w := request(handler(&fakeRepo{}), tc.method, tc.path, tc.body, tc.token)
		var data any
		if err = json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if err = doc.Components.Schemas[tc.component].Value.VisitJSON(data); err != nil {
			t.Fatalf("%s response violates %s: %v", tc.path, tc.component, err)
		}
	}
}
