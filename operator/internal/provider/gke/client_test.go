package gke

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"kordex.local/api/protocol"
)

type tokenStub string

func (t tokenStub) Token(context.Context) (string, error) { return string(t), nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestNodePoolUpdateUsesExactResourceETagAndImageType(t *testing.T) {
	ref := protocol.GKENodePoolReference{Project: "test-project", Location: "us-central1-a", Cluster: "test-cluster", NodePool: "default-pool"}
	client := NewClient()
	client.Tokens = tokenStub("test-token")
	client.HTTP = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPut {
			t.Fatalf("method = %s, want PUT", req.Method)
		}
		wantPath := "/v1/projects/test-project/locations/us-central1-a/clusters/test-cluster/nodePools/default-pool"
		if req.URL.Path != wantPath {
			t.Fatalf("path = %q, want %q", req.URL.Path, wantPath)
		}
		if req.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatal("GKE request did not use workload token")
		}
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{`"nodeVersion":"1.36.5-gke.100"`, `"imageType":"COS_CONTAINERD"`, `"etag":"etag-1"`, `"name":"default-pool"`} {
			if !strings.Contains(string(payload), expected) {
				t.Fatalf("update body %s does not contain %s", payload, expected)
			}
		}
		return response(http.StatusOK, `{"name":"projects/test-project/locations/us-central1-a/operations/op-1","status":"RUNNING"}`), nil
	})}

	operation, err := client.UpdateNodePool(context.Background(), ref, "1.36.5-gke.100", "COS_CONTAINERD", "etag-1")
	if err != nil {
		t.Fatal(err)
	}
	if operation.Name != "projects/test-project/locations/us-central1-a/operations/op-1" {
		t.Fatalf("operation identity = %q", operation.Name)
	}
}

func TestGKEClientRejectsUntrustedEndpointAndMissingConcurrencyToken(t *testing.T) {
	ref := protocol.GKENodePoolReference{Project: "test-project", Location: "us-central1-a", Cluster: "test-cluster", NodePool: "default-pool"}
	client := NewClient()
	client.BaseURL = "https://example.invalid/v1"
	client.Tokens = tokenStub("test-token")
	if _, err := client.GetNodePool(context.Background(), ref); err == nil || !strings.Contains(err.Error(), "Google Container API") {
		t.Fatalf("untrusted endpoint accepted: %v", err)
	}
	client.BaseURL = ""
	if _, err := client.UpdateNodePool(context.Background(), ref, "1.36.5-gke.100", "COS_CONTAINERD", ""); err == nil {
		t.Fatal("update without etag accepted")
	}
}

func TestMetadataTokenSourceValidatesAndCachesToken(t *testing.T) {
	calls := 0
	source := &MetadataTokenSource{Client: &http.Client{Timeout: time.Second, Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "metadata.google.internal" || req.Header.Get("Metadata-Flavor") != "Google" {
			t.Fatalf("invalid metadata request: host=%q flavor=%q", req.URL.Host, req.Header.Get("Metadata-Flavor"))
		}
		return response(http.StatusOK, `{"access_token":"metadata-token","expires_in":3600,"token_type":"Bearer"}`), nil
	})}}
	for i := 0; i < 2; i++ {
		token, err := source.Token(context.Background())
		if err != nil || token != "metadata-token" {
			t.Fatalf("token=%q err=%v", token, err)
		}
	}
	if calls != 1 {
		t.Fatalf("metadata calls=%d, want cached single call", calls)
	}
}
