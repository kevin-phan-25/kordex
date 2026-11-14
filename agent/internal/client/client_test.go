package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPSAndRedirectBoundaries(t *testing.T) {
	const cluster = "80bd80f9-f097-4474-86f4-b80986fd5423"
	for _, origin := range []string{"http://hub.example", "https://user:password@hub.example", "https://hub.example/path", "https://hub.example?secret=x"} {
		if _, err := New(origin, cluster, false, nil); err == nil {
			t.Fatalf("accepted unsafe origin %q", origin)
		}
	}
	if _, err := New("http://127.0.0.1:8080", cluster, true, nil); err != nil {
		t.Fatal(err)
	}
	targetCalled := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalled = true }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	c, err := New(redirect.URL, cluster, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP.Transport = redirect.Client().Transport
	if err = c.Call(context.Background(), "GET", "/v1/agent/identity", nil, nil, nil); err == nil {
		t.Fatal("redirect reported as success")
	}
	if targetCalled {
		t.Fatal("followed redirect to another origin")
	}
}
